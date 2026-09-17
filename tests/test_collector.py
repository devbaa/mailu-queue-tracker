"""The collector: HTTP ingestion, limits, robustness and the log cursor."""

import json
import threading
import urllib.error
import urllib.request

from helpers import FIXTURES, MailutTestCase

from mailut import collector
from mailut import scopes as scope_store
from mailut.mailu import ENV_SMTP_LOG


class _Args:
    verbose = False
    once = True
    no_log_poll = True
    allow_remote = False


class CollectorHttpTests(MailutTestCase):
    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        self.ingestor = collector.Ingestor(self.config())
        self.addCleanup(self.ingestor.close)
        self.server = collector._Server(("127.0.0.1", 0), self.ingestor, 65536)
        self.addCleanup(self.server.server_close)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)

    def post(self, payload, *, raw=None, path="/rspamd"):
        body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_accepts_an_exporter_payload(self):
        payload = json.loads((FIXTURES / "rspamd-accept.json").read_text())
        status, body = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["stored"], 1)
        row = self.db().execute("SELECT subject, action FROM audit_events").fetchone()
        self.assertEqual(row["subject"], "September invoice")
        self.assertEqual(row["action"], "accept")

    def test_repeated_delivery_is_deduplicated(self):
        payload = json.loads((FIXTURES / "rspamd-accept.json").read_text())
        self.post(payload)
        status, body = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["duplicate"], 1)
        self.assertEqual(
            self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"], 1
        )

    def test_invalid_json_is_a_client_error(self):
        status, body = self.post(None, raw=b"{not json")
        self.assertEqual(status, 400)
        self.assertIn("invalid JSON", body["error"])

    def test_empty_body_is_refused(self):
        status, _ = self.post(None, raw=b"")
        self.assertEqual(status, 400)

    def test_oversized_body_is_refused(self):
        status, body = self.post(None, raw=b"x" * 70000)
        self.assertEqual(status, 413)
        self.assertIn("exceeds", body["error"])

    def test_unknown_path_is_404(self):
        status, _ = self.post({"rcpt": ["a@example.com"]}, path="/elsewhere")
        self.assertEqual(status, 404)

    def test_health_endpoint(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertEqual(payload["status"], "ok")

    def test_a_batch_of_records(self):
        payloads = [
            json.loads((FIXTURES / name).read_text())
            for name in ("rspamd-accept.json", "rspamd-greylist.json")
        ]
        status, body = self.post(payloads)
        self.assertEqual(status, 200)
        self.assertEqual(body["stored"], 2)

    def test_malformed_record_does_not_kill_the_server(self):
        status, _ = self.post({"rcpt": ["a@example.com"], "message_b64": "###"})
        self.assertEqual(status, 400)
        status, body = self.post(json.loads((FIXTURES / "rspamd-accept.json").read_text()))
        self.assertEqual(status, 200)
        self.assertEqual(body["stored"], 1)

    def test_out_of_scope_recipient_is_reported_not_stored(self):
        self.db().execute("UPDATE audit_scopes SET mode = 'exclude'")
        status, body = self.post(json.loads((FIXTURES / "rspamd-accept.json").read_text()))
        self.assertEqual(status, 200)
        self.assertEqual(body["out_of_scope"], 1)
        self.assertEqual(
            self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"], 0
        )


class CollectorLogPollerTests(MailutTestCase):
    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )

    def poller(self, monkeypatch_env):
        import os

        os.environ[ENV_SMTP_LOG] = monkeypatch_env
        self.addCleanup(os.environ.pop, ENV_SMTP_LOG, None)
        ingestor = collector.Ingestor(self.config())
        self.addCleanup(ingestor.close)
        return collector.LogPoller(ingestor, threading.Event()), ingestor

    def test_poll_ingests_and_advances_the_cursor(self):
        poller, ingestor = self.poller(str(FIXTURES / "smtp-inbound.log"))
        summary = poller.poll_once()
        self.assertGreaterEqual(summary["stored"], 5)
        self.assertGreaterEqual(summary["unparsed"], 1)
        self.assertIsNotNone(ingestor.get_state(collector.CURSOR_KEY))

    def test_restart_does_not_duplicate_events(self):
        poller, ingestor = self.poller(str(FIXTURES / "smtp-inbound.log"))
        first = poller.poll_once()
        stored_before = self.db().execute(
            "SELECT COUNT(*) AS n FROM audit_events"
        ).fetchone()["n"]

        # A fresh Ingestor is what a service restart produces; the cursor and
        # the event fingerprints both live in the database.
        restarted = collector.Ingestor(self.config())
        self.addCleanup(restarted.close)
        second = collector.LogPoller(restarted, threading.Event()).poll_once()
        stored_after = self.db().execute(
            "SELECT COUNT(*) AS n FROM audit_events"
        ).fetchone()["n"]

        self.assertGreater(first["stored"], 0)
        self.assertEqual(second["stored"], 0)
        self.assertEqual(stored_before, stored_after)

    def test_message_id_is_attached_from_the_cleanup_line(self):
        poller, _ = self.poller(str(FIXTURES / "smtp-inbound.log"))
        poller.poll_once()
        row = self.db().execute(
            "SELECT message_id, message_size FROM audit_events WHERE queue_id = '4AbCd67890'"
        ).fetchone()
        self.assertEqual(row["message_id"], "abc123@example.net")
        self.assertEqual(row["message_size"], 4096)

    def test_garbage_log_does_not_crash(self):
        garbage = self.tmp / "garbage.log"
        garbage.write_bytes(b"\x00\x01\x02 not a log\nanother line\n" + b"x" * 5000)
        poller, _ = self.poller(str(garbage))
        summary = poller.poll_once()
        self.assertEqual(summary["stored"], 0)


class CollectorGuardTests(MailutTestCase):
    extra_config = "\n"

    def test_non_localhost_bind_is_refused_without_the_flag(self):
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        path = self.tmp / "remote.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n[collector]\nbind = 0.0.0.0\nport = 18999\n",
            encoding="utf-8",
        )
        from mailut.config import Config
        from mailut.util import MailutError

        args = _Args()
        with self.assertRaises(MailutError) as caught:
            collector.cmd_collect(args, Config.load(path))
        self.assertIn("refusing to bind", str(caught.exception))
