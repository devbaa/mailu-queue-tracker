"""The log poller: reading the Mailu smtp and antispam logs into the store."""

import os
import threading

from helpers import FIXTURES, MailutTestCase

from mailut import collector
from mailut import scopes as scope_store
from mailut.mailu import ENV_ANTISPAM_LOG, ENV_SMTP_LOG

_HOOKS = {"smtp": ENV_SMTP_LOG, "antispam": ENV_ANTISPAM_LOG}


class _PollerCase(MailutTestCase):
    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )

    def serve(self, source, path):
        os.environ[_HOOKS[source]] = str(path)
        self.addCleanup(os.environ.pop, _HOOKS[source], None)

    def poller(self):
        ingestor = collector.Ingestor(self.config())
        self.addCleanup(ingestor.close)
        return collector.LogPoller(ingestor, threading.Event()), ingestor

    def count(self, where="1=1"):
        return self.db().execute(f"SELECT COUNT(*) AS n FROM audit_events WHERE {where}").fetchone()["n"]


class SmtpLogTests(_PollerCase):
    def setUp(self):
        super().setUp()
        self.serve("smtp", FIXTURES / "smtp-inbound.log")

    def test_poll_ingests_and_advances_the_cursor(self):
        poller, ingestor = self.poller()
        summary = poller.poll_source("smtp")
        self.assertGreaterEqual(summary["stored"], 5)
        self.assertGreaterEqual(summary["unparsed"], 1)
        self.assertIsNotNone(ingestor.get_state(collector.SOURCES["smtp"]["cursor"]))

    def test_restart_does_not_duplicate_events(self):
        poller, _ = self.poller()
        first = poller.poll_source("smtp")
        before = self.count()

        # A fresh Ingestor is what a service restart produces; the cursor and
        # the event fingerprints both live in the database.
        restarted = collector.Ingestor(self.config())
        self.addCleanup(restarted.close)
        second = collector.LogPoller(restarted, threading.Event()).poll_source("smtp")

        self.assertGreater(first["stored"], 0)
        self.assertEqual(second["stored"], 0)
        self.assertEqual(before, self.count())

    def test_message_id_is_attached_from_the_cleanup_line(self):
        poller, _ = self.poller()
        poller.poll_source("smtp")
        row = self.db().execute(
            "SELECT message_id, message_size FROM audit_events WHERE queue_id = '4AbCd67890'"
        ).fetchone()
        self.assertEqual(row["message_id"], "abc123@example.net")
        self.assertEqual(row["message_size"], 4096)

    def test_garbage_log_does_not_crash(self):
        garbage = self.tmp / "garbage.log"
        garbage.write_bytes(b"\x00\x01\x02 not a log\nanother line\n" + b"x" * 5000)
        self.serve("smtp", garbage)
        poller, _ = self.poller()
        self.assertEqual(poller.poll_source("smtp")["stored"], 0)


class AntispamLogTests(_PollerCase):
    def setUp(self):
        super().setUp()
        self.serve("antispam", FIXTURES / "antispam.log")

    def test_poll_ingests_rspamd_decisions(self):
        poller, ingestor = self.poller()
        summary = poller.poll_source("antispam")
        # 17 recipients across the recognised lines; the outbound one is skipped.
        self.assertEqual(summary["stored"], 17)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(self.count("source = 'rspamd'"), 17)
        self.assertIsNotNone(ingestor.get_state(collector.SOURCES["antispam"]["cursor"]))

    def test_symbols_are_stored_in_their_own_table(self):
        poller, _ = self.poller()
        poller.poll_source("antispam")
        row = self.db().execute(
            "SELECT s.options FROM audit_symbols s JOIN audit_events e ON e.id = s.event_id "
            "WHERE e.message_id = 'spam-1@example.net' AND s.symbol = 'BAYES_SPAM'"
        ).fetchone()
        self.assertEqual(row["options"], "99.98%")

    def test_restart_does_not_duplicate_events(self):
        poller, _ = self.poller()
        poller.poll_source("antispam")
        before = self.count()
        restarted = collector.Ingestor(self.config())
        self.addCleanup(restarted.close)
        second = collector.LogPoller(restarted, threading.Event()).poll_source("antispam")
        self.assertEqual(second["stored"], 0)
        self.assertEqual(before, self.count())

    def test_outbound_mail_is_not_audited(self):
        poller, _ = self.poller()
        poller.poll_source("antispam")
        self.assertEqual(self.count("message_id = 'out-1@example.com'"), 0)

    def test_garbage_log_does_not_crash(self):
        garbage = self.tmp / "garbage.log"
        garbage.write_bytes(b"rspamd_task_write_log: \x00\x01 (default: T (\n" * 50)
        self.serve("antispam", garbage)
        poller, _ = self.poller()
        summary = poller.poll_source("antispam")
        self.assertEqual(summary["stored"], 0)
        self.assertEqual(summary["unparsed"], 50)


class BothLogsTests(_PollerCase):
    def test_one_poll_records_evidence_from_both_logs(self):
        self.serve("smtp", FIXTURES / "smtp-inbound.log")
        self.serve("antispam", FIXTURES / "antispam.log")
        poller, _ = self.poller()
        poller.poll_once()
        sources = {row["source"] for row in self.db().execute("SELECT DISTINCT source FROM audit_events")}
        self.assertEqual(sources, {"rspamd", "postfix"})

    def test_poll_once_reports_each_source(self):
        self.serve("smtp", FIXTURES / "smtp-inbound.log")
        self.serve("antispam", FIXTURES / "antispam.log")
        poller, _ = self.poller()
        results = poller.poll_once()
        self.assertEqual(set(results), {"smtp", "antispam"})
        self.assertGreater(results["antispam"]["stored"], 0)
