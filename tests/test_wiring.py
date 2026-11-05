"""How the collector connects to Mailu: it reads logs, and nothing else.

These tests pin the properties that made log reading the design: nothing
listens on the network, each log is read independently, a log that cannot be
read does not stop the other or the daemon, and `doctor` checks the one thing
that can go wrong on a real host -- the Rspamd log not being in the expected
format.
"""

import json
import os
import socket

from helpers import FIXTURES, MailutTestCase

from mailut import collector
from mailut import scopes as scope_store
from mailut.config import Config
from mailut.mailu import ENV_ANTISPAM_LOG, ENV_SMTP_LOG, Mailu
from mailut.util import MailutError


class _CollectArgs:
    verbose = False
    once = True


def _quiet(test):
    import logging

    logging.disable(logging.CRITICAL)
    test.addCleanup(logging.disable, logging.NOTSET)


class _LogFixtures(MailutTestCase):
    """Both Mailu logs served from fixtures, and an `all` scope collecting."""

    def setUp(self):
        super().setUp()
        _quiet(self)
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        for name, path in ((ENV_SMTP_LOG, "smtp-inbound.log"), (ENV_ANTISPAM_LOG, "antispam.log")):
            os.environ[name] = str(FIXTURES / path)
            self.addCleanup(os.environ.pop, name, None)

    def conf(self, extra=""):
        path = self.tmp / "collect.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n[collector]\nlog_poll_seconds = 1\n{extra}",
            encoding="utf-8",
        )
        return Config.load(path)

    def count(self, where="1=1", *params):
        return self.db().execute(
            f"SELECT COUNT(*) AS n FROM audit_events WHERE {where}", params
        ).fetchone()["n"]


class CollectOnceTests(_LogFixtures):
    """`--once` reads each log exactly once and exits."""

    def test_each_log_is_read_exactly_once(self):
        calls = []
        real = collector.LogPoller.poll_source

        def counting(self, source):
            calls.append(source)
            return real(self, source)

        collector.LogPoller.poll_source = counting
        self.addCleanup(setattr, collector.LogPoller, "poll_source", real)
        self.assertEqual(collector.cmd_collect(_CollectArgs(), self.conf()), 0)
        self.assertEqual(sorted(calls), ["antispam", "smtp"])

    def test_once_returns_promptly(self):
        import time

        started = time.monotonic()
        self.assertEqual(collector.cmd_collect(_CollectArgs(), self.conf()), 0)
        self.assertLess(time.monotonic() - started, 10)

    def test_both_logs_are_ingested(self):
        collector.cmd_collect(_CollectArgs(), self.conf())
        self.assertGreater(self.count("source = 'rspamd'"), 0)
        self.assertGreater(self.count("source = 'postfix'"), 0)

    def test_a_source_can_be_turned_off(self):
        collector.cmd_collect(_CollectArgs(), self.conf("ingest_rspamd_logs = false\n"))
        self.assertEqual(self.count("source = 'rspamd'"), 0)
        self.assertGreater(self.count("source = 'postfix'"), 0)

    def test_turning_both_off_is_an_error_not_a_silent_no_op(self):
        config = self.conf("ingest_rspamd_logs = false\ningest_smtp_logs = false\n")
        with self.assertRaises(MailutError) as caught:
            collector.cmd_collect(_CollectArgs(), config)
        self.assertIn("nothing to collect", str(caught.exception))

    def test_each_log_gets_its_own_cursor(self):
        collector.cmd_collect(_CollectArgs(), self.conf())
        rows = dict(self.db().execute("SELECT key, value FROM collector_state").fetchall())
        self.assertIn("smtp_log_cursor", rows)
        self.assertIn("antispam_log_cursor", rows)


class FailureIsolationTests(_LogFixtures):
    """A log that cannot be read must cost that log's poll, nothing more.

    This is what replaced the boot-order problem of the HTTP collector: if the
    antispam container is not up yet, reading its log fails and is retried
    next time; it does not crash the service or block the smtp log.
    """

    def test_an_unreadable_antispam_log_does_not_stop_the_smtp_log(self):
        real = Mailu.logs

        def flaky(self, service, **kwargs):
            if service == self.antispam_service:
                raise MailutError("cannot read logs for service 'antispam': no such service")
            return real(self, service, **kwargs)

        Mailu.logs = flaky
        self.addCleanup(setattr, Mailu, "logs", real)
        self.assertEqual(collector.cmd_collect(_CollectArgs(), self.conf()), 0)
        self.assertGreater(self.count("source = 'postfix'"), 0)
        self.assertEqual(self.count("source = 'rspamd'"), 0)

    def test_a_failed_poll_does_not_move_that_logs_cursor(self):
        """Nothing was read, so the next poll must start from the same place."""
        real = Mailu.logs

        def failing(self, service, **kwargs):
            if service == self.antispam_service:
                raise MailutError("docker is restarting")
            return real(self, service, **kwargs)

        Mailu.logs = failing
        self.addCleanup(setattr, Mailu, "logs", real)
        collector.cmd_collect(_CollectArgs(), self.conf())
        keys = {row["key"] for row in self.db().execute("SELECT key FROM collector_state")}
        self.assertNotIn("antispam_log_cursor", keys)

    def test_the_daemon_keeps_polling_after_a_failure(self):
        import threading

        calls = []
        stop = threading.Event()

        def flaky(self, source):
            calls.append(source)
            if len(calls) == 1:
                raise MailutError("first poll fails")
            if len(calls) >= 3:
                stop.set()
            return {"lines": 0, "stored": 0, "duplicate": 0, "out_of_scope": 0, "enriched": 0}

        real = collector.LogPoller.poll_source
        collector.LogPoller.poll_source = flaky
        self.addCleanup(setattr, collector.LogPoller, "poll_source", real)

        ingestor = collector.Ingestor(self.conf())
        self.addCleanup(ingestor.close)
        poller = collector.LogPoller(ingestor, stop, ["antispam"])
        poller.start()
        poller.join(timeout=10)
        self.assertFalse(poller.is_alive(), "the poller should have stopped when asked")
        self.assertGreaterEqual(len(calls), 3)

    def test_an_empty_poll_moves_the_cursor_to_when_the_poll_began(self):
        """Not to when it finished: a line logged meanwhile must not be skipped."""
        import datetime as dt

        moments = iter([dt.datetime(2026, 9, 17, 13, 0, 0, tzinfo=dt.timezone.utc),
                        dt.datetime(2026, 9, 17, 13, 0, 5, tzinfo=dt.timezone.utc)])
        real_now = collector.utcnow
        collector.utcnow = lambda: next(moments, dt.datetime(2026, 9, 17, 13, 0, 9, tzinfo=dt.timezone.utc))
        self.addCleanup(setattr, collector, "utcnow", real_now)
        empty = self.tmp / "empty.log"
        empty.write_text("", encoding="utf-8")
        os.environ[ENV_ANTISPAM_LOG] = str(empty)

        ingestor = collector.Ingestor(self.conf())
        self.addCleanup(ingestor.close)
        import threading

        poller = collector.LogPoller(ingestor, threading.Event(), ["antispam"])
        poller.poll_source("antispam")
        self.assertEqual(ingestor.get_state("antispam_log_cursor"), "2026-09-17T13:00:00Z")


class QuietPeriodTests(_LogFixtures):
    def test_a_quiet_log_is_not_re_read_from_the_last_event(self):
        """The cursor is how far the log was read, not when the last mail came.

        Keyed to the last event, a quiet period re-finds that event as a
        duplicate on every poll and never moves on, so each poll re-reads
        everything since the last mail.
        """
        import datetime as dt
        import threading

        old_line = [line for line in (FIXTURES / "antispam.log").read_text().splitlines()
                    if "spam-1@" in line][0]
        log = self.tmp / "quiet.log"
        log.write_text(old_line + "\n", encoding="utf-8")
        os.environ[ENV_ANTISPAM_LOG] = str(log)

        later = dt.datetime(2026, 9, 17, 18, 0, 0, tzinfo=dt.timezone.utc)
        real_now = collector.utcnow
        collector.utcnow = lambda: later
        self.addCleanup(setattr, collector, "utcnow", real_now)

        ingestor = collector.Ingestor(self.conf())
        self.addCleanup(ingestor.close)
        poller = collector.LogPoller(ingestor, threading.Event(), ["antispam"])
        poller.poll_source("antispam")
        poller.poll_source("antispam")  # nothing new: the same line again
        self.assertEqual(ingestor.get_state("antispam_log_cursor"), "2026-09-17T18:00:00Z")


class NoListenerTests(_LogFixtures):
    """The collector must never open a listening socket again.

    That was the whole point of moving to log reading: no port to expose,
    authenticate, firewall or get wrong.
    """

    def _watch_sockets(self):
        listened = []
        real_listen = socket.socket.listen
        real_bind = socket.socket.bind

        def listen(sock, *args):
            listened.append(("listen", sock.family))
            return real_listen(sock, *args)

        def bind(sock, address):
            listened.append(("bind", address))
            return real_bind(sock, address)

        socket.socket.listen = listen
        socket.socket.bind = bind
        self.addCleanup(setattr, socket.socket, "listen", real_listen)
        self.addCleanup(setattr, socket.socket, "bind", real_bind)
        return listened

    def test_once_opens_no_socket(self):
        listened = self._watch_sockets()
        collector.cmd_collect(_CollectArgs(), self.conf())
        self.assertEqual(listened, [])

    def test_the_daemon_opens_no_socket(self):
        import signal

        # The daemon installs SIGTERM/SIGINT handlers; give the test runner its
        # own back afterwards.
        for signum in (signal.SIGTERM, signal.SIGINT):
            self.addCleanup(signal.signal, signum, signal.getsignal(signum))
        listened = self._watch_sockets()
        real_run = collector.LogPoller.run
        collector.LogPoller.run = lambda self: self.poll_once()
        self.addCleanup(setattr, collector.LogPoller, "run", real_run)

        class Daemon(_CollectArgs):
            once = False

        self.assertEqual(collector.cmd_collect(Daemon(), self.conf()), 0)
        self.assertEqual(listened, [])

    def test_no_listener_settings_remain(self):
        """An old config naming a listener fails loudly instead of being ignored."""
        for setting in ("bind = 127.0.0.1", "port = 8765", "token_file = /x"):
            path = self.tmp / "old.conf"
            path.write_text(f"[collector]\n{setting}\n", encoding="utf-8")
            with self.assertRaises(MailutError, msg=setting) as caught:
                Config.load(path)
            self.assertIn("unknown setting", str(caught.exception))


class RspamdLogDoctorTests(MailutTestCase):
    """doctor checks the live antispam log against the parser."""

    def checks(self, log_text=None, extra=""):
        from mailut import status

        if log_text is not None:
            path = self.tmp / "antispam-doctor.log"
            path.write_text(log_text, encoding="utf-8")
            os.environ[ENV_ANTISPAM_LOG] = str(path)
            self.addCleanup(os.environ.pop, ENV_ANTISPAM_LOG, None)
        path = self.tmp / "doctor.conf"
        path.write_text(
            f"[mailu]\ncompose_dir = {self.compose_dir}\ncompose_command = /bin/false\n"
            f"[storage]\nstate_dir = {self.state_dir}\n[collector]\n{extra}",
            encoding="utf-8",
        )
        return {c["check"]: c for c in status.collect_checks(Config.load(path))}

    def _lines(self, *markers):
        lines = (FIXTURES / "antispam.log").read_text(encoding="utf-8").splitlines()
        return "\n".join(line for line in lines if any(m in line for m in markers)) + "\n"

    def test_recognised_lines_pass(self):
        check = self.checks(self._lines("spam-1@", "ham-1@"))["rspamd log"]
        self.assertEqual(check["status"], "ok", check["detail"])
        self.assertIn("all recognised", check["detail"])

    def test_a_customised_format_fails(self):
        """Lines are there, none parse: no Rspamd decision would be recorded."""
        custom = (
            "antispam-1  | 2026-09-17T13:02:51Z 2026-09-17 13:02:51 #42(normal) <ab>; task; "
            "rspamd_task_write_log: msg=<x@y> action=reject score=16.4\n"
        )
        check = self.checks(custom * 3)["rspamd log"]
        self.assertEqual(check["status"], "fail")
        self.assertIn("log_format", check["detail"])

    def test_no_lines_is_a_warning_not_a_failure(self):
        check = self.checks(self._lines("lua;"))["rspamd log"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("no per-message lines", check["detail"])

    def test_a_partial_match_is_reported(self):
        check = self.checks(self._lines("spam-1@", "not the default format"))["rspamd log"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("1 of 2", check["detail"])

    def test_disabled_source_is_not_checked(self):
        check = self.checks(extra="ingest_rspamd_logs = false\n")["rspamd log"]
        self.assertEqual(check["status"], "ok")
        self.assertIn("disabled", check["detail"])

    def test_doctor_has_no_network_checks_left(self):
        names = set(self.checks(self._lines("spam-1@")))
        for gone in ("collector bind", "collector token", "rspamd exporter",
                     "rspamd exporter auth", "rspamd -> collector", "collector"):
            self.assertNotIn(gone, names)


class StatusCursorTests(_LogFixtures):
    def test_status_reports_how_far_each_log_was_read(self):
        collector.cmd_collect(_CollectArgs(), self.conf())
        proc = self.run_cli("--config", str(self.tmp / "collect.conf"), "status", "--json", expect=0)
        cursors = json.loads(proc.stdout)["collector"]["log_cursors"]
        self.assertTrue(cursors["smtp"])
        self.assertTrue(cursors["antispam"])


class LevelTests(MailutTestCase):
    """Only metadata exists in the logs, so only metadata can be asked for."""

    def test_headers_and_message_are_refused_with_the_reason(self):
        for level in ("headers", "message"):
            proc = self.run_cli("audit", "add", "domain", "example.com", "--level", level, expect=2)
            self.assertIn("not available", proc.stderr)
            self.assertIn("no message headers or bodies", proc.stderr)
        self.assertEqual(scope_store.list_scopes(self.db()), [])

    def test_metadata_is_accepted(self):
        self.run_cli("audit", "add", "domain", "example.com", "--level", "metadata", expect=0)

    def test_default_level_must_be_metadata(self):
        path = self.tmp / "level.conf"
        path.write_text("[audit]\ndefault_level = headers\n", encoding="utf-8")
        with self.assertRaises(MailutError) as caught:
            Config.load(path)
        self.assertIn("no message headers or bodies", str(caught.exception))

    def test_content_settings_are_gone(self):
        for setting in ("allow_headers = true", "allow_messages = true",
                        "message_retention_days = 30", "message_max_bytes = 1024"):
            path = self.tmp / "content.conf"
            path.write_text(f"[audit]\n{setting}\n", encoding="utf-8")
            with self.assertRaises(MailutError, msg=setting):
                Config.load(path)


class DegradedScopeTests(MailutTestCase):
    """A scope recorded above metadata (by an older version) must say so."""

    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="domain", value="example.com", mode="include",
            level="headers", retention_days=30, message_retention_days=None,
        )

    def test_scopes_shows_the_effective_level(self):
        proc = self.run_cli("audit", "scopes", expect=0)
        self.assertIn("metadata (asked headers)", proc.stdout)
        self.assertIn("collecting metadata only", proc.stderr)

    def test_scopes_json_exposes_the_effective_level(self):
        record = json.loads(self.run_cli("audit", "scopes", "--json", expect=0).stdout)[0]
        self.assertEqual(record["level"], "headers")
        self.assertEqual(record["effective_level"], "metadata")

    def test_doctor_warns_about_degraded_scopes(self):
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(self.config())}
        self.assertEqual(checks["scope levels"]["status"], "warn")
        self.assertIn("example.com", checks["scope levels"]["detail"])

    def test_scopes_test_agrees_with_the_listing(self):
        tested = self.run_cli("audit", "scopes", "--test", "user@example.com", expect=0).stdout
        self.assertIn("metadata (asked headers)", tested)
        payload = json.loads(self.run_cli(
            "audit", "scopes", "--test", "user@example.com", "--json", expect=0).stdout)
        self.assertEqual(payload["effective_level"], "metadata")

    def test_events_are_recorded_as_metadata(self):
        from mailut.events import Event, EventStore
        from mailut.util import utcnow

        store = EventStore(self.db(), self.config())
        result = store.store(Event(occurred_at=utcnow(), source="rspamd", stage="data",
                                   action="reject", envelope_to="user@example.com",
                                   headers_text="Subject: should not be kept"))
        self.assertEqual(result["status"], "stored")
        row = self.db().execute("SELECT level FROM audit_events").fetchone()
        self.assertEqual(row["level"], "metadata")
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS n FROM audit_payloads").fetchone()["n"], 0)


class NoDegradationTests(MailutTestCase):
    def test_no_warning_for_metadata_scopes(self):
        from mailut import status

        scope_store.upsert_scope(
            self.db(), scope_type="domain", value="example.com", mode="include",
            level="metadata", retention_days=30, message_retention_days=None,
        )
        checks = {c["check"]: c for c in status.collect_checks(self.config())}
        self.assertEqual(checks["scope levels"]["status"], "ok")
        self.assertNotIn("asked", self.run_cli("audit", "scopes", expect=0).stdout)


class VersionJsonTests(MailutTestCase):
    def test_version_json_reports_the_schema_version(self):
        from mailut import migrations

        proc = self.run_cli("version", "--json", expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], migrations.LATEST)
        self.assertIn("version", payload)
        self.assertIn("installed", payload)


class SubjectWordingTests(_LogFixtures):
    """Never invent a subject, and say truthfully why there is none."""

    def test_pre_data_and_post_data_absences_are_worded_differently(self):
        collector.cmd_collect(_CollectArgs(), self.conf())
        conf = str(self.tmp / "collect.conf")
        post = self.run_cli("--config", conf, "audit", "show", "--since", "400d",
                            "--symbol", "RBL_SPAMHAUS_SBL", expect=0).stdout
        self.assertIn("subject:  not recorded (not in the Mailu logs)", post)
        self.assertNotIn("rejected before DATA", post)
        pre = self.run_cli("--config", conf, "audit", "show", "--since", "400d",
                           "--stage", "rcpt", expect=0).stdout
        self.assertIn("subject:  unavailable (rejected before DATA)", pre)
