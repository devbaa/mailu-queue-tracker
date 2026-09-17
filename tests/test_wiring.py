"""Regressions for the collector/Rspamd/upgrade integration defects.

Each test here corresponds to a defect found by reading the code rather than
by running it, so they are written to fail loudly if the behaviour returns.
"""

import json
import os
import types

from helpers import FIXTURES, MailutTestCase

from mailut import collector
from mailut import scopes as scope_store
from mailut.config import Config
from mailut.mailu import ENV_SMTP_LOG, Mailu
from mailut.util import MailutError, classify_bind_address


class _CollectArgs:
    verbose = False
    once = True
    no_log_poll = False
    allow_remote = False


class BindAddressTests(MailutTestCase):
    """The collector must permit the documented Docker-bridge setup.

    Binding to the bridge gateway is how the antispam container reaches the
    host; refusing it made docs/install.md's own instructions unusable, because
    mailut-audit.service runs `audit collect` with no --allow-remote.
    """

    def test_classification(self):
        for address, expected in (
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("localhost", "loopback"),
            ("172.17.0.1", "private"),
            ("192.168.1.10", "private"),
            ("10.1.2.3", "private"),
            ("0.0.0.0", "wildcard"),
            ("::", "wildcard"),
            ("", "wildcard"),
            ("8.8.8.8", "public"),
            ("mail.example.com", "unknown"),
        ):
            self.assertEqual(classify_bind_address(address), expected, address)

    def _collect(self, bind, **overrides):
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        path = self.tmp / "bind.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nbind = {bind}\nport = 18999\ningest_smtp_logs = false\n",
            encoding="utf-8",
        )
        args = _CollectArgs()
        for key, value in overrides.items():
            setattr(args, key, value)
        return collector.cmd_collect(args, Config.load(path))

    def test_bridge_gateway_bind_is_accepted(self):
        """The documented Linux setup must not refuse to start."""
        self.assertEqual(self._collect("172.17.0.1"), 0)

    def test_loopback_bind_is_accepted(self):
        self.assertEqual(self._collect("127.0.0.1"), 0)

    def test_wildcard_bind_is_refused(self):
        with self.assertRaises(MailutError) as caught:
            self._collect("0.0.0.0")
        self.assertIn("refusing to bind", str(caught.exception))

    def test_public_bind_is_refused(self):
        with self.assertRaises(MailutError) as caught:
            self._collect("8.8.8.8")
        self.assertIn("refusing to bind", str(caught.exception))

    def test_allow_remote_overrides_the_refusal(self):
        self.assertEqual(self._collect("0.0.0.0", allow_remote=True), 0)

    def test_the_shipped_exporter_and_docs_agree(self):
        """The example URL and the documented bind must be the same address."""
        from helpers import ROOT

        snippet = (ROOT / "share" / "rspamd" / "mailut-exporter.conf").read_text()
        install_doc = (ROOT / "docs" / "install.md").read_text()
        self.assertIn("172.17.0.1:8765", snippet)
        self.assertIn("bind = 172.17.0.1", install_doc)
        self.assertIn("172.17.0.1:8765", install_doc)
        # And that address must be one the collector actually permits.
        self.assertEqual(classify_bind_address("172.17.0.1"), "private")


class CollectOnceTests(MailutTestCase):
    """`--once` must poll exactly once and exit, not start a looping thread."""

    def setUp(self):
        super().setUp()
        import logging

        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        os.environ[ENV_SMTP_LOG] = str(FIXTURES / "smtp-inbound.log")
        self.addCleanup(os.environ.pop, ENV_SMTP_LOG, None)

    def test_once_polls_exactly_one_time(self):
        calls = []
        real_poll = collector.LogPoller.poll_once

        def counting_poll(self):
            calls.append(1)
            return real_poll(self)

        collector.LogPoller.poll_once = counting_poll
        self.addCleanup(setattr, collector.LogPoller, "poll_once", real_poll)

        args = _CollectArgs()
        # A short interval would have let the old implementation poll many
        # times inside its 30-second join().
        path = self.tmp / "once.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            f"[collector]\nport = 18998\nlog_poll_seconds = 1\n",
            encoding="utf-8",
        )
        self.assertEqual(collector.cmd_collect(args, Config.load(path)), 0)
        self.assertEqual(len(calls), 1, f"expected one poll, got {len(calls)}")

    def test_once_returns_promptly(self):
        import time

        args = _CollectArgs()
        started = time.monotonic()
        self.assertEqual(collector.cmd_collect(args, self.config()), 0)
        elapsed = time.monotonic() - started
        # The old implementation joined a daemon thread for up to 30 seconds.
        self.assertLess(elapsed, 10, f"--once took {elapsed:.1f}s")

    def test_once_actually_ingests(self):
        collector.cmd_collect(_CollectArgs(), self.config())
        stored = self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
        self.assertGreaterEqual(stored, 5)

    def test_once_with_log_polling_disabled_does_nothing(self):
        args = _CollectArgs()
        args.no_log_poll = True
        self.assertEqual(collector.cmd_collect(args, self.config()), 0)
        stored = self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
        self.assertEqual(stored, 0)


class RspamdDoctorTests(MailutTestCase):
    """doctor must check the real wiring, not that our own example exists."""

    def checks(self):
        from mailut import status

        return {c["check"]: c for c in status.collect_checks(self.config())}

    def test_missing_override_is_reported(self):
        check = self.checks()["rspamd exporter"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("not be collected", check["detail"])

    def test_unrelated_override_does_not_count_as_configured(self):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "other.conf").write_text("# some unrelated tuning\n", encoding="utf-8")
        check = self.checks()["rspamd exporter"]
        self.assertEqual(check["status"], "warn")

    def test_exporter_targeting_the_collector_is_recognised(self):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.17.0.1:18765/rspamd"; } } }',
            encoding="utf-8",
        )
        check = self.checks()["rspamd exporter"]
        self.assertEqual(check["status"], "ok", check["detail"])

    def test_exporter_on_the_wrong_port_is_not_accepted(self):
        override = self.compose_dir / "overrides" / "rspamd"
        override.mkdir(parents=True)
        (override / "mailut-exporter.conf").write_text(
            'metadata_exporter { rules { mailut { url = "http://172.17.0.1:9999/rspamd"; } } }',
            encoding="utf-8",
        )
        self.assertEqual(self.checks()["rspamd exporter"]["status"], "warn")

    def test_reachability_failure_is_never_reported_as_success(self):
        """A compose command that cannot exec must not look like a passing check."""
        check = self.checks()["rspamd -> collector"]
        self.assertEqual(check["status"], "warn")
        self.assertIn("not verified", check["detail"])

    def test_antispam_service_setting_is_used(self):
        """It was configured and documented but read nowhere."""
        mailu = Mailu(self.config())
        self.assertEqual(mailu.antispam_service, "antispam")
        self.assertTrue(str(mailu.rspamd_override_dir).endswith("overrides/rspamd"))


class ProbeTests(MailutTestCase):
    def test_probe_distinguishes_unreachable_from_unverifiable(self):
        mailu = Mailu(self.config())

        def fake_exec(service, args, stdin=None, timeout=120):
            return types.SimpleNamespace(returncode=0, stdout="MAILUT_NO_CLIENT\n", stderr="")

        mailu.exec_service = fake_exec
        reachable, detail = mailu.probe_url_from_service("antispam", "http://127.0.0.1:1/health")
        self.assertIsNone(reachable)
        self.assertIn("no curl or wget", detail)

        def fake_ok(service, args, stdin=None, timeout=120):
            return types.SimpleNamespace(returncode=0, stdout="MAILUT_OK\n", stderr="")

        mailu.exec_service = fake_ok
        self.assertEqual(mailu.probe_url_from_service("antispam", "http://x/health")[0], True)

        def fake_fail(service, args, stdin=None, timeout=120):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="connection refused\n")

        mailu.exec_service = fake_fail
        reachable, detail = mailu.probe_url_from_service("antispam", "http://x/health")
        self.assertIs(reachable, False)
        self.assertIn("connection refused", detail)


class DegradedScopeTests(MailutTestCase):
    """A scope asking for more than the host permits must not look healthy."""

    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="domain", value="example.com", mode="include",
            level="headers", retention_days=30, message_retention_days=None,
        )

    def tightened_config(self):
        path = self.tmp / "tight.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n"
            "[audit]\nallow_headers = false\n",
            encoding="utf-8",
        )
        return path

    def test_scopes_shows_the_effective_level(self):
        proc = self.run_cli("--config", str(self.tightened_config()), "audit", "scopes", expect=0)
        self.assertIn("metadata (asked headers)", proc.stdout)
        self.assertIn("collecting metadata only", proc.stderr)

    def test_scopes_json_exposes_the_effective_level(self):
        proc = self.run_cli(
            "--config", str(self.tightened_config()), "audit", "scopes", "--json", expect=0
        )
        record = json.loads(proc.stdout)[0]
        self.assertEqual(record["level"], "headers")
        self.assertEqual(record["effective_level"], "metadata")

    def test_doctor_warns_about_degraded_scopes(self):
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(Config.load(self.tightened_config()))}
        self.assertEqual(checks["scope levels"]["status"], "warn")
        self.assertIn("example.com", checks["scope levels"]["detail"])

    def test_no_warning_when_the_level_is_permitted(self):
        from mailut import status

        checks = {c["check"]: c for c in status.collect_checks(self.config())}
        self.assertEqual(checks["scope levels"]["status"], "ok")
        proc = self.run_cli("audit", "scopes", expect=0)
        self.assertNotIn("asked", proc.stdout)


class VersionJsonTests(MailutTestCase):
    def test_version_json_reports_the_schema_version(self):
        from mailut import migrations

        proc = self.run_cli("version", "--json", expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], migrations.LATEST)
        self.assertIn("version", payload)
        self.assertIn("installed", payload)
