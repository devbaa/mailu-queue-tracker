"""Queue, IP and watch commands, driven from fixtures instead of Docker."""

import json

from helpers import FIXTURES, MailutTestCase

from mailut import ips
from mailut.mailu import ENV_FRONT_LOG, ENV_POSTSUPER_OUT, ENV_QUEUE, ENV_SMTP_LOG
from mailut.util import EXIT_ABORTED, EXIT_USAGE


class QueueTests(MailutTestCase):
    def queue_env(self, **extra):
        env = {ENV_QUEUE: str(FIXTURES / "postqueue-incident.json")}
        env.update(extra)
        return env

    def test_queue_list_summary(self):
        proc = self.run_cli("queue", "list", env=self.queue_env(), expect=0)
        self.assertIn("queue total:              63", proc.stdout)
        self.assertIn("deferred:                 60", proc.stdout)
        self.assertIn("noreply@example.com", proc.stdout)

    def test_bare_queue_is_queue_list(self):
        bare = self.run_cli("queue", env=self.queue_env(), expect=0).stdout
        listed = self.run_cli("queue", "list", env=self.queue_env(), expect=0).stdout
        self.assertEqual(bare, listed)

    def test_queue_list_json(self):
        proc = self.run_cli("queue", "list", "--json", env=self.queue_env(), expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["total"], 63)
        self.assertEqual(payload["top_sender"], "noreply@example.com")
        self.assertEqual(payload["top_sender_count"], 60)
        self.assertGreaterEqual(payload["top_fanout_domains"], 25)

    def test_drain_dry_run_matches_exactly(self):
        proc = self.run_cli("queue", "drain", "--sender", "noreply@example.com", "--dry-run",
                            env=self.queue_env(), expect=0)
        self.assertIn("Matched 60 message(s) where sender = noreply@example.com", proc.stdout)
        self.assertIn("dry run", proc.stdout)

    def test_drain_does_not_match_a_partial_address(self):
        proc = self.run_cli("queue", "drain", "--sender", "noreply@example.org", "--dry-run",
                            env=self.queue_env(), expect=0)
        self.assertIn("Matched 0 message(s)", proc.stdout)

    def test_drain_by_recipient(self):
        proc = self.run_cli("queue", "drain", "--recipient", "victim1@honeypot-1.example",
                            "--dry-run", env=self.queue_env(), expect=0)
        self.assertIn("Matched 1 message(s) where recipient =", proc.stdout)

    def test_drain_requires_exactly_one_selector(self):
        self.run_cli("queue", "drain", "--dry-run", env=self.queue_env(), expect=EXIT_USAGE)
        self.run_cli("queue", "drain", "--sender", "a@example.com", "--recipient",
                     "b@example.com", "--dry-run", env=self.queue_env(), expect=EXIT_USAGE)

    def test_drain_without_a_terminal_and_without_yes_aborts(self):
        capture = self.tmp / "ids.txt"
        proc = self.run_cli(
            "queue", "drain", "--sender", "noreply@example.com",
            env=self.queue_env(**{ENV_POSTSUPER_OUT: str(capture)}), expect=EXIT_ABORTED,
        )
        self.assertIn("aborted", proc.stderr)
        self.assertFalse(capture.exists())

    def test_drain_with_yes_applies_to_every_matching_id(self):
        capture = self.tmp / "ids.txt"
        proc = self.run_cli(
            "queue", "drain", "--sender", "noreply@example.com", "--yes",
            env=self.queue_env(**{ENV_POSTSUPER_OUT: str(capture)}), expect=0,
        )
        self.assertIn("Done: delete 60 message(s)", proc.stdout)
        ids = [line for line in capture.read_text().splitlines() if line.strip()]
        self.assertEqual(len(ids), 60)
        self.assertTrue(all(i.startswith("4inc") for i in ids))

    def test_hold_uses_the_hold_operation(self):
        capture = self.tmp / "ids.txt"
        proc = self.run_cli(
            "queue", "hold", "--sender", "billing@example.com", "--yes",
            env=self.queue_env(**{ENV_POSTSUPER_OUT: str(capture)}), expect=0,
        )
        self.assertIn("Done: hold 3 message(s)", proc.stdout)

    def test_invalid_address_is_a_usage_error(self):
        self.run_cli("queue", "drain", "--sender", "not-an-address", "--dry-run",
                     env=self.queue_env(), expect=EXIT_USAGE)


class IpTests(MailutTestCase):
    def front_env(self):
        return {ENV_FRONT_LOG: str(FIXTURES / "front.log")}

    def test_external_ips_are_surfaced(self):
        proc = self.run_cli("ips", "--since", "6h", env=self.front_env(), expect=0)
        self.assertIn("203.0.113.66", proc.stdout)
        self.assertIn("198.51.100.20", proc.stdout)

    def test_private_addresses_are_hidden_by_default(self):
        proc = self.run_cli("ips", env=self.front_env(), expect=0)
        self.assertNotIn("192.168.0.9", proc.stdout)
        self.assertNotIn("172.20.0.5", proc.stdout)
        proc = self.run_cli("ips", "--all", env=self.front_env(), expect=0)
        self.assertIn("192.168.0.9", proc.stdout)

    def test_user_filter_narrows_to_one_account(self):
        proc = self.run_cli("ips", "--user", "noreply@example.com", env=self.front_env(), expect=0)
        self.assertIn("203.0.113.66", proc.stdout)
        self.assertNotIn("198.51.100.20", proc.stdout)

    def test_exclusions(self):
        proc = self.run_cli("ips", "--exclude", "203.0.113.66", env=self.front_env(), expect=0)
        self.assertNotIn("203.0.113.66", proc.stdout)

    def test_json_output(self):
        proc = self.run_cli("ips", "--json", env=self.front_env(), expect=0)
        payload = json.loads(proc.stdout)
        top = payload["results"][0]
        self.assertEqual(top["ip"], "203.0.113.66")
        self.assertEqual(top["lines"], 5)
        self.assertIn("noreply@example.com", top["users"])

    def test_tally_ignores_invalid_octets(self):
        rows = ips.tally("client: 999.1.2.3 and 203.0.113.7\n")
        self.assertEqual([r["ip"] for r in rows], ["203.0.113.7"])


class WatchTests(MailutTestCase):
    def watch_env(self, log="smtp-abuse.log", queue="postqueue-incident.json"):
        return {
            ENV_QUEUE: str(FIXTURES / queue),
            ENV_SMTP_LOG: str(FIXTURES / log),
        }

    def test_watch_print_does_not_record(self):
        proc = self.run_cli("watch", "--print", env=self.watch_env(), expect=0)
        self.assertIn("severity=critical", proc.stdout)
        self.assertIn("queue_total=63", proc.stdout)
        proc = self.run_cli("report", expect=0)
        self.assertIn("samples:        0", proc.stdout)

    def test_watch_records_a_sample(self):
        self.run_cli("watch", env=self.watch_env(), expect=0)
        proc = self.run_cli("report", "--json", expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["totals"]["samples"], 1)
        self.assertEqual(payload["totals"]["criticals"], 1)
        self.assertEqual(payload["samples"][0]["queue_total"], 63)

    def test_quiet_sample_is_ok(self):
        proc = self.run_cli("watch", "--print",
                            env=self.watch_env(queue="postqueue-quiet.json"), expect=0)
        self.assertIn("severity=", proc.stdout)
        self.assertIn("queue_total=1", proc.stdout)

    def test_watch_json(self):
        proc = self.run_cli("watch", "--print", "--json", env=self.watch_env(), expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["queue_total"], 63)
        self.assertEqual(payload["severity"], "critical")
        self.assertIn("rate_limit_seen", payload["reasons"])

    def test_report_without_samples(self):
        proc = self.run_cli("report", expect=0)
        self.assertIn("No samples recorded yet", proc.stdout)


class StatusTests(MailutTestCase):
    def test_status_runs_without_a_database(self):
        proc = self.run_cli("status", expect=0)
        self.assertIn("Mailu Tools", proc.stdout)
        self.assertIn("not created yet", proc.stdout)

    def test_status_json(self):
        self.run_cli("audit", "add", "all", expect=0)
        proc = self.run_cli("status", "--json", expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["database"]["scopes"], 1)
        self.assertEqual(payload["database"]["schema_version"], 1)
        self.assertIn("collector", payload)

    def test_doctor_reports_checks_and_does_not_change_state(self):
        proc = self.run_cli("doctor")
        self.assertIn("checks:", proc.stdout)
        self.assertIn("python", proc.stdout)
        self.assertIn(proc.returncode, (0, 4))
        self.assertFalse((self.state_dir / "mailut.sqlite3").exists())

    def test_audit_doctor_is_the_same_command(self):
        one = self.run_cli("doctor").stdout
        two = self.run_cli("audit", "doctor").stdout
        self.assertEqual(one.count("["), two.count("["))
