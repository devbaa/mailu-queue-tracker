"""The command line itself: help, exit codes, JSON output, end-to-end flows."""

import json

from helpers import FIXTURES, MailutTestCase

from mailut.util import EXIT_ABORTED, EXIT_FAILURE, EXIT_USAGE


class HelpTests(MailutTestCase):
    def test_top_level_help(self):
        proc = self.run_cli("--help", expect=0)
        for command in ("audit", "queue", "ips", "report", "watch", "status",
                        "upgrade", "uninstall", "version"):
            self.assertIn(command, proc.stdout)
        self.assertIn("Exit status:", proc.stdout)

    def test_help_command_matches_help_flag(self):
        self.assertEqual(self.run_cli("help", expect=0).stdout, self.run_cli("--help", expect=0).stdout)

    def test_help_for_every_documented_level(self):
        for args in (
            ("audit", "--help"),
            ("audit", "add", "--help"),
            ("audit", "add", "domain", "--help"),
            ("audit", "remove", "--help"),
            ("audit", "purge", "--help"),
            ("audit", "show", "--help"),
            ("queue", "--help"),
            ("queue", "drain", "--help"),
            ("ips", "--help"),
            ("upgrade", "--help"),
            ("uninstall", "--help"),
        ):
            proc = self.run_cli(*args, expect=0)
            self.assertTrue(proc.stdout.strip(), f"empty help for {args}")
            self.assertIn("usage:", proc.stdout)

    def test_help_topic_navigation(self):
        proc = self.run_cli("help", "audit", "purge", expect=0)
        self.assertIn("--expired", proc.stdout)

    def test_unknown_help_topic_is_a_usage_error(self):
        self.run_cli("help", "nonsense", expect=EXIT_USAGE)

    def test_documented_options_are_discoverable(self):
        proc = self.run_cli("audit", "add", "email", "--help", expect=0)
        for option in ("--retention", "--level", "--message-retention"):
            self.assertIn(option, proc.stdout)

    def test_version_forms_agree(self):
        one = self.run_cli("version", expect=0).stdout.strip()
        two = self.run_cli("--version", expect=0).stdout.strip()
        self.assertEqual(one, two)
        self.assertTrue(one.startswith("mailut "))


class ExitCodeTests(MailutTestCase):
    def test_success(self):
        self.run_cli("audit", "scopes", expect=0)

    def test_usage_error_for_unknown_command(self):
        self.run_cli("nope", expect=EXIT_USAGE)

    def test_usage_error_for_unknown_option(self):
        self.run_cli("audit", "scopes", "--nope", expect=EXIT_USAGE)

    def test_usage_error_for_invalid_domain(self):
        proc = self.run_cli("audit", "add", "domain", "not a domain", expect=EXIT_USAGE)
        self.assertIn("invalid domain", proc.stderr)

    def test_usage_error_for_invalid_email(self):
        self.run_cli("audit", "add", "email", "nope", expect=EXIT_USAGE)

    def test_usage_error_for_two_purge_selectors(self):
        self.run_cli("audit", "purge", "--expired", "--all", "--yes", expect=EXIT_USAGE)

    def test_usage_error_for_disabled_level(self):
        proc = self.run_cli("audit", "add", "domain", "example.com", "--level", "message",
                            expect=EXIT_USAGE)
        self.assertIn("disabled on this host", proc.stderr)
        self.assertNotIn("Added", proc.stdout)

    def test_runtime_failure_for_a_broken_config(self):
        broken = self.tmp / "broken.conf"
        broken.write_text("[audit]\ndefault_retention_days = zero\n", encoding="utf-8")
        proc = self.run_cli("--config", str(broken), "status", expect=EXIT_FAILURE)
        self.assertIn("must be an integer", proc.stderr)

    def test_destructive_command_without_a_terminal_aborts(self):
        self.run_cli("audit", "add", "all", expect=0)
        self.run_cli("audit", "ingest", "rspamd", "--file",
                     str(FIXTURES / "rspamd-accept.json"), expect=0)
        proc = self.run_cli("audit", "purge", "--all", expect=EXIT_ABORTED)
        self.assertIn("aborted", proc.stderr)
        # and nothing was deleted
        self.assertIn("1 event(s)", self.run_cli("audit", "show", "--since", "400d").stdout)


class ScopeCliTests(MailutTestCase):
    def test_scope_lifecycle(self):
        self.run_cli("audit", "add", "all", expect=0)
        self.run_cli("audit", "remove", "domain", "internal.example.com", expect=0)
        proc = self.run_cli("audit", "add", "email", "monitored@internal.example.com",
                            "--retention", "365", expect=0)
        self.assertIn("365", proc.stdout)

        proc = self.run_cli("audit", "scopes", expect=0)
        self.assertIn("TYPE", proc.stdout)
        self.assertIn("internal.example.com", proc.stdout)
        self.assertIn("exclude", proc.stdout)
        self.assertIn("365d", proc.stdout)

        proc = self.run_cli("audit", "scopes", "--json", expect=0)
        records = json.loads(proc.stdout)
        by_value = {r["scope_value"]: r for r in records}
        self.assertEqual(by_value["*"]["mode"], "include")
        self.assertEqual(by_value["internal.example.com"]["mode"], "exclude")
        self.assertEqual(by_value["monitored@internal.example.com"]["retention_days"], 365)

    def test_scope_test_helper(self):
        self.run_cli("audit", "add", "all", expect=0)
        self.run_cli("audit", "remove", "domain", "private.example.com", expect=0)
        proc = self.run_cli("audit", "scopes", "--test", "x@private.example.com", expect=0)
        self.assertIn("not collected", proc.stdout)
        proc = self.run_cli("audit", "scopes", "--test", "x@example.com", expect=0)
        self.assertIn("collected via all", proc.stdout)

    def test_remove_says_history_is_kept(self):
        self.run_cli("audit", "add", "domain", "example.com", expect=0)
        proc = self.run_cli("audit", "remove", "domain", "example.com", expect=0)
        self.assertIn("Existing records are kept", proc.stdout)

    def test_retention_bounds_are_validated(self):
        self.run_cli("audit", "add", "domain", "example.com", "--retention", "0", expect=EXIT_USAGE)
        self.run_cli("audit", "add", "domain", "example.com", "--retention", "99999",
                     expect=EXIT_USAGE)


class IngestCliTests(MailutTestCase):
    def test_end_to_end_rspamd_then_query(self):
        self.run_cli("audit", "add", "domain", "example.com", expect=0)
        for name in ("rspamd-accept.json", "rspamd-greylist.json", "rspamd-spam.json"):
            proc = self.run_cli("audit", "ingest", "rspamd", "--file", str(FIXTURES / name),
                                expect=0)
            self.assertEqual(json.loads(proc.stdout)["stored"], 1)

        proc = self.run_cli("audit", "show", "--since", "400d", expect=0)
        self.assertIn("3 event(s)", proc.stdout)
        self.assertIn("September invoice", proc.stdout)

        proc = self.run_cli("audit", "show", "--symbol", "RBL_SPAMHAUS", "--since", "400d",
                            "--json", expect=0)
        records = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["action"], "reject")

    def test_duplicate_ingestion_is_reported_not_duplicated(self):
        self.run_cli("audit", "add", "all", expect=0)
        path = str(FIXTURES / "rspamd-accept.json")
        self.run_cli("audit", "ingest", "rspamd", "--file", path, expect=0)
        proc = self.run_cli("audit", "ingest", "rspamd", "--file", path, expect=0)
        self.assertEqual(json.loads(proc.stdout)["duplicate"], 1)

    def test_postfix_log_ingestion(self):
        self.run_cli("audit", "add", "all", expect=0)
        proc = self.run_cli("audit", "ingest", "postfix", "--file",
                            str(FIXTURES / "smtp-inbound.log"), expect=0)
        summary = json.loads(proc.stdout)
        self.assertGreaterEqual(summary["stored"], 5)
        self.assertGreaterEqual(summary["unparsed"], 1)

        proc = self.run_cli("audit", "show", "--stage", "rcpt", "--since", "400d", expect=0)
        self.assertIn("unavailable (rejected before DATA)", proc.stdout)

        proc = self.run_cli("audit", "stats", "--since", "400d", "--json", expect=0)
        stats = json.loads(proc.stdout)
        self.assertGreaterEqual(stats["pre_data_rejected"], 3)
        self.assertIn("deliver", stats["by_action"])

    def test_out_of_scope_ingestion_stores_nothing(self):
        proc = self.run_cli("audit", "ingest", "rspamd", "--file",
                            str(FIXTURES / "rspamd-accept.json"), expect=0)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["stored"], 0)
        self.assertEqual(summary["out_of_scope"], 1)

    def test_malformed_lines_do_not_fail_the_run(self):
        self.run_cli("audit", "add", "all", expect=0)
        proc = self.run_cli(
            "audit", "ingest", "postfix", input_text="garbage\n\n\x00\x01\nnope\n", expect=0
        )
        self.assertEqual(json.loads(proc.stdout)["stored"], 0)

    def test_purge_dry_run_then_real(self):
        self.run_cli("audit", "add", "all", expect=0)
        self.run_cli("audit", "ingest", "rspamd", "--file",
                     str(FIXTURES / "rspamd-spam.json"), expect=0)
        proc = self.run_cli("audit", "purge", "--domain", "example.com", "--dry-run", expect=0)
        self.assertIn("events:            1", proc.stdout)
        self.assertIn("dry run", proc.stdout)
        proc = self.run_cli("audit", "show", "--since", "400d", expect=0)
        self.assertIn("2 event(s)", proc.stdout)

        self.run_cli("audit", "purge", "--domain", "example.com", "--yes", expect=0)
        proc = self.run_cli("audit", "show", "--since", "400d", expect=0)
        self.assertIn("1 event(s)", proc.stdout)

    def test_remove_scope_keeps_history(self):
        self.run_cli("audit", "add", "domain", "example.com", expect=0)
        self.run_cli("audit", "ingest", "rspamd", "--file",
                     str(FIXTURES / "rspamd-accept.json"), expect=0)
        self.run_cli("audit", "remove", "domain", "example.com", expect=0)
        proc = self.run_cli("audit", "show", "--since", "400d", expect=0)
        self.assertIn("1 event(s)", proc.stdout)
        proc = self.run_cli("audit", "ingest", "rspamd", "--file",
                            str(FIXTURES / "rspamd-greylist.json"), expect=0)
        self.assertEqual(json.loads(proc.stdout)["out_of_scope"], 1)


class ConfigCliTests(MailutTestCase):
    def test_config_check(self):
        proc = self.run_cli("config", "check", expect=0)
        self.assertIn("ok", proc.stdout)

    def test_config_show_json(self):
        proc = self.run_cli("config", "show", "--json", expect=0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["audit"]["default_level"], "metadata")
        self.assertIn("database", payload["_derived"])

    def test_db_migrate_reports_the_schema(self):
        proc = self.run_cli("db", "migrate", expect=0)
        self.assertIn("schema version 1", proc.stdout)

    def test_db_optimize_does_not_vacuum_by_default(self):
        self.run_cli("db", "migrate", expect=0)
        proc = self.run_cli("db", "optimize", expect=0)
        self.assertIn("VACUUM was not run", proc.stdout)
