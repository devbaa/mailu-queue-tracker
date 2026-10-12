"""Configuration parsing, validation and derived paths."""

from helpers import MailutTestCase

from mailut.config import Config
from mailut.util import MailutError, UsageError


class ConfigTests(MailutTestCase):
    def test_defaults_without_a_file(self):
        config = Config.load(self.tmp / "does-not-exist.conf")
        self.assertFalse(config.present)
        self.assertEqual(config.get("audit", "default_retention_days"), 30)
        self.assertEqual(config.get("audit", "default_level"), "metadata")
        self.assertTrue(config.get("audit", "store_accepted"))
        self.assertEqual(config.get("collector", "log_poll_seconds"), 30)
        self.assertTrue(config.get("collector", "ingest_smtp_logs"))
        self.assertTrue(config.get("collector", "ingest_rspamd_logs"))

    def test_parses_types(self):
        config = self.config()
        self.assertIsInstance(config.get("collector", "log_poll_seconds"), int)
        self.assertIsInstance(config.get("audit", "store_accepted"), bool)
        self.assertEqual(config.compose_argv, ["/bin/false"])

    def test_derived_paths(self):
        config = self.config()
        self.assertEqual(config.database, self.state_dir / "mailut.sqlite3")
        self.assertEqual(config.message_dir, self.state_dir / "messages")
        self.assertEqual(config.backup_dir, self.state_dir / "backups")

    def test_local_domains_list(self):
        path = self.tmp / "local.conf"
        path.write_text("[mailu]\nlocal_domains = example.com, Example.ORG\n", encoding="utf-8")
        self.assertEqual(Config.load(path).local_domains, ["example.com", "example.org"])

    def test_inline_comment_is_stripped(self):
        path = self.tmp / "comment.conf"
        path.write_text("[collector]\nlog_poll_seconds = 45  # slower\n", encoding="utf-8")
        self.assertEqual(Config.load(path).get("collector", "log_poll_seconds"), 45)

    def test_unknown_section_is_an_error(self):
        path = self.tmp / "bad.conf"
        path.write_text("[nope]\nkey = 1\n", encoding="utf-8")
        with self.assertRaises(MailutError):
            Config.load(path)

    def test_unknown_key_is_an_error(self):
        path = self.tmp / "bad.conf"
        path.write_text("[audit]\nnot_a_setting = 1\n", encoding="utf-8")
        with self.assertRaises(MailutError):
            Config.load(path)

    def test_non_integer_is_an_error(self):
        path = self.tmp / "bad.conf"
        path.write_text("[collector]\nlog_poll_seconds = eight\n", encoding="utf-8")
        with self.assertRaises(MailutError):
            Config.load(path)

    def test_default_level_must_be_collectable(self):
        path = self.tmp / "bad.conf"
        path.write_text("[audit]\ndefault_level = message\n", encoding="utf-8")
        with self.assertRaises(MailutError):
            Config.load(path)

    def test_check_level_allowed(self):
        config = self.config()
        config.check_level_allowed("metadata")
        for level in ("headers", "message"):
            with self.assertRaises(UsageError):
                config.check_level_allowed(level)
        with self.assertRaises(UsageError):
            config.check_level_allowed("everything")

    def test_poll_interval_must_be_positive(self):
        path = self.tmp / "bad.conf"
        path.write_text("[collector]\nlog_poll_seconds = 0\n", encoding="utf-8")
        with self.assertRaises(MailutError):
            Config.load(path)
