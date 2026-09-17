"""Database creation, migration and backup."""

import os
import sqlite3
import stat

from helpers import MailutTestCase

from mailut import migrations
from mailut.db import Database, backup, migrate_database, schema_version
from mailut.util import MailutError


class DatabaseTests(MailutTestCase):
    def test_database_is_created_automatically(self):
        config = self.config()
        self.assertFalse(config.database.exists())
        conn = self.db()
        self.assertTrue(config.database.exists())
        self.assertEqual(schema_version(conn), migrations.LATEST)

    def test_state_directory_and_database_are_owner_only(self):
        config = self.config()
        self.db()
        self.assertEqual(stat.S_IMODE(config.database.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(config.state_dir.stat().st_mode), 0o700)

    def test_expected_tables_exist(self):
        conn = self.db()
        names = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        for table in (
            "schema_migrations", "audit_scopes", "audit_events", "audit_symbols",
            "audit_payloads", "collector_state", "watch_samples", "purge_runs",
        ):
            self.assertIn(table, names)

    def test_pragmas(self):
        conn = self.db()
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_migration_is_idempotent(self):
        conn = self.db()
        before, after = migrate_database(conn)
        self.assertEqual(before, migrations.LATEST)
        self.assertEqual(after, migrations.LATEST)
        rows = conn.execute("SELECT COUNT(*) AS n FROM schema_migrations").fetchone()["n"]
        self.assertEqual(rows, len(migrations.MIGRATIONS))

    def test_newer_schema_is_refused(self):
        conn = self.db()
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
            (migrations.LATEST + 5, "2026-01-01T00:00:00Z", "from the future"),
        )
        with self.assertRaises(MailutError):
            migrate_database(conn)

    def test_foreign_keys_cascade(self):
        conn = self.db()
        from mailut import scopes as scope_store

        scope, _ = scope_store.upsert_scope(
            conn, scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        conn.execute(
            "INSERT INTO audit_events (fingerprint, occurred_at, received_at, source, stage, "
            "action, level, expires_at) VALUES ('fp', 't', 't', 'postfix', 'rcpt', 'reject', "
            "'metadata', 't')"
        )
        event_id = conn.execute("SELECT id FROM audit_events").fetchone()["id"]
        conn.execute(
            "INSERT INTO audit_symbols (event_id, symbol) VALUES (?, 'X')", (event_id,)
        )
        conn.execute("DELETE FROM audit_events WHERE id = ?", (event_id,))
        self.assertEqual(
            conn.execute("SELECT COUNT(*) AS n FROM audit_symbols").fetchone()["n"], 0
        )
        self.assertIsNotNone(scope.id)

    def test_backup_is_consistent_and_restricted(self):
        conn = self.db()
        conn.execute("INSERT INTO collector_state (key, value, updated_at) VALUES ('k', 'v', 't')")
        destination = self.tmp / "backups" / "copy.sqlite3"
        backup(conn, destination)
        self.assertTrue(destination.is_file())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        other = sqlite3.connect(str(destination))
        try:
            value = other.execute("SELECT value FROM collector_state WHERE key = 'k'").fetchone()
            self.assertEqual(value[0], "v")
        finally:
            other.close()

    def test_open_readonly_requires_an_existing_database(self):
        config = self.config()
        database = Database(config.database)
        with self.assertRaises(MailutError):
            database.open_readonly()

    def test_size_bytes_counts_wal_sidecars(self):
        self.db()
        config = self.config()
        database = Database(config.database)
        self.assertGreater(database.size_bytes(), os.path.getsize(config.database) - 1)
