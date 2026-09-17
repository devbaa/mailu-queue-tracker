"""Purging: selectors, dry runs, safety and idempotency."""

import argparse
import datetime
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

from helpers import MailutTestCase, make_event

from mailut import purge
from mailut import scopes as scope_store
from mailut.util import AbortedError, UsageError, to_iso, utcnow


def purge_args(**kwargs):
    params = {
        "expired": False, "all": False, "domain": None, "email": None, "before": None,
        "dry_run": False, "yes": True, "json": False,
    }
    params.update(kwargs)
    return argparse.Namespace(**params)


class PurgeTests(MailutTestCase):
    allow_messages = "true"

    def add_scope(self, level="metadata", retention=30, message_retention=None):
        return scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level=level,
            retention_days=retention, message_retention_days=message_retention,
        )[0]

    def seed(self, count=3, recipient="user@example.com", **kwargs):
        self.add_scope(**kwargs)
        store = self.store()
        when = utcnow()
        for index in range(count):
            store.store(
                make_event(
                    occurred_at=when - datetime.timedelta(minutes=index),
                    envelope_to=recipient,
                    queue_id=f"Q{index}",
                )
            )

    def expire_all(self):
        past = to_iso(utcnow() - datetime.timedelta(days=1))
        self.db().execute("UPDATE audit_events SET expires_at = ?", (past,))
        self.db().execute("UPDATE audit_payloads SET expires_at = ?", (past,))

    def count(self):
        return self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]

    def run_purge(self, **kwargs):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = purge.cmd_purge(purge_args(**kwargs), self.config(), self.db())
        return code, buffer.getvalue()

    # -- selectors ----------------------------------------------------------
    def test_exactly_one_selector_is_required(self):
        with self.assertRaises(UsageError):
            purge.cmd_purge(purge_args(), self.config(), self.db())
        with self.assertRaises(UsageError):
            purge.cmd_purge(purge_args(expired=True, all=True), self.config(), self.db())

    def test_dry_run_changes_nothing(self):
        self.seed(3)
        self.expire_all()
        code, output = self.run_purge(expired=True, dry_run=True)
        self.assertEqual(code, 0)
        self.assertIn("dry run", output)
        self.assertIn("events:            3", output)
        self.assertEqual(self.count(), 3)

    def test_expired_purge_deletes_only_expired_records(self):
        self.seed(2, recipient="old@example.com")
        self.expire_all()
        self.seed(2, recipient="new@example.com")
        code, _ = self.run_purge(expired=True)
        self.assertEqual(code, 0)
        remaining = self.db().execute("SELECT envelope_to FROM audit_events").fetchall()
        self.assertTrue(all(row["envelope_to"] == "new@example.com" for row in remaining))
        self.assertEqual(len(remaining), 2)

    def test_expired_purge_is_idempotent(self):
        self.seed(2)
        self.expire_all()
        self.run_purge(expired=True)
        code, _ = self.run_purge(expired=True)
        self.assertEqual(code, 0)
        self.assertEqual(self.count(), 0)

    def test_domain_purge(self):
        self.seed(2, recipient="a@example.com")
        self.seed(2, recipient="b@example.org")
        self.run_purge(domain="example.com")
        rows = self.db().execute("SELECT envelope_to_domain FROM audit_events").fetchall()
        self.assertEqual({r["envelope_to_domain"] for r in rows}, {"example.org"})

    def test_email_purge(self):
        self.seed(2, recipient="john@example.com")
        self.seed(2, recipient="jane@example.com")
        self.run_purge(email="john@example.com")
        rows = self.db().execute("SELECT envelope_to FROM audit_events").fetchall()
        self.assertEqual({r["envelope_to"] for r in rows}, {"jane@example.com"})

    def test_before_purge(self):
        self.add_scope()
        store = self.store()
        store.store(make_event(occurred_at=utcnow() - datetime.timedelta(days=10), queue_id="old"))
        store.store(make_event(occurred_at=utcnow(), queue_id="new"))
        cutoff = to_iso(utcnow() - datetime.timedelta(days=1))[:10]
        self.run_purge(before=cutoff)
        rows = self.db().execute("SELECT queue_id FROM audit_events").fetchall()
        self.assertEqual([r["queue_id"] for r in rows], ["new"])

    # -- safety -------------------------------------------------------------
    def test_purge_all_requires_confirmation(self):
        self.seed(2)
        with redirect_stdout(io.StringIO()), self.assertRaises(AbortedError):
            purge.cmd_purge(purge_args(all=True, yes=False), self.config(), self.db())
        self.assertEqual(self.count(), 2)

    def test_purge_all_with_yes(self):
        self.seed(3)
        code, _ = self.run_purge(all=True)
        self.assertEqual(code, 0)
        self.assertEqual(self.count(), 0)

    def test_non_interactive_purge_without_yes_aborts(self):
        self.seed(2)
        with redirect_stdout(io.StringIO()), self.assertRaises(AbortedError):
            purge.cmd_purge(purge_args(domain="example.com", yes=False), self.config(), self.db())
        self.assertEqual(self.count(), 2)

    # -- payloads -----------------------------------------------------------
    def test_payload_files_are_deleted_with_their_events(self):
        self.add_scope(level="message")
        self.store().store(make_event(raw_message=b"Subject: x\n\nbody"))
        path = Path(self.db().execute("SELECT path FROM audit_payloads").fetchone()["path"])
        self.assertTrue(path.is_file())
        self.expire_all()
        code, output = self.run_purge(expired=True)
        self.assertEqual(code, 0)
        self.assertFalse(path.exists())
        self.assertEqual(
            self.db().execute("SELECT COUNT(*) AS n FROM audit_payloads").fetchone()["n"], 0
        )
        self.assertIn("file(s)", output)

    def test_expired_payload_is_removed_while_the_event_remains(self):
        self.add_scope(level="message", retention=365, message_retention=1)
        self.store().store(make_event(raw_message=b"Subject: x\n\nbody"))
        path = Path(self.db().execute("SELECT path FROM audit_payloads").fetchone()["path"])
        self.db().execute(
            "UPDATE audit_payloads SET expires_at = ?",
            (to_iso(utcnow() - datetime.timedelta(days=1)),),
        )
        self.run_purge(expired=True)
        self.assertFalse(path.exists())
        self.assertEqual(self.count(), 1)
        self.assertEqual(
            self.db().execute("SELECT COUNT(*) AS n FROM audit_payloads").fetchone()["n"], 0
        )

    def test_missing_payload_file_does_not_block_the_purge(self):
        self.add_scope(level="message")
        self.store().store(make_event(raw_message=b"body"))
        path = Path(self.db().execute("SELECT path FROM audit_payloads").fetchone()["path"])
        path.unlink()
        self.expire_all()
        code, _ = self.run_purge(expired=True)
        self.assertEqual(code, 0)
        self.assertEqual(self.count(), 0)

    def test_purge_run_is_recorded(self):
        self.seed(1)
        self.expire_all()
        self.run_purge(expired=True)
        row = self.db().execute("SELECT * FROM purge_runs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["selector"], "expired")
        self.assertIsNotNone(row["finished_at"])
        self.assertEqual(row["events"], 1)

    def test_expired_purge_also_removes_expired_watch_samples(self):
        self.db().execute(
            "INSERT INTO watch_samples (occurred_at, severity, expires_at) VALUES (?, 'ok', ?)",
            (to_iso(utcnow()), to_iso(utcnow() - datetime.timedelta(days=1))),
        )
        self.run_purge(expired=True)
        self.assertEqual(
            self.db().execute("SELECT COUNT(*) AS n FROM watch_samples").fetchone()["n"], 0
        )

    def test_json_dry_run_output(self):
        self.seed(2)
        self.expire_all()
        code, output = self.run_purge(expired=True, dry_run=True, json=True)
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["events"], 2)
