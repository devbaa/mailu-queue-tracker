"""Storing events: scope binding, levels, payloads, retention, de-duplication."""

import datetime
import gzip
import stat
from pathlib import Path

from helpers import MailutTestCase, make_event

from mailut import scopes as scope_store
from mailut.util import from_iso, utcnow


class EventStoreTests(MailutTestCase):
    def add_scope(self, scope_type="all", value="*", level="metadata", retention=30,
                  message_retention=None):
        return scope_store.upsert_scope(
            self.db(), scope_type=scope_type, value=value, mode="include", level=level,
            retention_days=retention, message_retention_days=message_retention,
        )[0]

    # -- scope binding ------------------------------------------------------
    def test_event_out_of_scope_is_not_stored(self):
        result = self.store().store(make_event())
        self.assertEqual(result["status"], "out_of_scope")
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"], 0)

    def test_accepted_event_is_stored(self):
        self.add_scope()
        result = self.store().store(make_event(action="accept"))
        self.assertEqual(result["status"], "stored")
        row = self.db().execute("SELECT * FROM audit_events").fetchone()
        self.assertEqual(row["action"], "accept")
        self.assertEqual(row["envelope_to_domain"], "example.com")
        self.assertEqual(row["envelope_from_domain"], "example.net")

    def test_store_accepted_can_be_disabled(self):
        path = self.tmp / "no-accept.conf"
        path.write_text(
            f"[storage]\nstate_dir = {self.state_dir}\n[audit]\nstore_accepted = false\n",
            encoding="utf-8",
        )
        from mailut.config import Config
        from mailut.events import EventStore

        self.add_scope()
        store = EventStore(self.db(), Config.load(path))
        self.assertEqual(store.store(make_event(action="accept"))["status"], "out_of_scope")
        self.assertEqual(store.store(make_event(action="reject", stage="rcpt"))["status"], "stored")

    # -- de-duplication -----------------------------------------------------
    def test_duplicate_ingestion_is_ignored(self):
        self.add_scope()
        event = make_event(queue_id="4ABC")
        self.assertEqual(self.store().store(event)["status"], "stored")
        self.assertEqual(self.store().store(make_event(queue_id="4ABC", occurred_at=event.occurred_at))["status"],
                         "duplicate")
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"], 1)

    def test_greylist_retry_is_a_distinct_event(self):
        self.add_scope()
        first = utcnow()
        self.store().store(
            make_event(occurred_at=first, action="greylist", stage="data", reason="greylisting")
        )
        self.store().store(
            make_event(
                occurred_at=first + datetime.timedelta(minutes=5),
                action="accept",
                stage="data",
            )
        )
        rows = self.db().execute("SELECT action FROM audit_events ORDER BY occurred_at").fetchall()
        self.assertEqual([r["action"] for r in rows], ["greylist", "accept"])

    def test_same_second_different_recipient_is_distinct(self):
        self.add_scope()
        when = utcnow()
        self.store().store(make_event(occurred_at=when, envelope_to="a@example.com"))
        self.store().store(make_event(occurred_at=when, envelope_to="b@example.com"))
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"], 2)

    # -- pre-DATA invariants ------------------------------------------------
    def test_pre_data_event_never_stores_a_subject(self):
        self.add_scope()
        self.store().store(
            make_event(stage="rcpt", action="reject", subject="invented", message_id="nope@x")
        )
        row = self.db().execute("SELECT subject, message_id FROM audit_events").fetchone()
        self.assertIsNone(row["subject"])
        self.assertIsNone(row["message_id"])

    def test_message_id_enrichment_skips_pre_data_events(self):
        self.add_scope()
        store = self.store()
        store.store(make_event(stage="rcpt", action="reject", queue_id="4Q"))
        store.store(make_event(stage="data", action="accept", queue_id="4Q"))
        updated = store.attach_message_id("4Q", "found@example.net")
        self.assertEqual(updated, 1)
        rows = self.db().execute(
            "SELECT stage, message_id FROM audit_events ORDER BY stage"
        ).fetchall()
        by_stage = {r["stage"]: r["message_id"] for r in rows}
        self.assertEqual(by_stage["data"], "found@example.net")
        self.assertIsNone(by_stage["rcpt"])

    # -- symbols ------------------------------------------------------------
    def test_symbols_are_stored_and_queryable(self):
        self.add_scope()
        self.store().store(
            make_event(
                symbols=[
                    {"symbol": "RBL_SPAMHAUS", "score": 7.0, "options": "127.0.0.2"},
                    {"symbol": "BAYES_SPAM", "score": 5.1, "options": None},
                    {"symbol": "", "score": 1.0},
                ]
            )
        )
        rows = self.db().execute("SELECT symbol, score, options FROM audit_symbols ORDER BY symbol").fetchall()
        self.assertEqual([r["symbol"] for r in rows], ["BAYES_SPAM", "RBL_SPAMHAUS"])
        self.assertAlmostEqual(rows[1]["score"], 7.0)
        self.assertEqual(rows[1]["options"], "127.0.0.2")

    # -- retention ----------------------------------------------------------
    def test_expiry_is_written_from_the_scope_retention(self):
        self.add_scope(retention=365)
        event = make_event()
        self.store().store(event)
        row = self.db().execute("SELECT occurred_at, expires_at FROM audit_events").fetchone()
        delta = from_iso(row["expires_at"]) - from_iso(row["occurred_at"])
        self.assertEqual(delta.days, 365)

    def test_changing_retention_does_not_rewrite_history(self):
        self.add_scope(retention=30)
        self.store().store(make_event(queue_id="first"))
        self.add_scope(retention=365)
        self.store().store(make_event(queue_id="second"))
        rows = self.db().execute(
            "SELECT queue_id, occurred_at, expires_at FROM audit_events ORDER BY queue_id"
        ).fetchall()
        days = {
            r["queue_id"]: (from_iso(r["expires_at"]) - from_iso(r["occurred_at"])).days
            for r in rows
        }
        self.assertEqual(days["first"], 30)
        self.assertEqual(days["second"], 365)

    # -- levels -------------------------------------------------------------
    def test_metadata_level_stores_no_payload(self):
        self.add_scope(level="metadata")
        self.store().store(
            make_event(headers_text="Subject: x\n", raw_message=b"Subject: x\n\nbody")
        )
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS n FROM audit_payloads").fetchone()["n"], 0)

    def test_headers_level_stores_headers_but_no_body(self):
        self.add_scope(level="headers")
        self.store().store(
            make_event(headers_text="Subject: x\nFrom: y\n", raw_message=b"Subject: x\n\nbody")
        )
        rows = self.db().execute("SELECT kind, content, path FROM audit_payloads").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "headers")
        self.assertIn("Subject: x", rows[0]["content"])
        self.assertIsNone(rows[0]["path"])

    def test_message_level_is_ignored_when_globally_disabled(self):
        """A scope can't be created at this level, and stale rows downgrade."""
        self.db().execute(
            "INSERT INTO audit_scopes (scope_type, scope_value, mode, level, retention_days, "
            "created_at, updated_at) VALUES ('all', '*', 'include', 'message', 30, 't', 't')"
        )
        self.store().store(make_event(raw_message=b"Subject: x\n\nbody"))
        row = self.db().execute("SELECT level FROM audit_events").fetchone()
        self.assertEqual(row["level"], "metadata")
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS n FROM audit_payloads").fetchone()["n"], 0)


class MessageStorageTests(MailutTestCase):
    allow_messages = "true"
    message_max_bytes = 4096

    def add_scope(self, **kwargs):
        params = {"scope_type": "all", "value": "*", "mode": "include", "level": "message",
                  "retention_days": 30, "message_retention_days": None}
        params.update(kwargs)
        return scope_store.upsert_scope(self.db(), **params)[0]

    def test_message_is_stored_compressed_and_restricted(self):
        self.add_scope()
        body = b"Subject: stored\n\nhello world\n"
        self.store().store(make_event(raw_message=body))
        row = self.db().execute(
            "SELECT * FROM audit_payloads WHERE kind = 'message'"
        ).fetchone()
        self.assertIsNotNone(row)
        path = Path(row["path"])
        self.assertTrue(path.is_file())
        self.assertTrue(str(path).startswith(str(self.state_dir / "messages")))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(gzip.decompress(path.read_bytes()), body)
        self.assertEqual(row["original_bytes"], len(body))
        self.assertEqual(len(row["sha256"]), 64)

    def test_message_directories_are_date_partitioned(self):
        self.add_scope()
        when = utcnow()
        self.store().store(make_event(occurred_at=when, raw_message=b"x"))
        row = self.db().execute("SELECT path FROM audit_payloads").fetchone()
        expected = f"{when.year:04d}/{when.month:02d}/{when.day:02d}"
        self.assertIn(expected, row["path"])

    def test_oversized_message_is_not_stored_and_is_recorded(self):
        self.add_scope()
        self.store().store(make_event(raw_message=b"x" * 5000))
        self.assertEqual(
            self.db().execute("SELECT COUNT(*) AS n FROM audit_payloads WHERE kind = 'message'")
            .fetchone()["n"],
            0,
        )
        reason = self.db().execute("SELECT reason FROM audit_events").fetchone()["reason"]
        self.assertIn("message_max_bytes", reason)

    def test_message_retention_can_be_shorter_than_metadata_retention(self):
        self.add_scope(retention_days=365, message_retention_days=7)
        self.store().store(make_event(raw_message=b"body"))
        event = self.db().execute("SELECT occurred_at, expires_at FROM audit_events").fetchone()
        payload = self.db().execute(
            "SELECT expires_at FROM audit_payloads WHERE kind = 'message'"
        ).fetchone()
        self.assertEqual((from_iso(event["expires_at"]) - from_iso(event["occurred_at"])).days, 365)
        self.assertEqual((from_iso(payload["expires_at"]) - from_iso(event["occurred_at"])).days, 7)

    def test_filenames_are_generated_not_derived_from_the_message(self):
        self.add_scope()
        self.store().store(
            make_event(
                subject="../../etc/passwd",
                envelope_from="../../../root@example.net",
                raw_message=b"body",
            )
        )
        path = Path(self.db().execute("SELECT path FROM audit_payloads").fetchone()["path"])
        self.assertNotIn("passwd", str(path))
        self.assertNotIn("..", str(path))
        self.assertTrue(path.name.endswith(".eml.gz"))
