"""Querying retained events: filters, output shape and streaming."""

import argparse
import datetime
import io
import json
from contextlib import redirect_stdout

from helpers import MailutTestCase, make_event

from mailut import query
from mailut import scopes as scope_store
from mailut.util import UsageError, utcnow


def show_args(**kwargs):
    params = {
        "since": None, "after": None, "before": None, "domain": None, "recipient": None,
        "sender": None, "sender_domain": None, "action": None, "stage": None,
        "queue_id": None, "message_id": None, "ip": None, "symbol": None,
        "limit": 100, "json": False,
    }
    params.update(kwargs)
    return argparse.Namespace(**params)


class QueryTests(MailutTestCase):
    def setUp(self):
        super().setUp()
        scope_store.upsert_scope(
            self.db(), scope_type="all", value="*", mode="include", level="metadata",
            retention_days=30, message_retention_days=None,
        )
        store = self.store()
        now = utcnow()
        store.store(
            make_event(
                occurred_at=now - datetime.timedelta(hours=1),
                action="reject", stage="rcpt", envelope_to="user@example.com",
                envelope_from="spammer@example.net", remote_ip="203.0.113.4",
                smtp_code="550", smtp_enhanced_code="5.7.1",
                reason="Recipient address rejected: Access denied",
            )
        )
        store.store(
            make_event(
                occurred_at=now - datetime.timedelta(minutes=30),
                action="reject", stage="data", envelope_to="user@example.com",
                envelope_from="spammer@example.net", subject="You have won",
                message_id="spam1@example.net", queue_id="4SpAm",
                rspamd_score=19.2, rspamd_required=6.0, rspamd_action="reject",
                symbols=[{"symbol": "RBL_SPAMHAUS", "score": 7.0, "options": "127.0.0.2"}],
            )
        )
        store.store(
            make_event(
                occurred_at=now - datetime.timedelta(days=10),
                action="accept", stage="data", envelope_to="other@example.org",
                envelope_from="friend@example.net", subject="Hello",
            )
        )

    def show(self, **kwargs):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            query.cmd_show(show_args(**kwargs), self.config(), self.db())
        return buffer.getvalue()

    def stats(self, **kwargs):
        buffer = io.StringIO()
        args = show_args(**kwargs)
        args.limit = None
        with redirect_stdout(buffer):
            query.cmd_stats(args, self.config(), self.db())
        return buffer.getvalue()

    # -- filtering ----------------------------------------------------------
    def test_since_filter(self):
        self.assertIn("2 event(s)", self.show(since="24h"))
        self.assertIn("3 event(s)", self.show(since="30d"))

    def test_recipient_and_domain_filters(self):
        self.assertIn("2 event(s)", self.show(recipient="user@example.com", since="30d"))
        self.assertIn("1 event(s)", self.show(domain="example.org", since="30d"))

    def test_sender_filter(self):
        self.assertIn("2 event(s)", self.show(sender="spammer@example.net", since="30d"))

    def test_combined_recipient_and_sender(self):
        output = self.show(recipient="user@example.com", sender="spammer@example.net", since="30d")
        self.assertIn("2 event(s)", output)

    def test_action_and_stage_filters(self):
        self.assertIn("1 event(s)", self.show(action=["accept"], since="30d"))
        self.assertIn("1 event(s)", self.show(stage=["rcpt"], since="30d"))

    def test_symbol_filter(self):
        self.assertIn("1 event(s)", self.show(symbol="RBL_SPAMHAUS", since="30d"))
        self.assertIn("No matching SMTP activity", self.show(symbol="NOT_A_SYMBOL", since="30d"))

    def test_queue_and_message_id_filters(self):
        self.assertIn("1 event(s)", self.show(queue_id="4SpAm", since="30d"))
        self.assertIn("1 event(s)", self.show(message_id="<spam1@example.net>", since="30d"))

    def test_ip_filter(self):
        self.assertIn("1 event(s)", self.show(ip="203.0.113.4", since="30d"))

    def test_limit(self):
        self.assertIn("1 event(s)", self.show(since="30d", limit=1))

    def test_invalid_action_is_a_usage_error(self):
        with self.assertRaises(UsageError):
            query.build_filters(show_args(action=["nonsense"]))

    def test_invalid_duration_is_a_usage_error(self):
        with self.assertRaises(UsageError):
            query.build_filters(show_args(since="soon"))

    # -- output -------------------------------------------------------------
    def test_pre_data_event_says_subject_is_unavailable(self):
        output = self.show(stage=["rcpt"], since="30d")
        self.assertIn("unavailable (rejected before DATA)", output)
        self.assertNotIn("You have won", output)

    def test_no_match_uses_factual_wording(self):
        output = self.show(recipient="nobody@example.com", since="30d")
        self.assertIn("No matching SMTP activity was recorded during the retained period.", output)
        self.assertNotIn("did not send", output)

    def test_json_output_is_json_lines(self):
        output = self.show(since="30d", json=True)
        lines = [line for line in output.splitlines() if line.strip()]
        self.assertEqual(len(lines), 3)
        records = [json.loads(line) for line in lines]
        for record in records:
            self.assertIn("occurred_at", record)
            self.assertIn("action", record)
            self.assertIn("symbols", record)
            self.assertIn("subject_available", record)
        spam = next(r for r in records if r["queue_id"] == "4SpAm")
        self.assertEqual(spam["symbols"][0]["symbol"], "RBL_SPAMHAUS")
        pre_data = next(r for r in records if r["stage"] == "rcpt")
        self.assertFalse(pre_data["subject_available"])
        self.assertIsNone(pre_data["subject"])

    def test_terminal_control_characters_are_escaped(self):
        self.store().store(
            make_event(
                occurred_at=utcnow(),
                subject="clean\x1b[31mred\x1b[0m\nsecond line",
                envelope_to="user@example.com",
                queue_id="ESCAPE",
            )
        )
        output = self.show(queue_id="ESCAPE")
        self.assertNotIn("\x1b", output)
        self.assertIn("\\x1b", output)

    # -- stats --------------------------------------------------------------
    def test_stats_counts_and_span(self):
        output = self.stats(since="30d")
        self.assertIn("Events:              3", output)
        self.assertIn("reject", output)
        self.assertIn("Pre-DATA rejected:   1", output)
        self.assertIn("Database size:", output)
        self.assertIn("RBL_SPAMHAUS", output)

    def test_stats_json(self):
        output = self.stats(since="30d", json=True)
        payload = json.loads(output)
        self.assertEqual(payload["events"], 3)
        self.assertEqual(payload["by_action"]["reject"], 2)
        self.assertEqual(payload["pre_data_rejected"], 1)
        self.assertIn("database_bytes", payload)
        self.assertIn("next_expiration", payload)

    def test_stats_respects_filters(self):
        payload = json.loads(self.stats(domain="example.org", since="30d", json=True))
        self.assertEqual(payload["events"], 1)
