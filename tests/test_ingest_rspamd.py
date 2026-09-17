"""Rspamd metadata-exporter ingestion."""

import json

from helpers import FIXTURES, MailutTestCase

from mailut.ingest import rspamd


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class RspamdParseTests(MailutTestCase):
    def test_timestamp_is_taken_from_the_payload(self):
        import datetime

        event = rspamd.parse(load("rspamd-accept.json"))[0]
        self.assertEqual(
            event.occurred_at,
            datetime.datetime(2026, 9, 17, 12, 46, 9, tzinfo=datetime.timezone.utc),
        )

    def test_unix_timestamps_are_accepted_too(self):
        import datetime

        event = rspamd.parse({"rcpt": ["a@example.com"], "timestamp": 1789000000})[0]
        self.assertEqual(
            event.occurred_at,
            datetime.datetime.fromtimestamp(1789000000, tz=datetime.timezone.utc),
        )

    def test_accepted_message(self):
        events = rspamd.parse(load("rspamd-accept.json"))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.action, "accept")
        self.assertEqual(event.rspamd_action, "no action")
        self.assertEqual(event.envelope_from, "sender@example.net")
        self.assertEqual(event.envelope_to, "user@example.com")
        self.assertEqual(event.subject, "September invoice")
        self.assertEqual(event.queue_id, "4AbCd67890")
        self.assertEqual(event.remote_ip, "203.0.113.42")
        self.assertEqual(event.helo, "mx.example.net")
        self.assertAlmostEqual(event.rspamd_score, 0.42)
        self.assertAlmostEqual(event.rspamd_required, 6.0)
        self.assertEqual(event.message_size, 4096)
        self.assertEqual(event.session_id, "9f3a1c")
        self.assertEqual(event.stage, "data")

    def test_authentication_results_from_symbols(self):
        event = rspamd.parse(load("rspamd-accept.json"))[0]
        self.assertEqual(event.spf, "pass")
        self.assertEqual(event.dkim, "pass")
        self.assertEqual(event.dmarc, "pass")

    def test_symbols_are_captured(self):
        event = rspamd.parse(load("rspamd-spam.json"))[0]
        names = {s["symbol"] for s in event.symbols}
        self.assertIn("RBL_SPAMHAUS", names)
        self.assertIn("BAYES_SPAM", names)
        spamhaus = next(s for s in event.symbols if s["symbol"] == "RBL_SPAMHAUS")
        self.assertAlmostEqual(spamhaus["score"], 7.0)
        self.assertEqual(spamhaus["options"], "127.0.0.2")

    def test_one_event_per_recipient(self):
        events = rspamd.parse(load("rspamd-spam.json"))
        self.assertEqual(len(events), 2)
        self.assertEqual(
            {e.envelope_to for e in events}, {"user@example.com", "other@example.org"}
        )
        self.assertNotEqual(events[0].fingerprint(), events[1].fingerprint())

    def test_action_mapping(self):
        self.assertEqual(rspamd.parse(load("rspamd-greylist.json"))[0].action, "greylist")
        self.assertEqual(rspamd.parse(load("rspamd-junk.json"))[0].action, "junk")
        self.assertEqual(rspamd.parse(load("rspamd-spam.json"))[0].action, "reject")

    def test_virus_is_distinguished_from_plain_reject(self):
        event = rspamd.parse(load("rspamd-virus.json"))[0]
        self.assertEqual(event.action, "virus_reject")
        self.assertEqual(event.rspamd_action, "reject")

    def test_greylist_reason_is_recorded(self):
        event = rspamd.parse(load("rspamd-greylist.json"))[0]
        self.assertEqual(event.reason, "greylisting")

    def test_headers_are_carried_when_present(self):
        event = rspamd.parse(load("rspamd-junk.json"))[0]
        self.assertIn("Subject: Weekly deals", event.headers_text)

    def test_malformed_payload_does_not_raise(self):
        events = rspamd.parse(load("rspamd-malformed.json"))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].action, "unknown")
        self.assertIsNone(events[0].rspamd_score)

    def test_non_object_payload_is_rejected(self):
        with self.assertRaises(rspamd.IngestError):
            rspamd.parse(["not", "an", "object"])

    def test_bad_base64_is_rejected(self):
        with self.assertRaises(rspamd.IngestError):
            rspamd.parse({"rcpt": ["user@example.com"], "message_b64": "!!!not base64!!!"})

    def test_symbols_as_a_dictionary(self):
        event = rspamd.parse(
            {
                "rcpt": ["user@example.com"],
                "action": "reject",
                "symbols": {"RBL_SPAMHAUS": {"score": 7.0, "options": ["127.0.0.2"]}},
            }
        )[0]
        self.assertEqual(event.symbols[0]["symbol"], "RBL_SPAMHAUS")
        self.assertEqual(event.symbols[0]["options"], ["127.0.0.2"])
