"""Postfix/Mailu SMTP log parsing."""

import datetime

from helpers import FIXTURES, MailutTestCase

from mailut.events import Event
from mailut.ingest import postfix
from mailut.util import from_iso, normalize_iso, utcnow


def parse(line):
    return postfix.parse_line(line)


PRE_DATA_REJECT = (
    "smtp-1  | 2026-09-17T11:03:21.000000000Z Sep 17 11:03:21 mail postfix/smtpd[111]: "
    "NOQUEUE: reject: RCPT from unknown[203.0.113.4]: 550 5.7.1 <user@example.com>: "
    "Recipient address rejected: Access denied; from=<sender@example.net> "
    "to=<user@example.com> proto=ESMTP helo=<mx.example.net>"
)


class PostfixParseTests(MailutTestCase):
    def test_pre_data_rejection(self):
        event = parse(PRE_DATA_REJECT)
        self.assertIsInstance(event, Event)
        self.assertEqual(event.stage, "rcpt")
        self.assertEqual(event.action, "policy_reject")
        self.assertEqual(event.envelope_from, "sender@example.net")
        self.assertEqual(event.envelope_to, "user@example.com")
        self.assertEqual(event.remote_ip, "203.0.113.4")
        self.assertEqual(event.helo, "mx.example.net")
        self.assertEqual(event.smtp_code, "550")
        self.assertEqual(event.smtp_enhanced_code, "5.7.1")
        self.assertIn("Recipient address rejected", event.reason)

    def test_pre_data_rejection_has_no_subject_or_message_id(self):
        event = parse(PRE_DATA_REJECT)
        self.assertTrue(event.pre_data)
        self.assertIsNone(event.subject)
        self.assertIsNone(event.message_id)
        self.assertIsNone(event.header_from)
        self.assertIsNone(event.raw_message)

    def test_timestamp_is_taken_from_the_docker_stamp(self):
        event = parse(PRE_DATA_REJECT)
        self.assertEqual(
            event.occurred_at,
            datetime.datetime(2026, 9, 17, 11, 3, 21, tzinfo=datetime.timezone.utc),
        )

    def test_connect_stage_rejection_has_no_recipient(self):
        line = (
            "smtp-1  | 2026-09-17T11:04:02.000000000Z Sep 17 11:04:02 mail postfix/smtpd[111]: "
            "NOQUEUE: reject: CONNECT from unknown[203.0.113.9]: 554 5.7.1 Client host rejected: "
            "Access denied; proto=SMTP"
        )
        event = parse(line)
        self.assertEqual(event.stage, "connect")
        self.assertIsNone(event.envelope_to)
        self.assertEqual(event.remote_ip, "203.0.113.9")

    def test_temporary_rejection_is_soft(self):
        line = (
            "smtp-1  | 2026-09-17T11:05:10.000000000Z Sep 17 11:05:10 mail postfix/smtpd[112]: "
            "NOQUEUE: reject: MAIL from unknown[203.0.113.11]: 450 4.7.1 Service unavailable; "
            "from=<spammer@example.net> proto=ESMTP helo=<evil.example.net>"
        )
        event = parse(line)
        self.assertEqual(event.stage, "mail")
        self.assertEqual(event.action, "soft_reject")

    def test_greylisting_is_classified_as_greylist(self):
        line = (
            "smtp-1  | 2026-09-17T11:06:00.000000000Z Sep 17 11:06:00 mail postfix/smtpd[113]: "
            "NOQUEUE: reject: RCPT from mx.example.net[203.0.113.42]: 450 4.7.1 "
            "<user@example.com>: Recipient address rejected: Greylisting in effect, please come "
            "back later; from=<sender@example.net> to=<user@example.com> proto=ESMTP "
            "helo=<mx.example.net>"
        )
        event = parse(line)
        self.assertEqual(event.action, "greylist")

    def test_milter_reject_after_data(self):
        line = (
            "smtp-1  | 2026-09-17T11:07:15.000000000Z Sep 17 11:07:15 mail postfix/smtpd[114]: "
            "4XyZ12345: milter-reject: END-OF-MESSAGE from mx.example.net[203.0.113.77]: 5.7.1 "
            "Gtube pattern; from=<virus@example.net> to=<user@example.com> proto=ESMTP "
            "helo=<mx.example.net>"
        )
        event = parse(line)
        self.assertEqual(event.stage, "data")
        self.assertEqual(event.action, "reject")
        self.assertEqual(event.queue_id, "4XyZ12345")
        self.assertEqual(event.smtp_enhanced_code, "5.7.1")
        self.assertFalse(event.pre_data)

    def test_local_delivery_is_an_event(self):
        line = (
            "smtp-1  | 2026-09-17T11:08:02.000000000Z Sep 17 11:08:02 mail postfix/lmtp[122]: "
            "4AbCd67890: to=<user@example.com>, relay=imap[192.168.203.4]:2525, delay=1.2, "
            "dsn=2.0.0, status=sent (250 2.0.0 <user@example.com> jOe0 Saved)"
        )
        event = parse(line)
        self.assertEqual(event.action, "deliver")
        self.assertEqual(event.stage, "delivery")
        self.assertEqual(event.envelope_to, "user@example.com")
        self.assertEqual(event.queue_id, "4AbCd67890")

    def test_outbound_relay_is_ignored(self):
        line = (
            "smtp-1  | 2026-09-17T11:10:00.000000000Z Sep 17 11:10:00 mail postfix/smtp[140]: "
            "4Out99999: to=<remote@example.org>, relay=mx.example.org[198.51.100.7]:25, "
            "delay=2.0, dsn=2.0.0, status=sent (250 ok)"
        )
        self.assertIsNone(parse(line))

    def test_authenticated_submission_is_ignored(self):
        line = (
            "smtp-1  | 2026-09-17T11:09:00.000000000Z Sep 17 11:09:00 mail postfix/smtpd[130]: "
            "NOQUEUE: reject: RCPT from unknown[203.0.113.55]: 550 5.1.1 <nobody@example.com>: "
            "Recipient address rejected: User unknown; from=<sender@example.net> "
            "to=<nobody@example.com> proto=ESMTP helo=<mx.example.net>, sasl_method=PLAIN, "
            "sasl_username=agent@example.com"
        )
        self.assertIsNone(parse(line))

    def test_reject_warning_is_not_a_rejection(self):
        line = (
            "smtp-1  | 2026-09-17T11:13:00.000000000Z Sep 17 11:13:00 mail postfix/smtpd[152]: "
            "NOQUEUE: reject_warning: RCPT from unknown[203.0.113.99]: 550 5.7.1 "
            "<user@example.com>: would have been rejected; from=<sender@example.net> "
            "to=<user@example.com> proto=ESMTP helo=<mx.example.net>"
        )
        self.assertIsNone(parse(line))

    def test_message_id_enrichment(self):
        line = (
            "smtp-1  | 2026-09-17T11:08:00.000000000Z Sep 17 11:08:00 mail postfix/cleanup[120]: "
            "4AbCd67890: message-id=<abc123@example.net>"
        )
        result = parse(line)
        self.assertEqual(result, {"queue_id": "4AbCd67890", "message_id": "abc123@example.net"})

    def test_qmgr_size_enrichment(self):
        line = (
            "smtp-1  | 2026-09-17T11:08:01.000000000Z Sep 17 11:08:01 mail postfix/qmgr[121]: "
            "4AbCd67890: from=<sender@example.net>, size=4096, nrcpt=1 (queue active)"
        )
        self.assertEqual(parse(line), {"queue_id": "4AbCd67890", "message_size": 4096})

    # -- robustness ---------------------------------------------------------
    def test_malformed_lines_do_not_crash(self):
        for line in (
            "",
            "   ",
            "not a log line",
            "smtp-1  | garbage",
            "smtp-1  | 2026-09-17T11:11:01.000000000Z Sep 17 11:11:01 mail postfix/smtpd[150]: NOQUEUE: reject:",
            "smtp-1  | \x00\x01\x02 postfix/smtpd[1]: NOQUEUE: reject: RCPT from",
            "postfix/smtpd[1]:",
            "a" * 10000,
            "smtp-1  | 2026-99-99T99:99:99Z Sep 99 99:99:99 mail postfix/smtpd[1]: NOQUEUE: reject: RCPT from x[1.2.3.4]: 550",
        ):
            result = parse(line)
            self.assertTrue(
                result is None or isinstance(result, (Event, dict)),
                f"unexpected result for {line[:40]!r}: {result!r}",
            )

    def test_syslog_timestamp_without_docker_stamp(self):
        line = (
            "Sep 17 11:03:21 mail postfix/smtpd[111]: NOQUEUE: reject: RCPT from "
            "unknown[203.0.113.4]: 550 5.7.1 <user@example.com>: Recipient address rejected: "
            "Access denied; from=<sender@example.net> to=<user@example.com> proto=ESMTP"
        )
        event = parse(line)
        self.assertIsInstance(event, Event)
        self.assertEqual(event.occurred_at.hour, 11)
        self.assertEqual(event.occurred_at.minute, 3)

    def test_whole_fixture_file_parses_without_error(self):
        text = (FIXTURES / "smtp-inbound.log").read_text(encoding="utf-8")
        events = 0
        for line in text.splitlines():
            result = parse(line)
            if isinstance(result, Event):
                events += 1
        self.assertGreaterEqual(events, 5)


class TimestampNormalisationTests(MailutTestCase):
    """RFC 3339 shapes that older interpreters reject.

    Before Python 3.11, fromisoformat accepts only what isoformat produces:
    3 or 6 fractional digits and a colon in the offset. Docker's --timestamps
    emits nanoseconds, so these assertions are on the normalised *string*,
    which makes them fail on every interpreter if the rewrite is wrong rather
    than only on the old ones.
    """

    def test_nanoseconds_are_truncated_to_microseconds(self):
        self.assertEqual(
            normalize_iso("2026-09-17T11:03:21.123456789Z"),
            "2026-09-17T11:03:21.123456+00:00",
        )

    def test_short_fractions_are_padded(self):
        self.assertEqual(
            normalize_iso("2026-09-17T11:03:21.5Z"), "2026-09-17T11:03:21.500000+00:00"
        )

    def test_zulu_becomes_an_offset(self):
        self.assertEqual(normalize_iso("2026-09-17T11:03:21Z"), "2026-09-17T11:03:21+00:00")
        self.assertEqual(normalize_iso("2026-09-17T11:03:21z"), "2026-09-17T11:03:21+00:00")

    def test_compact_offsets_gain_a_colon(self):
        self.assertEqual(
            normalize_iso("2026-09-17T11:03:21+0200"), "2026-09-17T11:03:21+02:00"
        )
        self.assertEqual(
            normalize_iso("2026-09-17T11:03:21.000000000-0500"),
            "2026-09-17T11:03:21.000000-05:00",
        )

    def test_output_is_accepted_by_a_pre_3_11_parser(self):
        """Enforce the old contract even when running on a new interpreter.

        Python 3.11 relaxed fromisoformat to accept almost any RFC 3339 input,
        so a newer interpreter cannot notice a regression here on its own. This
        checks the normalised string against what 3.9/3.10 actually accept:
        what isoformat() emits.
        """
        import re

        strict = re.compile(
            r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{3}(\d{3})?)?)?"
            r"([+-]\d{2}:\d{2}(:\d{2}(\.\d{6})?)?)?$"
        )
        for value in (
            "2026-09-17T11:03:21.000000000Z",
            "2026-09-17T11:03:21.987654321Z",
            "2026-09-17T11:03:21.123456Z",
            "2026-09-17T11:03:21.123Z",
            "2026-09-17T11:03:21.5Z",
            "2026-09-17T11:03:21Z",
            "2026-09-17T13:03:21+0200",
            "2026-09-17T13:03:21.000000000+02:00",
        ):
            normalised = normalize_iso(value)
            self.assertRegex(normalised, strict, f"{value} -> {normalised}")

    def test_already_valid_stamps_are_unchanged(self):
        for value in ("2026-09-17T11:03:21+00:00", "2026-09-17T11:03:21.123456+00:00"):
            self.assertEqual(normalize_iso(value), value)

    def test_every_shape_round_trips_through_from_iso(self):
        for value in (
            "2026-09-17T11:03:21.000000000Z",
            "2026-09-17T11:03:21.123456789Z",
            "2026-09-17T11:03:21.5Z",
            "2026-09-17T11:03:21Z",
            "2026-09-17T13:03:21+0200",
            "2026-09-17T13:03:21.000000000+02:00",
        ):
            parsed = from_iso(value)
            self.assertEqual(parsed.year, 2026)
            self.assertEqual(parsed.hour, 11, value)

    def test_nanosecond_log_line_keeps_its_own_timestamp(self):
        """The regression: a bad parse silently stamped the event with 'now'."""
        line = (
            "smtp-1  | 2026-09-17T11:03:21.987654321Z Sep 17 11:03:21 mail "
            "postfix/smtpd[111]: NOQUEUE: reject: RCPT from unknown[203.0.113.4]: 550 5.7.1 "
            "<user@example.com>: Recipient address rejected: Access denied; "
            "from=<sender@example.net> to=<user@example.com> proto=ESMTP"
        )
        event = parse(line)
        self.assertEqual(
            event.occurred_at,
            datetime.datetime(2026, 9, 17, 11, 3, 21, tzinfo=datetime.timezone.utc),
        )
        # The failure mode was a silent fallback to utcnow(), which on the day
        # the fixture was written differs from the log stamp only by the clock.
        self.assertNotEqual(event.occurred_at, utcnow())
        self.assertGreater(abs((utcnow() - event.occurred_at).total_seconds()), 5)


class FixtureHygieneTests(MailutTestCase):
    """Committed fixtures must only use reserved domains and addresses."""

    def fixture_text(self):
        return "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted(FIXTURES.iterdir())
            if path.is_file()
        )

    def test_only_reserved_domains(self):
        import re

        text = self.fixture_text()
        # Look only where a hostname can actually appear, so scores and
        # filenames in subjects are not mistaken for domains.
        patterns = (
            r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            r"helo=<([^>]+)>",
            r"relay=([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            r"host ([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        )
        candidates = set()
        for pattern in patterns:
            candidates.update(match.rstrip(".>") for match in re.findall(pattern, text))

        # RFC 2606 reserves the .example TLD and example.com/.net/.org.
        allowed = re.compile(r"(^|\.)example$|(^|\.)example\.(com|net|org)$")
        offenders = sorted(name for name in candidates if not allowed.search(name))
        self.assertEqual(offenders, [], f"non-reserved domain(s) in fixtures: {offenders}")
        self.assertGreater(len(candidates), 3, "the domain scan matched nothing")

    def test_only_reserved_ip_addresses(self):
        import ipaddress
        import re

        # RFC 5737 documentation ranges, RFC 1918 private space and loopback.
        reserved = [
            ipaddress.ip_network(cidr)
            for cidr in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24",
                         "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                         "127.0.0.0/8", "0.0.0.0/32")
        ]
        offenders = []
        for candidate in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", self.fixture_text())):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(address in network for network in reserved):
                offenders.append(candidate)
        self.assertEqual(sorted(offenders), [], f"routable IP(s) in fixtures: {offenders}")
