"""Rspamd's per-message log line -> events.

tests/fixtures/antispam.log was not captured from a live server. Every line
in it is constructed from Rspamd's own source: the default log_format string
in src/libserver/cfg_utils.cxx, the rendering of each variable in
src/libserver/task.c (scores as %.2f/%.2f, symbols as NAME(score){opt;},
recipients comma-joined and cut after log_task_max_elts with "..."), and the
logger prefix in src/libserver/logger/logger.c. Mailu sets
`logging { type = console; }` and does not override log_format, so these are
the lines `docker compose logs antispam` shows.
"""

import datetime as dt
import unittest

from helpers import FIXTURES

from mailut.ingest import rspamd

UTC = dt.timezone.utc


def _fixture():
    return (FIXTURES / "antispam.log").read_text(encoding="utf-8").splitlines()


def _line(marker):
    for line in _fixture():
        if marker in line:
            return line
    raise AssertionError(f"no fixture line contains {marker!r}")


def _one(marker):
    events = rspamd.parse_line(_line(marker))
    assert events, f"expected events for {marker!r}, got {events!r}"
    return events[0]


class FixtureTests(unittest.TestCase):
    def test_every_fixture_line_has_the_expected_outcome(self):
        """None = not a per-message line, [] = recognised but not audited."""
        outcomes = []
        for line in _fixture():
            result = rspamd.parse_line(line)
            outcomes.append(None if result is None else len(result))
        self.assertEqual(outcomes, [
            None,   # lua startup line
            None,   # main process line
            1,      # reject
            2,      # accept, two recipients
            1,      # greylist
            1,      # add header
            1,      # virus reject
            0,      # authenticated submission: skipped
            1,      # no Message-ID
            8,      # recipient list truncated by Rspamd
            1,      # severity-tagged prefix
            1,      # ANSI colour codes
            None,   # marker present, format not the default
            None,   # milter chatter
        ])


class FieldTests(unittest.TestCase):
    def test_reject(self):
        event = _one("spam-1@")
        self.assertEqual(event.source, "rspamd")
        self.assertEqual(event.stage, "data")
        self.assertEqual(event.action, "reject")
        self.assertEqual(event.rspamd_action, "reject")
        self.assertEqual(event.rspamd_score, 16.40)
        self.assertEqual(event.rspamd_required, 15.00)
        self.assertEqual(event.message_id, "spam-1@example.net")
        self.assertEqual(event.queue_id, "4SpAm00001")
        self.assertEqual(event.remote_ip, "203.0.113.4")
        self.assertEqual(event.envelope_from, "bulk@example.net")
        self.assertEqual(event.envelope_to, "user@example.com")
        self.assertEqual(event.message_size, 4096)

    def test_docker_timestamp_wins_over_rspamds_own(self):
        """Docker's has a zone and sub-second precision; Rspamd's is local time."""
        event = _one("spam-1@")
        self.assertEqual(event.occurred_at, dt.datetime(2026, 9, 17, 13, 2, 51, tzinfo=UTC))

    def test_rspamds_own_timestamp_is_used_without_dockers(self):
        line = _line("spam-1@").split(" | ", 1)[1].split(" ", 1)[1]  # strip service and docker stamp
        events = rspamd.parse_line(line)
        self.assertEqual(events[0].occurred_at, dt.datetime(2026, 9, 17, 13, 2, 51, tzinfo=UTC))

    def test_the_log_carries_no_content_so_none_is_recorded(self):
        for marker in ("spam-1@", "ham-1@", "junk-1@"):
            event = _one(marker)
            self.assertIsNone(event.subject)
            self.assertIsNone(event.header_from)
            self.assertIsNone(event.header_to)
            self.assertIsNone(event.headers_text)
            self.assertIsNone(event.raw_message)

    def test_missing_message_id_is_none_not_the_word_undef(self):
        event = _one("4NoMiD0001")
        self.assertIsNone(event.message_id)

    def test_null_sender_is_none(self):
        """A bounce has from: <>, which is not an address."""
        self.assertIsNone(_one("4NoMiD0001").envelope_from)


class ActionTests(unittest.TestCase):
    def test_action_mapping(self):
        for marker, action in (
            ("spam-1@", "reject"),
            ("ham-1@", "accept"),
            ("grey-1@", "greylist"),
            ("junk-1@", "junk"),
            ("sev-1@", "soft_reject"),
        ):
            self.assertEqual(_one(marker).action, action, marker)

    def test_virus_is_distinguished_from_plain_reject(self):
        self.assertEqual(_one("virus-1@").action, "virus_reject")

    def test_greylist_reason_is_recorded(self):
        self.assertEqual(_one("grey-1@").reason, "greylisting")


class SymbolTests(unittest.TestCase):
    def test_symbols_scores_and_options(self):
        symbols = {s["symbol"]: s for s in _one("spam-1@").symbols}
        self.assertEqual(set(symbols), {
            "BAYES_SPAM", "RBL_SPAMHAUS_SBL", "R_SPF_FAIL", "DMARC_POLICY_REJECT", "R_DKIM_REJECT",
        })
        self.assertEqual(symbols["BAYES_SPAM"]["score"], 5.10)
        self.assertEqual(symbols["BAYES_SPAM"]["options"], "99.98%")
        self.assertEqual(symbols["DMARC_POLICY_REJECT"]["options"], "example.net,reject")

    def test_empty_option_block(self):
        symbols = {s["symbol"]: s for s in _one("ham-1@").symbols}
        self.assertEqual(symbols["ARC_NA"]["score"], 0.0)
        self.assertIsNone(symbols["ARC_NA"]["options"])

    def test_options_may_contain_braces_and_commas(self):
        """Option values are free text -- URLs, dates -- and must not split symbols."""
        symbols = {s["symbol"]: s for s in _one("junk-1@").symbols}
        self.assertEqual(set(symbols), {"BAYES_SPAM", "URL_X", "HTML_SHORT_LINK_IMG_1"})
        self.assertEqual(symbols["URL_X"]["options"], "http://a.test/x?y={z},w")
        grey = {s["symbol"]: s for s in _one("grey-1@").symbols}
        self.assertIn("Thu, 17 Sep 2026", grey["GREYLIST"]["options"])

    def test_no_symbols(self):
        self.assertEqual(_one("colour-1@").symbols, [])

    def test_symbol_parser_never_raises(self):
        for text in ("", "(", "NAME(", "NAME(1.0", "NAME(x){", "NAME(1.0){a;", "{}", ",,,", "A(1){};B"):
            rspamd.parse_symbols(text)


class AuthenticationResultTests(unittest.TestCase):
    """Taken from the symbols Rspamd's own plugins define."""

    def test_spf_failure_is_recognised(self):
        """Regression: SPF failure is R_SPF_FAIL; R_SPF_REJECT does not exist."""
        self.assertEqual(_one("spam-1@").spf, "fail")

    def test_dkim_failure_is_recognised(self):
        self.assertEqual(_one("spam-1@").dkim, "fail")

    def test_dmarc(self):
        self.assertEqual(_one("spam-1@").dmarc, "fail")
        self.assertEqual(_one("ham-1@").dmarc, "pass")

    def test_passes(self):
        event = _one("ham-1@")
        self.assertEqual((event.spf, event.dkim), ("pass", "pass"))

    def test_spf_none(self):
        self.assertEqual(_one("4NoMiD0001").spf, "none")

    def test_no_symbols_no_result(self):
        event = _one("colour-1@")
        self.assertEqual((event.spf, event.dkim, event.dmarc), (None, None, None))


class RecipientTests(unittest.TestCase):
    def test_one_event_per_recipient(self):
        events = rspamd.parse_line(_line("ham-1@"))
        self.assertEqual([e.envelope_to for e in events], ["user@example.com", "second@example.com"])
        self.assertEqual({e.message_id for e in events}, {"ham-1@example.org"})

    def test_a_truncated_list_is_flagged_and_the_ellipsis_is_not_a_recipient(self):
        events = rspamd.parse_line(_line("many-1@"))
        self.assertEqual(len(events), 8)
        self.assertNotIn("...", [e.envelope_to for e in events])
        self.assertTrue(all("only the first recipients" in e.reason for e in events))

    def test_untruncated_events_carry_no_such_note(self):
        self.assertIsNone(_one("spam-1@").reason)

    def test_no_recipients_is_nothing_to_audit(self):
        line = _line("spam-1@").split(" rcpts: ")[0] + " "
        self.assertEqual(rspamd.parse_line(line), [])


class SkippedAndUnrecognisedTests(unittest.TestCase):
    def test_authenticated_submission_is_not_inbound_evidence(self):
        self.assertEqual(rspamd.parse_line(_line("out-1@")), [])

    def test_severity_prefix_and_colour_codes_are_handled(self):
        self.assertEqual(_one("sev-1@").message_id, "sev-1@example.net")
        self.assertEqual(_one("colour-1@").message_id, "colour-1@example.net")

    def test_other_lines_are_not_per_message_results(self):
        self.assertIsNone(rspamd.parse_line(_line("lua_cfg_transform")))
        self.assertIsNone(rspamd.parse_line(_line("rspamd_milter_process_command")))

    def test_a_customised_format_is_not_guessed_at(self):
        self.assertIsNone(rspamd.parse_line(_line("not the default format")))

    def test_garbage_never_raises(self):
        for text in (
            "", " ", "\x00\x01", "rspamd_task_write_log: ",
            "rspamd_task_write_log: id: <", "rspamd_task_write_log: id: <x>, (default: ",
            "rspamd_task_write_log: id: <x>, (default: T (reject): [1/2] [",
            "x" * 10000 + "rspamd_task_write_log: " + "(" * 5000,
        ):
            rspamd.parse_line(text)
