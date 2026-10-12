"""Parse Rspamd's per-message log line into audit events.

Rspamd writes one line per scanned message, from ``rspamd_task_write_log``.
Mailu runs Rspamd with ``logging { type = console; }`` and the default
``log_format``, so that line reaches ``docker compose logs antispam`` and looks
like this (wrapped here; it is one line)::

    2026-09-17 13:02:51 #42(normal) <8a3f2c>; task; rspamd_task_write_log:
      id: <abc@example.net>, qid: <4AbCd67890>, ip: 203.0.113.4,
      from: <sender@example.net>, (default: T (reject): [16.40/15.00]
      [BAYES_SPAM(5.10){99.98%;},R_SPF_FAIL(1.00){-all;}]), len: 4096,
      time: 120.5ms, dns req: 12, digest: <0123...>, rcpts: <user@example.com>,

The default format, and how each field in it is rendered, is taken from the
Rspamd source (``cfg_utils.cxx`` sets the format; ``task.c`` renders it).
Reading the log means nothing has to listen on the network and nothing in
Mailu's configuration has to change.

What the line does not carry, and therefore what is never recorded from it: the
Subject, header From/To, the message headers and the message body.

Two properties of that format matter here:

* Optional fields are only present when known (``qid``, ``ip``, ``user``,
  ``from``, ``rcpts``), while ``id`` is always present and reads ``undef``
  when the message had no Message-ID.
* Rspamd truncates long lists at ``log_task_max_elts`` (7 by default) and
  appends ``...``.  A message to more recipients than that names only the
  first few in this line; the rest are still visible in the Postfix log.

One scanned message can have several recipients.  Each becomes its own event,
because scope, retention and "what happened to mail for this customer?" are
all per recipient.
"""

from __future__ import annotations

import datetime as _dt
import re

from ..events import Event, classify_rspamd
from ..util import utcnow
from .postfix import strip_prefixes

# The function that writes the per-message line.  Everything before it is the
# logger's prefix, whose shape depends on Rspamd's logging options (severity
# tag, process type, systemd mode), so it is skipped rather than parsed.
MARKER = "rspamd_task_write_log: "

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

_HEAD = re.compile(
    r"^id: <(?P<mid>.*?)>,"
    r"(?: qid: <(?P<qid>[^>]*)>,)?"
    r"(?: ip: (?P<ip>[^,\s]*),)?"
    r"(?: user: (?P<user>[^,]*),)?"
    r"(?: from: <(?P<from>[^>]*)>,)?"
    r"\s*$"
)
_RESULT = re.compile(
    r"^\(default: (?P<spam>[TFS]) \((?P<action>[^)]*)\): "
    r"\[(?P<score>[^/\]]*)/(?P<required>[^\]]*)\] \["
)
_LEN = re.compile(r"\blen: (?P<len>\d+)")
_RCPTS = re.compile(r"\brcpts: <(?P<rcpts>[^>]*)>")
_SYMBOL_NAME = re.compile(r"^[A-Za-z0-9_.\-]+$")

# Literal value Rspamd prints for a field it does not have.
_UNDEF = "undef"
_TRUNCATED = "..."


class IngestError(ValueError):
    """An input record could not be understood."""


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _known(value):
    """None for an absent field or Rspamd's ``undef`` placeholder."""
    if value is None:
        return None
    value = value.strip()
    return None if value in ("", _UNDEF) else value


def _options_end(text: str, start: int) -> int:
    """Index of the ``}`` closing the option block that opens at ``start``.

    Each option is written as ``value;`` and the block as ``{...}``, so the
    closing brace is one that follows a ``;`` (or opens-and-closes an empty
    block) and is itself followed by ``,`` or the end.  That tolerates braces
    and commas inside option values, which are free text such as URLs.
    """
    n = len(text)
    p = start + 1
    while p < n:
        if text[p] == "}" and (p == start + 1 or text[p - 1] == ";") and (p + 1 == n or text[p + 1] == ","):
            return p
        p += 1
    return n - 1


def parse_symbols(text: str) -> list[dict]:
    """Parse ``NAME(score){opt;opt;},NAME(score){}`` into symbol dicts.

    Never raises: whatever can be read before something unexpected is returned.
    """
    out: list[dict] = []
    i, n = 0, len(text)
    while i < n:
        paren = text.find("(", i)
        if paren < 0:
            break
        name = text[i:paren].strip()
        if not _SYMBOL_NAME.match(name):
            break
        close = text.find(")", paren)
        if close < 0:
            break
        score = _as_float(text[paren + 1:close])
        i = close + 1
        options = None
        if i < n and text[i] == "{":
            end = _options_end(text, i)
            values = [value for value in text[i + 1:end].split(";") if value]
            options = ",".join(values) if values else None
            i = end + 1
        if i < n and text[i] == ",":
            i += 1
        out.append({"symbol": name, "score": score, "options": options})
    return out


# Symbol names as Rspamd's own plugins define them (spf.lua, dkim_check.c,
# dmarc.lua).  The two mechanisms do not name failure the same way: SPF says
# FAIL, DKIM says REJECT.
_AUTH_SYMBOLS = {
    "spf": (
        ("R_SPF_ALLOW", "pass"),
        ("R_SPF_FAIL", "fail"),
        ("R_SPF_SOFTFAIL", "softfail"),
        ("R_SPF_NEUTRAL", "neutral"),
        ("R_SPF_NA", "none"),
        ("R_SPF_PERMFAIL", "permerror"),
        ("R_SPF_DNSFAIL", "temperror"),
    ),
    "dkim": (
        ("R_DKIM_ALLOW", "pass"),
        ("R_DKIM_REJECT", "fail"),
        ("R_DKIM_NA", "none"),
        ("R_DKIM_PERMFAIL", "permerror"),
        ("R_DKIM_TEMPFAIL", "temperror"),
    ),
    "dmarc": (
        ("DMARC_POLICY_ALLOW", "pass"),
        ("DMARC_POLICY_REJECT", "fail"),
        ("DMARC_POLICY_QUARANTINE", "quarantine"),
        ("DMARC_POLICY_SOFTFAIL", "softfail"),
        ("DMARC_NA", "none"),
        ("DMARC_BAD_POLICY", "permerror"),
        ("DMARC_DNSFAIL", "temperror"),
    ),
}


def _auth_result(symbols: list[dict], name: str) -> str | None:
    """SPF/DKIM/DMARC result, inferred from the symbols Rspamd fired."""
    names = {str(s.get("symbol") or "").upper() for s in symbols}
    for symbol, result in _AUTH_SYMBOLS[name]:
        if symbol in names:
            return result
    return None


def parse_line(line: str, *, now: _dt.datetime | None = None) -> list[Event] | None:
    """Parse one antispam log line.

    Returns ``None`` when the line is not Rspamd's per-message line (most lines
    are not), ``[]`` when it is but carries nothing to audit (authenticated
    submission, or no recipient), and otherwise one event per recipient.
    Never raises.
    """
    try:
        return _parse_line(line, now=now)
    except Exception:  # pragma: no cover - belt and braces for the daemon
        return None


def _parse_line(line: str, *, now: _dt.datetime | None = None) -> list[Event] | None:
    if not line or MARKER not in line:
        return None
    line = _ANSI.sub("", line)
    when, _rest = strip_prefixes(line, now=now)
    body = line[line.index(MARKER) + len(MARKER):].rstrip()

    split = body.find(" (default: ")
    if split < 0:
        return None
    head = _HEAD.match(body[:split])
    result_text = body[split + 1:]
    result = _RESULT.match(result_text)
    if not head or not result:
        return None

    # The symbol list is free text and can contain anything, so find its end
    # from the right: nothing after it (lengths, timings, addresses) can
    # contain "]), len: ".
    symbols_end = result_text.rfind("]), len: ")
    if symbols_end < result.end():
        return None
    symbols = parse_symbols(result_text[result.end():symbols_end])
    tail = result_text[symbols_end + 3:]

    # Authenticated submission is a local account sending outwards, which is
    # not inbound evidence; the Postfix side skips it the same way.
    if _known(head.group("user")):
        return []

    recipients: list[str] = []
    truncated = False
    found = _RCPTS.search(tail)
    if found:
        for part in found.group("rcpts").split(","):
            part = part.strip()
            if part == _TRUNCATED or part.endswith(_TRUNCATED):
                truncated = True
                part = part[: -len(_TRUNCATED)].strip()
            if part:
                recipients.append(part)
    if not recipients:
        return []

    action = result.group("action").strip()
    classified = classify_rspamd(action, symbols)
    size = _LEN.search(tail)

    reasons = []
    if classified == "greylist":
        reasons.append("greylisting")
    if truncated:
        reasons.append("Rspamd's log listed only the first recipients; the rest are not attributed here")
    reason = "; ".join(reasons) or None

    events: list[Event] = []
    for recipient in recipients:
        event = Event(
            occurred_at=when or now or utcnow(),
            source="rspamd",
            stage="data",  # Rspamd scans the message after DATA, as a milter
            action=classified,
            envelope_from=_known(head.group("from")),
            envelope_to=recipient,
            message_id=_known(head.group("mid")),
            queue_id=_known(head.group("qid")),
            remote_ip=_known(head.group("ip")),
            reason=reason,
            rspamd_score=_as_float(result.group("score")),
            rspamd_required=_as_float(result.group("required")),
            rspamd_action=action.lower() or None,
            spf=_auth_result(symbols, "spf"),
            dkim=_auth_result(symbols, "dkim"),
            dmarc=_auth_result(symbols, "dmarc"),
            message_size=int(size.group("len")) if size else None,
            symbols=symbols,
        )
        events.append(event.normalize())
    return events
