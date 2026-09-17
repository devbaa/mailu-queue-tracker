"""Parse Mailu/Postfix SMTP log lines into audit events.

Rspamd never sees a connection that Postfix refused before DATA, so this is
where pre-DATA and policy evidence comes from.  Everything here is defensive:
a line that is not recognised, or is malformed, yields ``None`` rather than an
exception — a collector must never die on a log line.

Only *inbound* traffic is audited.  Lines carrying ``sasl_username=`` are
authenticated submission (a local account sending outwards) and are skipped,
as are deliveries over the outbound ``postfix/smtp`` transport; local delivery
to a mailbox goes over ``postfix/lmtp`` / ``virtual`` / ``local``.
"""

from __future__ import annotations

import datetime as _dt
import re

from ..events import Event
from ..util import UTC, utcnow

# `docker compose logs` prefixes each line with the service name, and with a
# timestamp when --timestamps is used.
_SERVICE_PREFIX = re.compile(r"^\s*[A-Za-z0-9_.\-]+\s*\|\s?")
_DOCKER_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+")
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+")
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+")
_COMPONENT = re.compile(r"postfix(?:/[a-z-]+)?/(?P<component>[a-z-]+)\[\d+\]:\s*(?P<rest>.*)$")

_REJECT = re.compile(
    r"^(?P<qid>NOQUEUE|[0-9A-Za-z]{6,20}):\s+"
    r"(?P<op>reject|reject_warning|milter-reject|discard|milter-discard|hold|warn):\s+"
    r"(?P<cmd>[A-Za-z-]+(?:\s+[A-Za-z-]+)?)\s+from\s+(?P<client>\S+?):\s*(?P<detail>.*)$"
)
_CLIENT_IP = re.compile(r"\[(?P<ip>[0-9a-fA-F:.]+)\]")
_CODE = re.compile(r"^(?P<code>[2-5]\d\d)\s+(?P<enh>\d\.\d\.\d)?\s*(?P<text>.*)$")
_ENH_ONLY = re.compile(r"^(?P<enh>\d\.\d\.\d)\s+(?P<text>.*)$")
_MESSAGE_ID = re.compile(r"^(?P<qid>[0-9A-Za-z]{6,20}):\s+message-id=<?(?P<mid>[^>\s]+)>?")
_QMGR = re.compile(r"^(?P<qid>[0-9A-Za-z]{6,20}):\s+from=<(?P<from>[^>]*)>,\s+size=(?P<size>\d+)")
_DELIVERY = re.compile(
    r"^(?P<qid>[0-9A-Za-z]{6,20}):\s+to=<(?P<to>[^>]*)>.*?status=(?P<status>[a-z]+)\b(?:\s+\((?P<text>.*)\))?"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_STAGE_BY_COMMAND = {
    "CONNECT": "connect",
    "EHLO": "helo",
    "HELO": "helo",
    "MAIL": "mail",
    "MAIL FROM": "mail",
    "RCPT": "rcpt",
    "DATA": "data",
    "BDAT": "data",
    "END-OF-MESSAGE": "data",
    "END-OF-DATA": "data",
    "VRFY": "unknown",
    "ETRN": "unknown",
    "UNKNOWN": "unknown",
}

# Postfix restriction wording.  A 5xx carrying one of these is the local policy
# refusing the mail, as opposed to a content/reputation rejection.
_POLICY_PHRASES = (
    "relay access denied",
    "access denied",
    "recipient address rejected",
    "sender address rejected",
    "client host rejected",
    "helo command rejected",
    "improper use of smtp command pipelining",
    "need fully-qualified",
    "unknown user",
    "user unknown",
    "domain not found",
    "service unavailable",
)
_VIRUS_PHRASES = ("virus", "malware", "infected", "clamav")
_GREYLIST_PHRASES = ("greylist", "greylisting", "try again later")

# Transports that deliver into a local mailbox (inbound), vs. the outbound relay.
_LOCAL_DELIVERY = ("lmtp", "virtual", "local", "pipe")


def _parse_timestamp(text: str, *, now: _dt.datetime | None = None) -> tuple[_dt.datetime | None, str]:
    """Pull the leading timestamp off a log line; returns (when, remainder)."""
    now = now or utcnow()
    match = _DOCKER_TS.match(text) or _ISO_TS.match(text)
    if match:
        raw = match.group(1).replace(" ", "T")
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = _dt.datetime.fromisoformat(raw)
        except ValueError:
            return None, text[match.end():]
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).replace(microsecond=0), text[match.end():]

    match = _SYSLOG_TS.match(text)
    if match:
        month = _MONTHS.get(match.group(1))
        if month is None:
            return None, text[match.end():]
        try:
            when = _dt.datetime(
                now.year, month, int(match.group(2)),
                int(match.group(3)), int(match.group(4)), int(match.group(5)),
                tzinfo=UTC,
            )
        except ValueError:
            return None, text[match.end():]
        # Syslog has no year: a timestamp far in the future is last year's.
        if when - now > _dt.timedelta(days=1):
            try:
                when = when.replace(year=now.year - 1)
            except ValueError:
                pass
        return when, text[match.end():]
    return None, text


def _strip_prefixes(line: str, *, now: _dt.datetime | None = None) -> tuple[_dt.datetime | None, str]:
    text = _SERVICE_PREFIX.sub("", line.rstrip("\n"), count=1)
    when, rest = _parse_timestamp(text, now=now)
    if when is not None:
        # A docker timestamp is usually followed by the container's own syslog
        # timestamp; drop that one and keep docker's (it has a year).
        _second, rest2 = _parse_timestamp(rest, now=now)
        if _second is not None:
            rest = rest2
        return when, rest
    # No leading timestamp: the syslog stamp may follow a hostname-less prefix.
    return None, rest


def _tail_fields(detail: str) -> dict:
    """Extract the ``from=<> to=<> proto= helo=`` trailer of a reject line."""
    fields: dict[str, str] = {}
    for key in ("from", "to", "helo", "proto", "sasl_username", "sasl_method"):
        match = re.search(rf"\b{key}=<([^>]*)>", detail)
        if match:
            fields[key] = match.group(1)
            continue
        match = re.search(rf"\b{key}=([^,;\s]+)", detail)
        if match:
            fields[key] = match.group(1)
    return fields


def _split_detail(detail: str) -> tuple[str | None, str | None, str]:
    """Split ``550 5.7.1 some reason; from=...`` into (code, enhanced, reason)."""
    head = detail.split(";", 1)[0].strip()
    match = _CODE.match(head)
    if match:
        return match.group("code"), match.group("enh"), match.group("text").strip()
    match = _ENH_ONLY.match(head)
    if match:
        return None, match.group("enh"), match.group("text").strip()
    return None, None, head


def _classify_reject(op: str, code: str | None, reason: str) -> str:
    lowered = (reason or "").lower()
    if op in ("discard", "milter-discard"):
        return "discard"
    if any(phrase in lowered for phrase in _GREYLIST_PHRASES):
        return "greylist"
    if code and code.startswith("4"):
        return "soft_reject"
    if any(phrase in lowered for phrase in _VIRUS_PHRASES):
        return "virus_reject"
    if op == "milter-reject":
        return "reject"
    if any(phrase in lowered for phrase in _POLICY_PHRASES):
        return "policy_reject"
    return "reject"


def parse_line(line: str, *, now: _dt.datetime | None = None) -> Event | dict | None:
    """Parse one log line.

    Returns an :class:`Event`, an enrichment dict (``{"queue_id", "message_id"}``
    or ``{"queue_id", "message_size"}``), or ``None`` when the line carries no
    audit evidence.  Never raises.
    """
    try:
        return _parse_line(line, now=now)
    except Exception:  # pragma: no cover - belt and braces for the daemon
        return None


def _parse_line(line: str, *, now: _dt.datetime | None = None) -> Event | dict | None:
    if not line or not line.strip():
        return None
    when, rest = _strip_prefixes(line, now=now)

    match = _COMPONENT.search(rest)
    if not match:
        return None
    component = match.group("component")
    body = match.group("rest").strip()
    occurred_at = when or utcnow()

    if component == "cleanup":
        found = _MESSAGE_ID.match(body)
        if found:
            return {"queue_id": found.group("qid"), "message_id": found.group("mid")}
        return None

    if component == "qmgr":
        found = _QMGR.match(body)
        if found:
            return {"queue_id": found.group("qid"), "message_size": int(found.group("size"))}
        return None

    if component in _LOCAL_DELIVERY:
        return _parse_delivery(body, occurred_at)

    if component == "smtpd":
        return _parse_smtpd(body, occurred_at)

    return None


def _parse_smtpd(body: str, occurred_at: _dt.datetime) -> Event | None:
    match = _REJECT.match(body)
    if not match:
        return None
    op = match.group("op")
    if op in ("hold", "warn", "reject_warning"):
        # Informational: the message was not refused.  Recording it as a
        # rejection would misrepresent what happened.
        return None

    detail = match.group("detail")
    fields = _tail_fields(detail)
    if fields.get("sasl_username"):
        return None  # authenticated submission: outbound, not inbound audit

    command = match.group("cmd").strip().upper()
    stage = _STAGE_BY_COMMAND.get(command, _STAGE_BY_COMMAND.get(command.split()[0], "unknown"))
    code, enhanced, reason = _split_detail(detail)
    action = _classify_reject(op, code, reason)

    client = match.group("client") or ""
    ip_match = _CLIENT_IP.search(client)
    remote_ip = ip_match.group("ip") if ip_match else None

    event = Event(
        occurred_at=occurred_at,
        source="postfix",
        stage=stage,
        action=action,
        envelope_from=fields.get("from") or None,
        envelope_to=fields.get("to") or None,
        queue_id=None if match.group("qid") == "NOQUEUE" else match.group("qid"),
        remote_ip=remote_ip,
        helo=fields.get("helo") or None,
        smtp_code=code,
        smtp_enhanced_code=enhanced,
        reason=reason or None,
    )
    return event.normalize()


def _parse_delivery(body: str, occurred_at: _dt.datetime) -> Event | None:
    match = _DELIVERY.match(body)
    if not match:
        return None
    status = match.group("status")
    action = {
        "sent": "deliver",
        "deferred": "soft_reject",
        "bounced": "reject",
        "expired": "reject",
    }.get(status)
    if action is None:
        return None
    text = (match.group("text") or "").strip()
    code = enhanced = None
    found = _CODE.match(text)
    if found:
        code, enhanced = found.group("code"), found.group("enh")
    event = Event(
        occurred_at=occurred_at,
        source="postfix",
        stage="delivery",
        action=action,
        envelope_to=match.group("to") or None,
        queue_id=match.group("qid"),
        smtp_code=code,
        smtp_enhanced_code=enhanced,
        reason=text or None,
    )
    return event.normalize()
