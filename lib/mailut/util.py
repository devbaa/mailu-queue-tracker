"""Small shared helpers: errors, time handling, validation, safe output."""

from __future__ import annotations

import datetime as _dt
import re
import sys

# --- exit codes -------------------------------------------------------------
# Documented in mailut(8) under EXIT STATUS.  Keep the two in step.
EXIT_OK = 0
EXIT_FAILURE = 1  # operational / runtime failure
EXIT_USAGE = 2  # invalid command line
EXIT_ABORTED = 3  # the operator declined a destructive action
EXIT_CHECK_FAILED = 4  # a verification/doctor check failed
EXIT_LOCKED = 5  # another lifecycle operation holds the lock

UTC = _dt.timezone.utc


class MailutError(Exception):
    """An operational failure with a message fit for stderr (exit 1)."""

    exit_code = EXIT_FAILURE


class UsageError(MailutError):
    """Bad input from the command line (exit 2)."""

    exit_code = EXIT_USAGE


class AbortedError(MailutError):
    """The operator did not confirm a destructive action (exit 3)."""

    exit_code = EXIT_ABORTED


class LockedError(MailutError):
    """Another lifecycle operation is running (exit 5)."""

    exit_code = EXIT_LOCKED


# --- time -------------------------------------------------------------------

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=UTC).replace(microsecond=0)


def to_iso(when: _dt.datetime) -> str:
    """Render a datetime as the one timestamp format stored in the database."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).strftime(TS_FORMAT)


def from_iso(text: str) -> _dt.datetime:
    """Parse a timestamp written by :func:`to_iso` (tolerant of offsets)."""
    value = text.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise UsageError(f"not a timestamp: {text}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> _dt.timedelta:
    """Parse ``30m`` / ``6h`` / ``7d`` / ``2w`` into a timedelta."""
    match = _DURATION_RE.match(str(text).strip())
    if not match:
        raise UsageError(
            f"invalid duration {text!r}: expected a number followed by s, m, h, d or w (e.g. 24h)"
        )
    amount = int(match.group(1))
    return _dt.timedelta(seconds=amount * _DURATION_UNITS[match.group(2).lower()])


def parse_since(text: str, *, now: _dt.datetime | None = None) -> _dt.datetime:
    """Parse ``--since``: either a duration ago, or an absolute timestamp."""
    now = now or utcnow()
    value = str(text).strip()
    if _DURATION_RE.match(value):
        return now - parse_duration(value)
    return parse_timepoint(value)


def parse_timepoint(text: str) -> _dt.datetime:
    """Parse ``--before``/``--after``: ``YYYY-MM-DD`` or a full timestamp."""
    value = str(text).strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        day = _dt.date.fromisoformat(value)
        return _dt.datetime(day.year, day.month, day.day, tzinfo=UTC)
    return from_iso(value)


# --- address validation -----------------------------------------------------

# Deliberately strict: these values become database keys and are shown to
# operators.  Anything unusual is rejected rather than normalised into
# something surprising.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LOCALPART_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")


def normalize_domain(value: str) -> str:
    """Validate and lower-case a DNS domain (SMTP domains are case-insensitive)."""
    text = str(value).strip().rstrip(".").lower()
    if not text:
        raise UsageError("empty domain")
    if len(text) > 253:
        raise UsageError(f"domain too long: {value!r}")
    try:
        text = text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass  # fall through to the label check, which will reject it
    labels = text.split(".")
    if len(labels) < 2:
        raise UsageError(f"invalid domain {value!r}: expected at least one dot (example.com)")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise UsageError(f"invalid domain {value!r}: bad label {label!r}")
    return text


def normalize_email(value: str) -> str:
    """Validate an address and lower-case its domain.

    The local part keeps its case for display, but is compared
    case-insensitively everywhere (see :func:`match_key`), which is what
    practically every real mail system does.
    """
    text = str(value).strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    if not text or text.count("@") != 1:
        raise UsageError(f"invalid email address {value!r}: expected local@domain")
    local, _, domain = text.partition("@")
    if not local or len(local) > 64:
        raise UsageError(f"invalid email address {value!r}: bad local part")
    if not _LOCALPART_RE.match(local):
        raise UsageError(f"invalid email address {value!r}: bad local part")
    return f"{local.lower()}@{normalize_domain(domain)}"


def domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().lower() or None


def try_normalize_email(value: str | None) -> str | None:
    """Best-effort normalisation of an address seen in a log or an exporter.

    Ingested data is not operator input: a malformed address must be stored as
    seen rather than rejected, so evidence is never silently dropped.
    """
    if not value:
        return None
    text = str(value).strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    if not text:
        return None
    if text.count("@") == 1:
        local, _, domain = text.partition("@")
        return f"{local.lower()}@{domain.strip().rstrip('.').lower()}"
    return text.lower()


# --- safe human output ------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize(value, placeholder: str = "-") -> str:
    """Make an untrusted string safe to print on a terminal.

    Senders, subjects, HELO names and remote rejection text are all chosen by
    the remote side.  Terminal control sequences are escaped rather than
    emitted, and newlines are collapsed so one record stays on one line.
    """
    if value is None:
        return placeholder
    text = str(value)
    if text == "":
        return placeholder
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return _CONTROL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)), text)


def truncate(text: str, width: int) -> str:
    if width <= 1 or len(text) <= width:
        return text
    return text[: width - 1] + "…"


def human_bytes(count) -> str:
    try:
        size = float(count)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def confirm(prompt: str, *, assume_yes: bool = False, expect: str | None = None) -> bool:
    """Ask before doing something destructive.

    ``expect`` demands an exact word (used where retained mail evidence is
    about to be deleted) instead of a y/n that is easy to hit by accident.
    Without a terminal we never assume consent: the caller must pass --yes.
    """
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    if expect:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        try:
            answer = input()
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write("\n")
            return False
        return answer.strip() == expect
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        answer = input()
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write("\n")
        return False
    return answer.strip().lower() in ("y", "yes")


def columns(rows, headers):
    """Render a simple left-aligned column table (no decoration)."""
    widths = [len(h) for h in headers]
    body = []
    for row in rows:
        cells = [sanitize(c, "-") for c in row]
        body.append(cells)
        for i, cell in enumerate(cells):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    for cells in body:
        out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip())
    return "\n".join(out)
