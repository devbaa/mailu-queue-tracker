"""Parse an Rspamd metadata-exporter payload into audit events.

The recommended exporter configuration is shipped in
``<datadir>/rspamd/mailut-exporter.conf``; it posts one JSON object per scanned
message to the local collector.  The parser deliberately accepts a range of
key spellings so that a hand-rolled exporter, or a future Rspamd default
formatter, keeps working.

One scanned message can have several recipients.  Each recipient becomes its
own event, because scope, retention and the answer to "what happened to mail
for this customer?" are all per recipient.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt

from ..events import Event, classify_rspamd
from ..util import UTC, from_iso, utcnow


class IngestError(ValueError):
    """The payload could not be understood (the collector answers 400)."""


def _first(data: dict, *keys, default=None):
    for key in keys:
        if key in data and data[key] not in (None, "", []):
            return data[key]
    return default


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _timestamp(data: dict) -> _dt.datetime:
    raw = _first(data, "occurred_at", "timestamp", "time", "unix_time", "scan_time")
    if raw is None:
        return utcnow()
    if isinstance(raw, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(raw), tz=UTC).replace(microsecond=0)
        except (OverflowError, OSError, ValueError):
            return utcnow()
    try:
        return from_iso(str(raw))
    except Exception:
        return utcnow()


def _recipients(data: dict) -> list[str]:
    raw = _first(data, "rcpt", "recipients", "rcpt_smtp", "envelope_to", "to", default=[])
    if isinstance(raw, str):
        items = [part.strip() for part in raw.replace(";", ",").split(",")]
    elif isinstance(raw, (list, tuple)):
        items = []
        for entry in raw:
            if isinstance(entry, dict):
                value = entry.get("addr") or entry.get("address") or entry.get("user")
                if value:
                    items.append(str(value))
            elif entry:
                items.append(str(entry))
    else:
        items = []
    return [item for item in (i.strip() for i in items) if item]


def _sender(data: dict) -> str | None:
    raw = _first(data, "from", "sender", "envelope_from", "from_smtp")
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if isinstance(raw, dict):
        raw = raw.get("addr") or raw.get("address")
    return str(raw) if raw else None


def _symbols(data: dict) -> list[dict]:
    raw = _first(data, "symbols", default=None)
    out: list[dict] = []
    if isinstance(raw, dict):
        for name, entry in raw.items():
            if isinstance(entry, dict):
                out.append(
                    {
                        "symbol": entry.get("name") or name,
                        "score": entry.get("score"),
                        "options": entry.get("options"),
                    }
                )
            else:
                out.append({"symbol": name, "score": _as_float(entry), "options": None})
    elif isinstance(raw, (list, tuple)):
        for entry in raw:
            if isinstance(entry, dict):
                out.append(
                    {
                        "symbol": entry.get("symbol") or entry.get("name"),
                        "score": entry.get("score"),
                        "options": entry.get("options"),
                    }
                )
            elif entry:
                out.append({"symbol": str(entry), "score": None, "options": None})
    return [s for s in out if s.get("symbol")]


def _auth_result(data: dict, name: str) -> str | None:
    """Pull an SPF/DKIM/DMARC result from an explicit key or from symbols."""
    explicit = _first(data, name, name.upper(), f"{name}_result")
    if explicit:
        return str(explicit).lower()
    symbol_names = {str(s.get("symbol") or "").upper() for s in _symbols(data)}
    prefix = {"spf": "R_SPF_", "dkim": "R_DKIM_", "dmarc": "DMARC_"}[name]
    mapping = {
        f"{prefix}ALLOW": "pass",
        f"{prefix}REJECT": "fail",
        f"{prefix}SOFTFAIL": "softfail",
        f"{prefix}NEUTRAL": "neutral",
        f"{prefix}NA": "none",
        f"{prefix}PERMFAIL": "permerror",
        f"{prefix}TEMPFAIL": "temperror",
        "DMARC_POLICY_ALLOW": "pass",
        "DMARC_POLICY_REJECT": "fail",
        "DMARC_POLICY_QUARANTINE": "quarantine",
        "DMARC_POLICY_SOFTFAIL": "softfail",
        "DMARC_NA": "none",
    }
    for symbol, result in mapping.items():
        if name == "dmarc" and not symbol.startswith("DMARC"):
            continue
        if symbol in symbol_names:
            return result
    return None


def _decode_message(data: dict, limit: int) -> bytes | None:
    raw = _first(data, "message_b64", "message_base64", "raw_b64")
    if raw:
        try:
            decoded = base64.b64decode(str(raw), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise IngestError(f"message_b64 is not valid base64: {exc}") from exc
        return decoded[: limit + 1]
    raw = _first(data, "message", "raw_message")
    if raw:
        return str(raw).encode("utf-8", "replace")[: limit + 1]
    return None


def parse(data, *, message_limit: int = 26214400) -> list[Event]:
    """Turn one exporter payload into one event per recipient."""
    if not isinstance(data, dict):
        raise IngestError("expected a JSON object")

    action = _first(data, "action", "rspamd_action")
    symbols = _symbols(data)
    occurred_at = _timestamp(data)
    sender = _sender(data)
    recipients = _recipients(data) or [None]

    headers_text = _first(data, "headers", "header_text")
    if isinstance(headers_text, dict):
        headers_text = "\n".join(f"{k}: {v}" for k, v in headers_text.items())
    raw_message = _decode_message(data, message_limit)

    stage = str(_first(data, "stage", default="data") or "data").lower()
    classified = classify_rspamd(action, symbols)

    events: list[Event] = []
    for recipient in recipients:
        event = Event(
            occurred_at=occurred_at,
            source="rspamd",
            stage=stage,
            action=classified,
            envelope_from=sender,
            envelope_to=recipient,
            header_from=_first(data, "header_from", "from_header"),
            header_to=_first(data, "header_to", "to_header"),
            subject=_first(data, "subject"),
            message_id=_first(data, "message_id", "message-id", "msg_id"),
            queue_id=_first(data, "qid", "queue_id"),
            session_id=_first(data, "session_id", "session", "rspamd_session"),
            remote_ip=_first(data, "ip", "remote_ip", "client_ip"),
            helo=_first(data, "helo", "hostname"),
            smtp_code=_first(data, "smtp_code"),
            smtp_enhanced_code=_first(data, "smtp_enhanced_code", "dsn"),
            reason=_first(data, "reason", "message_reason", "subject_reason"),
            rspamd_score=_as_float(_first(data, "score", "rspamd_score")),
            rspamd_required=_as_float(_first(data, "required_score", "required", "rspamd_required_score")),
            rspamd_action=str(action).lower() if action else None,
            spf=_auth_result(data, "spf"),
            dkim=_auth_result(data, "dkim"),
            dmarc=_auth_result(data, "dmarc"),
            message_size=_as_int(_first(data, "size", "message_size", "len")),
            symbols=symbols,
            headers_text=str(headers_text) if headers_text else None,
            raw_message=raw_message,
        )
        if event.action == "greylist" and not event.reason:
            event.reason = "greylisting"
        events.append(event.normalize())
    return events
