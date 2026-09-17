"""The audit event model: classification, fingerprinting and storage."""

from __future__ import annotations

import datetime as _dt
import hashlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from . import payloads as payload_store
from . import scopes as scope_store
from .util import MailutError, domain_of, to_iso, try_normalize_email, utcnow

# Stable machine-readable outcomes.  These are what gets stored and what
# --action accepts; human wording is derived from them, never the reverse.
ACTIONS = (
    "accept",
    "deliver",
    "junk",
    "greylist",
    "soft_reject",
    "reject",
    "discard",
    "policy_reject",
    "virus_reject",
    "unknown",
)

# SMTP stages.  Anything before "data" means the sending server had not yet
# transmitted headers or a body, so Subject/Message-ID cannot exist.
STAGES = ("connect", "helo", "mail", "rcpt", "data", "queue", "delivery", "unknown")
PRE_DATA_STAGES = ("connect", "helo", "mail", "rcpt")

SOURCES = ("rspamd", "postfix", "manual")

# Rspamd's action is authoritative: it is affected by force_actions, settings
# and modules independently of the raw score, so never re-derive it from the
# score alone.
RSPAMD_ACTION_MAP = {
    "no action": "accept",
    "no_action": "accept",
    "add header": "junk",
    "add_header": "junk",
    "rewrite subject": "junk",
    "rewrite_subject": "junk",
    "greylist": "greylist",
    "soft reject": "soft_reject",
    "soft_reject": "soft_reject",
    "reject": "reject",
    "discard": "discard",
    "quarantine": "discard",
}

_VIRUS_HINTS = ("CLAMAV", "VIRUS", "MALWARE", "OLEFY")


@dataclass
class Event:
    """One observed decision, before it is bound to a scope and stored."""

    occurred_at: _dt.datetime
    source: str
    stage: str = "unknown"
    action: str = "unknown"
    envelope_from: str | None = None
    envelope_to: str | None = None
    header_from: str | None = None
    header_to: str | None = None
    subject: str | None = None
    message_id: str | None = None
    queue_id: str | None = None
    session_id: str | None = None
    remote_ip: str | None = None
    helo: str | None = None
    smtp_code: str | None = None
    smtp_enhanced_code: str | None = None
    reason: str | None = None
    rspamd_score: float | None = None
    rspamd_required: float | None = None
    rspamd_action: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    message_size: int | None = None
    symbols: list[dict] = field(default_factory=list)
    headers_text: str | None = None
    raw_message: bytes | None = None

    def normalize(self) -> "Event":
        """Clean up ingested values and enforce the pre-DATA invariant."""
        if self.source not in SOURCES:
            self.source = "manual"
        if self.stage not in STAGES:
            self.stage = "unknown"
        if self.action not in ACTIONS:
            self.action = "unknown"
        self.envelope_from = try_normalize_email(self.envelope_from)
        self.envelope_to = try_normalize_email(self.envelope_to)
        if self.occurred_at.tzinfo is None:
            self.occurred_at = self.occurred_at.replace(tzinfo=_dt.timezone.utc)
        self.occurred_at = self.occurred_at.replace(microsecond=0)
        # A message rejected before DATA was never transmitted: refuse to carry
        # a Subject, Message-ID, header addresses or a body for it, whatever
        # the ingested record claims.
        if self.stage in PRE_DATA_STAGES:
            self.subject = None
            self.message_id = None
            self.header_from = None
            self.header_to = None
            self.headers_text = None
            self.raw_message = None
        return self

    @property
    def pre_data(self) -> bool:
        return self.stage in PRE_DATA_STAGES

    def fingerprint(self) -> str:
        """A deterministic identity for de-duplication.

        Re-delivery of the same exporter request or a re-read of the same log
        line produces the same fingerprint and is ignored.  A genuine retry
        (a greylisted sender coming back five minutes later) has a different
        timestamp, so it stays a distinct event.
        """
        parts = [
            self.source,
            to_iso(self.occurred_at),
            self.stage,
            self.action,
            self.envelope_from or "",
            self.envelope_to or "",
            self.queue_id or "",
            self.message_id or "",
            self.remote_ip or "",
            self.smtp_code or "",
            self.session_id or "",
            (self.reason or "")[:200],
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def classify_rspamd(action: str | None, symbols=()) -> str:
    """Map an Rspamd action (plus symbol hints) to a stored action."""
    key = (action or "").strip().lower()
    mapped = RSPAMD_ACTION_MAP.get(key, "unknown")
    if mapped == "reject":
        for symbol in symbols:
            name = str(symbol.get("symbol") or symbol.get("name") or "").upper()
            if any(hint in name for hint in _VIRUS_HINTS):
                return "virus_reject"
    return mapped


class EventStore:
    """Binds events to scopes, applies retention and writes them to SQLite."""

    def __init__(self, conn: sqlite3.Connection, config):
        self.conn = conn
        self.config = config
        self.local_domains = config.local_domains

    # -- retention -----------------------------------------------------------
    def _expiry(self, occurred_at: _dt.datetime, days: int) -> str:
        return to_iso(occurred_at + _dt.timedelta(days=days))

    # -- storage -------------------------------------------------------------
    def store(self, event: Event) -> dict:
        """Store one event if its recipient is in scope.

        Returns a result dict with ``status`` in {stored, duplicate, out_of_scope}.
        Retention is resolved *now* and written into ``expires_at``: a later
        scope change affects future records only.
        """
        event.normalize()
        scope = scope_store.resolve(self.conn, event.envelope_to, local_domains=self.local_domains)
        if scope is None:
            return {"status": "out_of_scope", "recipient": event.envelope_to}

        if event.action in ("accept", "deliver") and not self.config.get("audit", "store_accepted"):
            return {"status": "out_of_scope", "recipient": event.envelope_to, "reason": "accepted events disabled"}

        # A scope cannot be *created* at a level the host forbids, but the host
        # configuration can be tightened afterwards. Collect at the reduced
        # level rather than dropping the evidence entirely -- and record the
        # reduced level on the event, so `audit show` reports what was actually
        # retained. `audit scopes` and `doctor` surface the discrepancy, so
        # this never passes unnoticed.
        level = scope.level
        if level == "headers" and not self.config.get("audit", "allow_headers"):
            level = "metadata"
        if level == "message" and not self.config.get("audit", "allow_messages"):
            level = "metadata"

        retention = scope.retention_days or self.config.get("audit", "default_retention_days")
        expires_at = self._expiry(event.occurred_at, retention)
        fingerprint = event.fingerprint()
        now = to_iso(utcnow())

        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cursor = self.conn.execute(
                """
                INSERT INTO audit_events (
                    fingerprint, occurred_at, received_at, source, stage, action,
                    envelope_from, envelope_from_domain, envelope_to, envelope_to_domain,
                    header_from, header_to, subject, message_id, queue_id, session_id,
                    remote_ip, helo, smtp_code, smtp_enhanced_code, reason,
                    rspamd_score, rspamd_required, rspamd_action, spf, dkim, dmarc,
                    message_size, level, scope_id, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (fingerprint) DO NOTHING
                """,
                (
                    fingerprint,
                    to_iso(event.occurred_at),
                    now,
                    event.source,
                    event.stage,
                    event.action,
                    event.envelope_from,
                    domain_of(event.envelope_from),
                    event.envelope_to,
                    domain_of(event.envelope_to),
                    event.header_from,
                    event.header_to,
                    event.subject,
                    event.message_id,
                    event.queue_id,
                    event.session_id,
                    event.remote_ip,
                    event.helo,
                    event.smtp_code,
                    event.smtp_enhanced_code,
                    event.reason,
                    event.rspamd_score,
                    event.rspamd_required,
                    event.rspamd_action,
                    event.spf,
                    event.dkim,
                    event.dmarc,
                    event.message_size,
                    level,
                    scope.id,
                    expires_at,
                ),
            )
            if cursor.rowcount == 0:
                self.conn.execute("COMMIT")
                return {"status": "duplicate", "fingerprint": fingerprint}
            event_id = cursor.lastrowid

            for symbol in event.symbols:
                name = str(symbol.get("symbol") or symbol.get("name") or "").strip()
                if not name:
                    continue
                score = symbol.get("score")
                options = symbol.get("options")
                if isinstance(options, (list, tuple)):
                    options = ",".join(str(o) for o in options)
                self.conn.execute(
                    "INSERT INTO audit_symbols (event_id, symbol, score, options) VALUES (?, ?, ?, ?)",
                    (
                        event_id,
                        name,
                        float(score) if isinstance(score, (int, float)) else None,
                        str(options) if options not in (None, "") else None,
                    ),
                )

            stored_payloads = self._store_payloads(event, event_id, level, expires_at, now)
            self.conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self.conn.execute("ROLLBACK")
            raise MailutError(f"cannot store audit event: {exc}") from exc
        except MailutError:
            self.conn.execute("ROLLBACK")
            raise

        return {
            "status": "stored",
            "id": event_id,
            "fingerprint": fingerprint,
            "level": level,
            "expires_at": expires_at,
            "payloads": stored_payloads,
        }

    def _store_payloads(self, event: Event, event_id: int, level: str, expires_at: str, now: str) -> list[str]:
        stored: list[str] = []
        if level == "metadata":
            return stored  # metadata mode never keeps headers or a body

        if event.headers_text and level in ("headers", "message"):
            text = event.headers_text
            self.conn.execute(
                """
                INSERT INTO audit_payloads (event_id, kind, content, stored_bytes,
                                            original_bytes, sha256, created_at, expires_at)
                VALUES (?, 'headers', ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    text,
                    len(text.encode("utf-8", "replace")),
                    len(text.encode("utf-8", "replace")),
                    hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
                    now,
                    expires_at,
                ),
            )
            stored.append("headers")

        if event.raw_message and level == "message":
            limit = self.config.get("audit", "message_max_bytes")
            if len(event.raw_message) > limit:
                # Oversized messages are not silently truncated: the metadata
                # is kept and the omission is recorded on the event.
                self.conn.execute(
                    "UPDATE audit_events SET reason = COALESCE(reason || ' | ', '') || ? WHERE id = ?",
                    (f"message payload not stored: {len(event.raw_message)} bytes exceeds message_max_bytes={limit}", event_id),
                )
                return stored
            scope_row = self.conn.execute(
                "SELECT message_retention_days FROM audit_events e "
                "LEFT JOIN audit_scopes s ON s.id = e.scope_id WHERE e.id = ?",
                (event_id,),
            ).fetchone()
            days = (scope_row["message_retention_days"] if scope_row else None) or self.config.get(
                "audit", "message_retention_days"
            )
            payload_expiry = self._expiry(event.occurred_at, days)
            meta = payload_store.store_message(
                Path(self.config.message_dir), event.occurred_at, event.raw_message
            )
            self.conn.execute(
                """
                INSERT INTO audit_payloads (event_id, kind, path, stored_bytes,
                                            original_bytes, sha256, created_at, expires_at)
                VALUES (?, 'message', ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    meta["path"],
                    meta["stored_bytes"],
                    meta["original_bytes"],
                    meta["sha256"],
                    now,
                    payload_expiry,
                ),
            )
            stored.append("message")
        return stored

    # -- enrichment ----------------------------------------------------------
    def attach_message_id(self, queue_id: str, message_id: str) -> int:
        """Fill in a Message-ID learned later from postfix/cleanup.

        Only events that do not already have one are touched, and only events
        that actually reached DATA (a pre-DATA reject never has one).
        """
        if not queue_id or not message_id:
            return 0
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cursor = self.conn.execute(
                """
                UPDATE audit_events SET message_id = ?
                 WHERE queue_id = ? AND message_id IS NULL
                   AND stage NOT IN ('connect', 'helo', 'mail', 'rcpt')
                """,
                (message_id, queue_id),
            )
            self.conn.execute("COMMIT")
        except sqlite3.Error:
            self.conn.execute("ROLLBACK")
            return 0
        return cursor.rowcount or 0
