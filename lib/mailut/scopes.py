"""Audit collection scopes.

Collection is opt-in.  A scope record says "collect (include) or do not collect
(exclude) mail addressed to this recipient set", where the set is one of

    all     every local recipient           (specificity 0)
    domain  every recipient at a domain     (specificity 1)
    email   one exact envelope recipient    (specificity 2)

Resolution rules (documented in mailut(8) and covered by the test suite):

  * the most specific applicable record wins;
  * at equal specificity, ``exclude`` wins;
  * when nothing matches, the recipient is not collected.

So ``add all`` + ``remove domain private.example.com`` collects every domain
except that one, and adding ``email monitored@private.example.com`` back brings
that single address into collection again.

``remove`` never deletes retained evidence — it only stops future collection.
"""

from __future__ import annotations

import sqlite3

from .util import MailutError, UsageError, domain_of, normalize_domain, normalize_email, to_iso, utcnow

SCOPE_TYPES = ("all", "domain", "email")
SPECIFICITY = {"all": 0, "domain": 1, "email": 2}
ALL_VALUE = "*"


class Scope:
    """One row of ``audit_scopes``."""

    __slots__ = (
        "id",
        "scope_type",
        "scope_value",
        "mode",
        "level",
        "retention_days",
        "message_retention_days",
        "created_at",
        "updated_at",
    )

    def __init__(self, row):
        for name in self.__slots__:
            setattr(self, name, row[name])

    @property
    def included(self) -> bool:
        return self.mode == "include"

    @property
    def specificity(self) -> int:
        return SPECIFICITY[self.scope_type]

    def label(self) -> str:
        return self.scope_value if self.scope_type != "all" else ALL_VALUE

    def as_dict(self) -> dict:
        return {name: getattr(self, name) for name in self.__slots__}


def normalize_target(scope_type: str, value: str | None) -> str:
    """Validate the operator-supplied scope target strictly."""
    if scope_type not in SCOPE_TYPES:
        raise UsageError(f"invalid scope type {scope_type!r}: expected all, domain or email")
    if scope_type == "all":
        if value not in (None, "", ALL_VALUE):
            raise UsageError("the 'all' scope takes no value")
        return ALL_VALUE
    if not value:
        raise UsageError(f"the '{scope_type}' scope requires a value")
    if scope_type == "domain":
        return normalize_domain(value)
    return normalize_email(value)


def list_scopes(conn: sqlite3.Connection) -> list[Scope]:
    rows = conn.execute(
        """
        SELECT * FROM audit_scopes
        ORDER BY CASE scope_type WHEN 'all' THEN 0 WHEN 'domain' THEN 1 ELSE 2 END,
                 scope_value
        """
    ).fetchall()
    return [Scope(row) for row in rows]


def get_scope(conn: sqlite3.Connection, scope_type: str, value: str) -> Scope | None:
    row = conn.execute(
        "SELECT * FROM audit_scopes WHERE scope_type = ? AND scope_value = ?",
        (scope_type, value),
    ).fetchone()
    return Scope(row) if row else None


def upsert_scope(
    conn: sqlite3.Connection,
    *,
    scope_type: str,
    value: str,
    mode: str,
    level: str,
    retention_days: int,
    message_retention_days: int | None,
) -> tuple[Scope, bool]:
    """Create or update one scope record.  Returns ``(scope, created)``."""
    if mode not in ("include", "exclude"):
        raise UsageError(f"invalid scope mode {mode!r}")
    now = to_iso(utcnow())
    existing = get_scope(conn, scope_type, value)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if existing is None:
            conn.execute(
                """
                INSERT INTO audit_scopes (scope_type, scope_value, mode, level,
                                          retention_days, message_retention_days,
                                          created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scope_type, value, mode, level, retention_days, message_retention_days, now, now),
            )
        else:
            conn.execute(
                """
                UPDATE audit_scopes
                   SET mode = ?, level = ?, retention_days = ?,
                       message_retention_days = ?, updated_at = ?
                 WHERE id = ?
                """,
                (mode, level, retention_days, message_retention_days, now, existing.id),
            )
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        conn.execute("ROLLBACK")
        raise MailutError(f"cannot store scope: {exc}") from exc
    scope = get_scope(conn, scope_type, value)
    assert scope is not None
    return scope, existing is None


def resolve(conn: sqlite3.Connection, recipient: str | None, *, local_domains=()) -> Scope | None:
    """Return the effective *including* scope for a recipient, or None.

    ``local_domains``, when configured, restricts the ``all`` scope to those
    domains so that outbound recipients are not swept in by it.

    A recipient of ``None`` happens for real evidence: a connection rejected
    before RCPT TO has no recipient to attribute.  Such an event is collected
    only when the ``all`` scope is including, since no narrower scope could
    ever be shown to apply.
    """
    if not recipient:
        row = conn.execute(
            "SELECT * FROM audit_scopes WHERE scope_type = 'all'"
        ).fetchone()
        if row is None:
            return None
        scope = Scope(row)
        return scope if scope.included else None
    address = recipient.strip().lower()
    domain = domain_of(address)

    candidates: list[Scope] = []
    rows = conn.execute(
        """
        SELECT * FROM audit_scopes
         WHERE (scope_type = 'email'  AND scope_value = ?)
            OR (scope_type = 'domain' AND scope_value = ?)
            OR  scope_type = 'all'
        """,
        (address, domain or ""),
    ).fetchall()
    for row in rows:
        scope = Scope(row)
        if scope.scope_type == "all" and local_domains and domain not in set(local_domains):
            continue
        candidates.append(scope)

    if not candidates:
        return None
    # Most specific wins; exclude beats include at equal specificity.
    candidates.sort(key=lambda s: (s.specificity, 0 if s.mode == "exclude" else 1), reverse=True)
    winner = candidates[0]
    return winner if winner.included else None


def describe_resolution(conn: sqlite3.Connection, recipient: str, *, local_domains=()) -> dict:
    """Explain why a recipient is or is not collected (used by `audit scopes`)."""
    scope = resolve(conn, recipient, local_domains=local_domains)
    return {
        "recipient": recipient,
        "collected": scope is not None,
        "scope": scope.as_dict() if scope else None,
    }
