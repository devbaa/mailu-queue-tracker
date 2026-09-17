"""`mailut audit show` / `mailut audit stats` — querying retained evidence.

Results are streamed: the SQL is built with bound parameters only, rows are
fetched in batches, and JSON output is JSON Lines so an arbitrarily large
result set never has to fit in memory (here or in the consumer).
"""

from __future__ import annotations

import json
import sys

from .events import ACTIONS, PRE_DATA_STAGES, STAGES
from .util import (
    UsageError,
    normalize_domain,
    parse_since,
    parse_timepoint,
    sanitize,
    to_iso,
    truncate,
    try_normalize_email,
)

BATCH = 500

# Columns exposed in JSON output.  Adding a column is backwards compatible;
# removing or renaming one is not, so this list is deliberately explicit.
JSON_COLUMNS = (
    "id", "occurred_at", "received_at", "source", "stage", "action",
    "envelope_from", "envelope_to", "header_from", "header_to", "subject",
    "message_id", "queue_id", "session_id", "remote_ip", "helo",
    "smtp_code", "smtp_enhanced_code", "reason",
    "rspamd_score", "rspamd_required", "rspamd_action",
    "spf", "dkim", "dmarc", "message_size", "level", "expires_at",
)


def build_filters(args) -> tuple[str, list]:
    """Translate the CLI filters into a WHERE clause and bound parameters."""
    clauses: list[str] = []
    params: list = []

    if getattr(args, "since", None):
        clauses.append("e.occurred_at >= ?")
        params.append(to_iso(parse_since(args.since)))
    if getattr(args, "after", None):
        clauses.append("e.occurred_at >= ?")
        params.append(to_iso(parse_timepoint(args.after)))
    if getattr(args, "before", None):
        clauses.append("e.occurred_at < ?")
        params.append(to_iso(parse_timepoint(args.before)))
    if getattr(args, "domain", None):
        clauses.append("e.envelope_to_domain = ?")
        params.append(normalize_domain(args.domain))
    if getattr(args, "recipient", None):
        clauses.append("e.envelope_to = ?")
        params.append(try_normalize_email(args.recipient))
    if getattr(args, "sender", None):
        clauses.append("e.envelope_from = ?")
        params.append(try_normalize_email(args.sender))
    if getattr(args, "sender_domain", None):
        clauses.append("e.envelope_from_domain = ?")
        params.append(normalize_domain(args.sender_domain))
    if getattr(args, "action", None):
        for action in args.action:
            if action not in ACTIONS:
                raise UsageError(f"unknown action {action!r}: expected one of {', '.join(ACTIONS)}")
        placeholders = ", ".join("?" for _ in args.action)
        clauses.append(f"e.action IN ({placeholders})")
        params.extend(args.action)
    if getattr(args, "stage", None):
        for stage in args.stage:
            if stage not in STAGES:
                raise UsageError(f"unknown stage {stage!r}: expected one of {', '.join(STAGES)}")
        placeholders = ", ".join("?" for _ in args.stage)
        clauses.append(f"e.stage IN ({placeholders})")
        params.extend(args.stage)
    if getattr(args, "queue_id", None):
        clauses.append("e.queue_id = ?")
        params.append(args.queue_id)
    if getattr(args, "message_id", None):
        clauses.append("e.message_id = ?")
        params.append(args.message_id.strip("<>"))
    if getattr(args, "ip", None):
        clauses.append("e.remote_ip = ?")
        params.append(args.ip)
    if getattr(args, "symbol", None):
        clauses.append("EXISTS (SELECT 1 FROM audit_symbols s WHERE s.event_id = e.id AND s.symbol = ?)")
        params.append(args.symbol.upper())

    where = " AND ".join(clauses) if clauses else "1"
    return where, params


def iter_events(conn, where: str, params: list, *, limit: int | None, order: str = "DESC"):
    """Yield matching event rows in batches, honouring an optional limit."""
    sql = f"SELECT e.* FROM audit_events e WHERE {where} ORDER BY e.occurred_at {order}, e.id {order}"
    cursor = conn.execute(sql, params)
    yielded = 0
    while True:
        rows = cursor.fetchmany(BATCH)
        if not rows:
            break
        for row in rows:
            yield row
            yielded += 1
            if limit is not None and yielded >= limit:
                cursor.close()
                return


def symbols_for(conn, event_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT symbol, score, options FROM audit_symbols WHERE event_id = ? ORDER BY symbol",
        (event_id,),
    ).fetchall()
    return [{"symbol": r["symbol"], "score": r["score"], "options": r["options"]} for r in rows]


def payload_kinds(conn, event_id: int) -> list[str]:
    rows = conn.execute(
        "SELECT kind FROM audit_payloads WHERE event_id = ? ORDER BY kind", (event_id,)
    ).fetchall()
    return [r["kind"] for r in rows]


def _unavailable(row) -> str:
    """Say plainly why a field cannot exist, instead of inventing one."""
    if row["stage"] in PRE_DATA_STAGES:
        return "unavailable (rejected before DATA)"
    return "unavailable"


def format_event(row, symbols, payloads=()) -> str:
    """One event, rendered for an administrator."""
    lines = [f"{row['occurred_at']}  {row['action']}"]

    def field(label, value, fallback="-"):
        lines.append(f"  {label + ':':<10}{sanitize(value, fallback)}")

    field("stage", row["stage"])
    # A null envelope sender is indistinguishable from one that was never
    # recorded (a delivery line carries no sender), so do not print "<>" and
    # imply a null-sender bounce that may not have happened.
    field("from", row["envelope_from"], "unavailable")
    field("to", row["envelope_to"], "unavailable (no recipient reached)")
    if row["remote_ip"]:
        field("ip", row["remote_ip"])
    if row["helo"]:
        field("helo", row["helo"])
    if row["subject"] is not None:
        field("subject", truncate(sanitize(row["subject"]), 120))
    else:
        field("subject", _unavailable(row))
    if row["message_id"]:
        field("msg-id", truncate(sanitize(row["message_id"]), 120))
    if row["queue_id"]:
        field("queue-id", row["queue_id"])
    if row["smtp_code"] or row["smtp_enhanced_code"]:
        field("smtp", " ".join(x for x in (row["smtp_code"], row["smtp_enhanced_code"]) if x))
    if row["rspamd_score"] is not None:
        required = row["rspamd_required"]
        score = f"{row['rspamd_score']:.2f}" + (f" / {required:.2f}" if required is not None else "")
        if row["rspamd_action"]:
            score += f" ({row['rspamd_action']})"
        field("rspamd", score)
    if row["reason"]:
        field("reason", truncate(sanitize(row["reason"]), 160))
    for label in ("spf", "dkim", "dmarc"):
        if row[label]:
            field(label, row[label])
    if row["message_size"] is not None:
        field("size", str(row["message_size"]))
    if symbols:
        rendered = ", ".join(
            f"{sanitize(s['symbol'])}" + (f"({s['score']:+.2f})" if s["score"] is not None else "")
            for s in symbols[:12]
        )
        if len(symbols) > 12:
            rendered += f", +{len(symbols) - 12} more"
        field("symbols", rendered)
    if payloads:
        # Never dump a retained body into ordinary output: only say it exists.
        field("stored", ", ".join(payloads))
    field("expires", row["expires_at"])
    return "\n".join(lines)


def cmd_show(args, config, conn) -> int:
    where, params = build_filters(args)
    limit = args.limit if args.limit and args.limit > 0 else None

    count = 0
    for row in iter_events(conn, where, params, limit=limit):
        count += 1
        if args.json:
            record = {key: row[key] for key in JSON_COLUMNS}
            record["symbols"] = symbols_for(conn, row["id"])
            record["payloads"] = payload_kinds(conn, row["id"])
            record["subject_available"] = row["stage"] not in PRE_DATA_STAGES
            sys.stdout.write(json.dumps(record, sort_keys=True) + "\n")
        else:
            if count > 1:
                print()
            print(format_event(row, symbols_for(conn, row["id"]), payload_kinds(conn, row["id"])))

    if not args.json and count == 0:
        # Wording matters here: absence of a record is not proof of absence of
        # a message.  Never claim the sender did not send it.
        print("No matching SMTP activity was recorded during the retained period.")
        print(
            "This means this server holds no matching retained observation; "
            "it does not establish what the sending system did."
        )
    elif not args.json:
        print(f"\n{count} event(s).")
    return 0


def cmd_stats(args, config, conn) -> int:
    where, params = build_filters(args)

    by_action = conn.execute(
        f"SELECT e.action AS action, COUNT(*) AS n FROM audit_events e WHERE {where} GROUP BY e.action",
        params,
    ).fetchall()
    by_stage = conn.execute(
        f"SELECT e.stage AS stage, COUNT(*) AS n FROM audit_events e WHERE {where} GROUP BY e.stage",
        params,
    ).fetchall()
    span = conn.execute(
        f"SELECT COUNT(*) AS n, MIN(e.occurred_at) AS oldest, MAX(e.occurred_at) AS newest, "
        f"MIN(e.expires_at) AS next_expiry FROM audit_events e WHERE {where}",
        params,
    ).fetchone()
    payloads = conn.execute(
        f"""
        SELECT p.kind AS kind, COUNT(*) AS n, COALESCE(SUM(p.stored_bytes), 0) AS bytes
          FROM audit_payloads p
         WHERE p.event_id IN (SELECT e.id FROM audit_events e WHERE {where})
         GROUP BY p.kind
        """,
        params,
    ).fetchall()
    top_symbols = conn.execute(
        f"""
        SELECT s.symbol AS symbol, COUNT(*) AS n
          FROM audit_symbols s
         WHERE s.event_id IN (SELECT e.id FROM audit_events e WHERE {where})
         GROUP BY s.symbol ORDER BY n DESC LIMIT 10
        """,
        params,
    ).fetchall()

    actions = {row["action"]: row["n"] for row in by_action}
    stages = {row["stage"]: row["n"] for row in by_stage}
    pre_data = sum(stages.get(stage, 0) for stage in PRE_DATA_STAGES)

    from .db import Database  # local import: keeps this module importable alone
    from . import payloads as payload_store

    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    stats = {
        "events": span["n"] or 0,
        "oldest": span["oldest"],
        "newest": span["newest"],
        "next_expiration": span["next_expiry"],
        "by_action": actions,
        "by_stage": stages,
        "pre_data_rejected": pre_data,
        "payloads": {row["kind"]: {"count": row["n"], "bytes": row["bytes"]} for row in payloads},
        "database_bytes": database.size_bytes(),
        "message_storage_bytes": payload_store.storage_bytes(config.message_dir),
        "top_symbols": [{"symbol": r["symbol"], "count": r["n"]} for r in top_symbols],
    }

    if args.json:
        json.dump(stats, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    from .util import human_bytes

    print(f"Events:              {stats['events']}")
    for action in ACTIONS:
        if actions.get(action):
            print(f"  {action:<18} {actions[action]}")
    print(f"Pre-DATA rejected:   {pre_data}")
    print()
    print(f"Oldest record:       {stats['oldest'] or '-'}")
    print(f"Newest record:       {stats['newest'] or '-'}")
    print(f"Next expiration:     {stats['next_expiration'] or '-'}")
    print()
    print(f"Database size:       {human_bytes(stats['database_bytes'])}")
    print(f"Message storage:     {human_bytes(stats['message_storage_bytes'])}")
    for kind, info in sorted(stats["payloads"].items()):
        print(f"  {kind:<18} {info['count']} ({human_bytes(info['bytes'])})")
    if top_symbols:
        print()
        print("Top Rspamd symbols:")
        for row in top_symbols:
            print(f"  {sanitize(row['symbol']):<30} {row['n']}")
    print()
    print(
        "Counts are per observed event; one message can produce several events "
        "(for example greylist, then accept, then deliver)."
    )
    return 0
