"""`mailut audit purge` — deleting retained evidence.

Purging is the only thing that removes audit history.  Removing a *scope*
stops future collection and never deletes anything.

Deletion order matters: the payload file is removed first, then the database
rows.  If a file cannot be removed, its event is left intact and reported, so
the database never points at a file that is gone (or claims to have deleted
something that still exists on disk).  Re-running the purge picks up where it
left off, which makes ``--expired`` idempotent.
"""

from __future__ import annotations

import json
import sqlite3
import sys

from . import payloads as payload_store
from .util import (
    AbortedError,
    MailutError,
    UsageError,
    confirm,
    normalize_domain,
    parse_timepoint,
    sanitize,
    to_iso,
    try_normalize_email,
    utcnow,
)

BATCH = 500


def _selector(args) -> tuple[str, str, list, str]:
    """Return (name, event-where, params, description)."""
    chosen = [
        name
        for name, value in (
            ("expired", args.expired),
            ("all", args.all),
            ("domain", args.domain),
            ("email", args.email),
            ("before", args.before),
        )
        if value
    ]
    if len(chosen) != 1:
        raise UsageError(
            "choose exactly one of --expired, --all, --domain, --email or --before"
        )
    name = chosen[0]
    now = to_iso(utcnow())
    if name == "expired":
        return name, "expires_at <= ?", [now], f"records expired as of {now}"
    if name == "all":
        return name, "1", [], "every retained audit record"
    if name == "domain":
        value = normalize_domain(args.domain)
        return name, "envelope_to_domain = ?", [value], f"records for recipients at {value}"
    if name == "email":
        value = try_normalize_email(args.email)
        return name, "envelope_to = ?", [value], f"records for recipient {value}"
    value = to_iso(parse_timepoint(args.before))
    return name, "occurred_at < ?", [value], f"records older than {value}"


def preview(conn, where: str, params: list, *, expired_payloads: bool) -> dict:
    events = conn.execute(
        f"SELECT COUNT(*) AS n FROM audit_events WHERE {where}", params
    ).fetchone()["n"]
    payload_rows = conn.execute(
        f"SELECT COUNT(*) AS n, COALESCE(SUM(stored_bytes), 0) AS bytes FROM audit_payloads "
        f"WHERE event_id IN (SELECT id FROM audit_events WHERE {where})",
        params,
    ).fetchone()
    files = conn.execute(
        f"SELECT COUNT(*) AS n FROM audit_payloads "
        f"WHERE kind = 'message' AND event_id IN (SELECT id FROM audit_events WHERE {where})",
        params,
    ).fetchone()["n"]
    result = {
        "events": events,
        "payloads": payload_rows["n"],
        "payload_bytes": payload_rows["bytes"],
        "files": files,
        "expired_payloads": 0,
        "expired_payload_files": 0,
    }
    if expired_payloads:
        # Raw-message retention can be shorter than metadata retention: those
        # payloads go even though their event stays.
        row = conn.execute(
            """
            SELECT COUNT(*) AS n, SUM(kind = 'message') AS files
              FROM audit_payloads
             WHERE expires_at <= ? AND event_id NOT IN (SELECT id FROM audit_events WHERE expires_at <= ?)
            """,
            (to_iso(utcnow()), to_iso(utcnow())),
        ).fetchone()
        result["expired_payloads"] = row["n"] or 0
        result["expired_payload_files"] = row["files"] or 0
    return result


def _delete_payload_files(conn, ids: list[int], message_dir) -> tuple[int, list[str]]:
    """Unlink the message files of the given events.  Returns (deleted, errors)."""
    if not ids:
        return 0, []
    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT id, event_id, path FROM audit_payloads "
        f"WHERE kind = 'message' AND path IS NOT NULL AND event_id IN ({placeholders})",
        ids,
    ).fetchall()
    deleted = 0
    errors: list[str] = []
    failed_events: set[int] = set()
    for row in rows:
        try:
            payload_store.remove_file(row["path"], message_dir)
            deleted += 1
        except MailutError as exc:
            errors.append(str(exc))
            failed_events.add(row["event_id"])
    if failed_events:
        for event_id in failed_events:
            if event_id in ids:
                ids.remove(event_id)
    return deleted, errors


def run(conn, config, where: str, params: list, *, selector: str, limit_batches: int | None = None) -> dict:
    """Delete matching events and their payloads.  Returns a result summary."""
    message_dir = config.message_dir
    result = {"events": 0, "payloads": 0, "files": 0, "errors": []}

    started = to_iso(utcnow())
    cursor = conn.execute(
        "INSERT INTO purge_runs (started_at, selector) VALUES (?, ?)", (started, selector)
    )
    run_id = cursor.lastrowid

    batches = 0
    while True:
        rows = conn.execute(
            f"SELECT id FROM audit_events WHERE {where} ORDER BY id LIMIT {BATCH}", params
        ).fetchall()
        if not rows:
            break
        ids = [row["id"] for row in rows]
        files, errors = _delete_payload_files(conn, ids, message_dir)
        result["files"] += files
        result["errors"].extend(errors)
        if not ids:
            break  # every event in this batch failed; stop rather than spin
        placeholders = ", ".join("?" for _ in ids)
        try:
            conn.execute("BEGIN IMMEDIATE")
            payload_count = conn.execute(
                f"SELECT COUNT(*) AS n FROM audit_payloads WHERE event_id IN ({placeholders})", ids
            ).fetchone()["n"]
            conn.execute(f"DELETE FROM audit_events WHERE id IN ({placeholders})", ids)
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            conn.execute("ROLLBACK")
            raise MailutError(f"purge failed while deleting events: {exc}") from exc
        result["events"] += len(ids)
        result["payloads"] += payload_count
        batches += 1
        if limit_batches is not None and batches >= limit_batches:
            break
        if len(rows) < BATCH:
            break

    if selector == "expired":
        result_files, result_errors, payload_rows = _purge_expired_payloads(conn, message_dir)
        result["files"] += result_files
        result["payloads"] += payload_rows
        result["errors"].extend(result_errors)
        result["watch_samples"] = _purge_expired_samples(conn)

    payload_store.prune_empty_dirs(message_dir)

    conn.execute(
        "UPDATE purge_runs SET finished_at = ?, events = ?, payloads = ?, files = ?, errors = ? WHERE id = ?",
        (
            to_iso(utcnow()),
            result["events"],
            result["payloads"],
            result["files"],
            len(result["errors"]),
            run_id,
        ),
    )
    return result


def _purge_expired_payloads(conn, message_dir) -> tuple[int, list[str], int]:
    """Drop payloads whose own retention elapsed while their event lives on."""
    now = to_iso(utcnow())
    rows = conn.execute(
        "SELECT id, kind, path FROM audit_payloads WHERE expires_at <= ?", (now,)
    ).fetchall()
    deleted_files = 0
    removable: list[int] = []
    errors: list[str] = []
    for row in rows:
        if row["kind"] == "message" and row["path"]:
            try:
                payload_store.remove_file(row["path"], message_dir)
                deleted_files += 1
            except MailutError as exc:
                errors.append(str(exc))
                continue
        removable.append(row["id"])
    if removable:
        placeholders = ", ".join("?" for _ in removable)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"DELETE FROM audit_payloads WHERE id IN ({placeholders})", removable)
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            conn.execute("ROLLBACK")
            raise MailutError(f"purge failed while deleting payloads: {exc}") from exc
    return deleted_files, errors, len(removable)


def _purge_expired_samples(conn) -> int:
    now = to_iso(utcnow())
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute("DELETE FROM watch_samples WHERE expires_at <= ?", (now,))
        conn.execute("COMMIT")
    except sqlite3.Error:
        conn.execute("ROLLBACK")
        return 0
    return cursor.rowcount or 0


def cmd_purge(args, config, conn) -> int:
    selector, where, params, description = _selector(args)
    counts = preview(conn, where, params, expired_payloads=(selector == "expired"))

    total_events = counts["events"]
    total_files = counts["files"] + counts["expired_payload_files"]

    if args.json and args.dry_run:
        json.dump({"selector": selector, "dry_run": True, **counts}, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    print(f"Purge selector: {description}")
    print(f"  events:            {total_events}")
    print(f"  payload records:   {counts['payloads'] + counts['expired_payloads']}")
    print(f"  payload files:     {total_files}")

    if args.dry_run:
        print("(dry run: nothing deleted)")
        return 0

    if total_events == 0 and counts["expired_payloads"] == 0 and selector != "expired":
        print("Nothing to purge.")
        return 0

    if selector == "all":
        if not confirm(
            'This permanently deletes ALL retained audit evidence.\nType "purge" to continue: ',
            assume_yes=args.yes,
            expect="purge",
        ):
            raise AbortedError("aborted: nothing was deleted")
    elif selector != "expired" and not args.yes:
        if not confirm(f"Permanently delete {total_events} event(s)? [y/N] "):
            raise AbortedError("aborted: nothing was deleted")

    result = run(conn, config, where, params, selector=selector)
    if args.json:
        json.dump({"selector": selector, "dry_run": False, **result}, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"Deleted {result['events']} event(s), {result['payloads']} payload record(s), "
              f"{result['files']} file(s).")
        if "watch_samples" in result and result["watch_samples"]:
            print(f"Deleted {result['watch_samples']} expired watch sample(s).")
        for error in result["errors"][:10]:
            print(f"  error: {sanitize(error)}", file=sys.stderr)
    return 1 if result["errors"] else 0
