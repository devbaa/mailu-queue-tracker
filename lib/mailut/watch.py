"""`mailut watch` and `mailut report` — queue/abuse sampling.

``watch`` takes one sample of queue size, delivery outcomes and authenticated
sender volume, evaluates it against the thresholds in the configuration and
stores the sample in SQLite.  Output goes to stdout (journald under systemd);
no separate application log file is created.

Samples expire like audit records do, and `mailut audit purge --expired`
removes them.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import sqlite3
import sys

from . import queuecmd
from .db import Database
from .mailu import Mailu
from .util import columns, parse_duration, sanitize, to_iso, truncate, utcnow

SEVERITIES = {"ok": 0, "warning": 1, "critical": 2}

_RATELIMIT_RE = re.compile(
    r"too many|rate.?limit|sasl login name rejected|sender address rejected.*rate|recipient address rate",
    re.IGNORECASE,
)
_SPAM_RE = re.compile(
    r"spam|blacklist|blocklist|blocked|policy rejection|reputation|spamhaus|listed on|access denied|554 5\.7\.1",
    re.IGNORECASE,
)
_SASL_RE = re.compile(r"sasl_username=([^,\s]+)")


def _threshold(value: int, warn: int, crit: int, name: str, state: dict) -> None:
    if value > crit:
        _escalate("critical", f"{name}_gt_{crit}", state)
    elif value > warn:
        _escalate("warning", f"{name}_gt_{warn}", state)


def _escalate(severity: str, reason: str, state: dict) -> None:
    if SEVERITIES[severity] > SEVERITIES[state["severity"]]:
        state["severity"] = severity
    state["reasons"].append(reason)


def sample(config) -> dict:
    """Collect one sample and evaluate it against the configured thresholds."""
    window = config.get("watch", "window")
    parse_duration(window)  # validate early so a typo is a clear error

    queue = queuecmd.collect_metrics(config)
    mailu = Mailu(config)
    logs = mailu.logs(config.get("mailu", "smtp_service"), since=window)

    sent = bounced = deferred = rate_limits = spam_blocks = 0
    sasl: dict[str, int] = {}
    for line in logs.splitlines():
        if "status=sent" in line:
            sent += 1
        elif "status=bounced" in line:
            bounced += 1
        elif "status=deferred" in line:
            deferred += 1
        if _RATELIMIT_RE.search(line):
            rate_limits += 1
        if _SPAM_RE.search(line):
            spam_blocks += 1
        match = _SASL_RE.search(line)
        if match:
            user = match.group(1).lower()
            sasl[user] = sasl.get(user, 0) + 1

    attempts = sent + bounced + deferred
    rate = int((bounced + deferred) * 100 / attempts) if attempts else 0
    top_user, top_count = max(sasl.items(), key=lambda kv: kv[1]) if sasl else ("none", 0)
    bulk_threshold = config.get("watch", "bulk_sender_msgs")
    bulk_senders = sum(1 for count in sasl.values() if count >= bulk_threshold)

    state = {"severity": "ok", "reasons": []}
    _threshold(queue["total"], config.get("watch", "queue_warn"), config.get("watch", "queue_crit"), "queue_total", state)
    _threshold(queue["deferred"], config.get("watch", "deferred_warn"), config.get("watch", "deferred_crit"), "deferred_queue", state)
    _threshold(top_count, config.get("watch", "sender_sent_warn"), config.get("watch", "sender_sent_crit"), "sasl_sender_sent", state)
    _threshold(queue["top_sender_count"], config.get("watch", "sender_queue_warn"), config.get("watch", "sender_queue_crit"), "sender_queue_backlog", state)
    _threshold(queue["top_fanout_domains"], config.get("watch", "rcpt_domains_warn"), config.get("watch", "rcpt_domains_crit"), "rcpt_domain_fanout", state)
    _threshold(rate, config.get("watch", "bounce_defer_rate_warn"), config.get("watch", "bounce_defer_rate_crit"), "bounce_defer_rate_pct", state)
    _threshold(bulk_senders, config.get("watch", "multi_sender_warn"), config.get("watch", "multi_sender_crit"), "multiple_bulk_senders", state)
    if rate_limits > 0:
        _escalate("critical", "rate_limit_seen", state)
    if spam_blocks >= config.get("watch", "spam_block_crit"):
        _escalate("critical", f"spam_blacklist_blocks_ge_{config.get('watch', 'spam_block_crit')}", state)
    elif spam_blocks >= config.get("watch", "spam_block_warn"):
        _escalate("warning", "spam_blacklist_terms_seen", state)

    return {
        "occurred_at": to_iso(utcnow()),
        "severity": state["severity"],
        "reasons": ",".join(state["reasons"]) or "none",
        "window": window,
        "queue_total": queue["total"],
        "deferred_queue": queue["deferred"],
        "sent": sent,
        "bounced": bounced,
        "deferred": deferred,
        "bounce_defer_rate": rate,
        "rate_limits": rate_limits,
        "spam_blocks": spam_blocks,
        "top_sasl_user": top_user,
        "top_sasl_count": top_count,
        "bulk_senders": bulk_senders,
        "queue_top_sender": queue["top_sender"],
        "queue_top_sender_count": queue["top_sender_count"],
        "queue_top_domain_sender": queue["top_fanout_sender"],
        "queue_top_domain_count": queue["top_fanout_domains"],
        "queue_unique_domains": queue["unique_recipient_domains"],
        "queue_error": queue.get("error"),
    }


def metric_line(record: dict) -> str:
    keys = (
        "severity", "queue_total", "deferred_queue", "sent", "bounced", "deferred",
        "bounce_defer_rate", "rate_limits", "spam_blocks", "top_sasl_user",
        "top_sasl_count", "bulk_senders", "queue_top_sender", "queue_top_sender_count",
        "queue_top_domain_sender", "queue_top_domain_count", "queue_unique_domains",
    )
    parts = [f"time={record['occurred_at']}", f"window={record['window']}"]
    for key in keys:
        parts.append(f"{key}={sanitize(record[key], 'none').replace(' ', '_')}")
    parts.append(f"reasons={record['reasons']}")
    return " ".join(parts)


def cmd_watch(args, config) -> int:
    record = sample(config)
    if record["queue_error"]:
        print(f"warning: {sanitize(record['queue_error'])}", file=sys.stderr)

    if args.json:
        json.dump(record, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(metric_line(record))

    if args.print_only:
        return 1 if record["queue_error"] else 0

    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    conn = database.connect()
    try:
        expires = utcnow() + _dt.timedelta(days=config.get("watch", "retention_days"))
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO watch_samples (
                occurred_at, severity, reasons, window, queue_total, deferred_queue,
                sent, bounced, deferred, bounce_defer_rate, rate_limits, spam_blocks,
                top_sasl_user, top_sasl_count, bulk_senders, queue_top_sender,
                queue_top_sender_count, queue_top_domain_sender, queue_top_domain_count,
                queue_unique_domains, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["occurred_at"], record["severity"], record["reasons"], record["window"],
                record["queue_total"], record["deferred_queue"], record["sent"], record["bounced"],
                record["deferred"], record["bounce_defer_rate"], record["rate_limits"],
                record["spam_blocks"], record["top_sasl_user"], record["top_sasl_count"],
                record["bulk_senders"], record["queue_top_sender"], record["queue_top_sender_count"],
                record["queue_top_domain_sender"], record["queue_top_domain_count"],
                record["queue_unique_domains"], to_iso(expires),
            ),
        )
        conn.execute("COMMIT")
    except sqlite3.Error:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return 1 if record["queue_error"] else 0


def cmd_report(args, config) -> int:
    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    conn = database.connect()
    try:
        since = to_iso(utcnow() - parse_duration(args.since))
        rows = conn.execute(
            "SELECT * FROM watch_samples WHERE occurred_at >= ? ORDER BY occurred_at DESC LIMIT ?",
            (since, args.limit),
        ).fetchall()
        totals = conn.execute(
            """
            SELECT COUNT(*) AS samples,
                   SUM(severity = 'warning')  AS warnings,
                   SUM(severity = 'critical') AS criticals,
                   MAX(queue_total)           AS peak_queue,
                   MAX(top_sasl_count)        AS peak_sender,
                   SUM(rate_limits)           AS rate_limits,
                   SUM(spam_blocks)           AS spam_blocks
              FROM watch_samples WHERE occurred_at >= ?
            """,
            (since,),
        ).fetchone()
        senders = conn.execute(
            """
            SELECT top_sasl_user AS user, SUM(top_sasl_count) AS messages
              FROM watch_samples
             WHERE occurred_at >= ? AND top_sasl_user IS NOT NULL AND top_sasl_user != 'none'
             GROUP BY top_sasl_user ORDER BY messages DESC LIMIT 10
            """,
            (since,),
        ).fetchall()

        if args.json:
            json.dump(
                {
                    "since": since,
                    "totals": {k: totals[k] for k in totals.keys()},
                    "top_senders": [dict(r) for r in senders],
                    "samples": [dict(r) for r in rows],
                },
                sys.stdout,
                indent=2,
                default=str,
            )
            sys.stdout.write("\n")
            return 0

        print(f"Watch report since {since}")
        print(f"  samples:        {totals['samples'] or 0}")
        print(f"  warnings:       {totals['warnings'] or 0}")
        print(f"  criticals:      {totals['criticals'] or 0}")
        print(f"  peak queue:     {totals['peak_queue'] or 0}")
        print(f"  peak sender:    {totals['peak_sender'] or 0} messages in one window")
        print(f"  rate limits:    {totals['rate_limits'] or 0}")
        print(f"  spam blocks:    {totals['spam_blocks'] or 0}")
        if senders:
            print()
            print(columns(
                [(str(r["messages"]), truncate(sanitize(r["user"]), 60)) for r in senders],
                ["MESSAGES", "TOP-SASL-SENDER"],
            ))
        alerts = [r for r in rows if r["severity"] != "ok"]
        if alerts:
            print()
            print(columns(
                [
                    (r["occurred_at"], r["severity"], truncate(sanitize(r["reasons"]), 70))
                    for r in alerts[:20]
                ],
                ["TIME", "SEVERITY", "REASONS"],
            ))
        elif totals["samples"]:
            print("\nNo threshold was crossed in this period.")
        else:
            print("\nNo samples recorded yet (is mailut-watch.timer enabled?).")
        return 0
    finally:
        conn.close()
