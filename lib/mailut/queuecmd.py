"""`mailut queue` — inspect the Postfix queue and remove or hold mail.

Matching is exact and case-insensitive on the envelope address, so
``example.com`` never matches ``user@example.com`` and a typo cannot widen a
deletion.
"""

from __future__ import annotations

import json
import sys

from .mailu import Mailu, queue_entry_recipients
from .util import (
    AbortedError,
    MailutError,
    UsageError,
    columns,
    confirm,
    domain_of,
    normalize_email,
    sanitize,
    truncate,
)

OPERATIONS = {"drain": ("-d", "delete"), "hold": ("-h", "hold"), "release": ("-H", "release")}


def _summarise(entries: list[dict]) -> dict:
    senders: dict[str, int] = {}
    sender_domains: dict[str, set] = {}
    domains: set[str] = set()
    deferred = 0
    for entry in entries:
        if entry.get("queue_name") == "deferred":
            deferred += 1
        sender = (entry.get("sender") or "<>").lower()
        senders[sender] = senders.get(sender, 0) + 1
        for recipient in queue_entry_recipients(entry):
            recipient_domain = domain_of(recipient)
            if recipient_domain:
                domains.add(recipient_domain)
                sender_domains.setdefault(sender, set()).add(recipient_domain)
    top_sender, top_sender_count = ("none", 0)
    if senders:
        top_sender, top_sender_count = max(senders.items(), key=lambda kv: kv[1])
    top_fanout, top_fanout_count = ("none", 0)
    if sender_domains:
        top_fanout, values = max(sender_domains.items(), key=lambda kv: len(kv[1]))
        top_fanout_count = len(values)
    return {
        "total": len(entries),
        "deferred": deferred,
        "senders": senders,
        "unique_recipient_domains": len(domains),
        "top_sender": top_sender,
        "top_sender_count": top_sender_count,
        "top_fanout_sender": top_fanout,
        "top_fanout_domains": top_fanout_count,
    }


def cmd_list(args, config) -> int:
    mailu = Mailu(config)
    entries = mailu.queue_json()

    if args.sender:
        wanted = normalize_email(args.sender)
        entries = [e for e in entries if (e.get("sender") or "").lower() == wanted]
    if args.recipient:
        wanted = normalize_email(args.recipient)
        entries = [
            e for e in entries
            if any(r.lower() == wanted for r in queue_entry_recipients(e))
        ]

    summary = _summarise(entries)
    if args.json:
        payload = {k: v for k, v in summary.items() if k != "senders"}
        payload["top_senders"] = [
            {"sender": s, "messages": n}
            for s, n in sorted(summary["senders"].items(), key=lambda kv: -kv[1])[: args.top]
        ]
        if args.detail:
            payload["messages"] = [
                {
                    "queue_id": e.get("queue_id"),
                    "queue_name": e.get("queue_name"),
                    "arrival_time": e.get("arrival_time"),
                    "message_size": e.get("message_size"),
                    "sender": e.get("sender"),
                    "recipients": queue_entry_recipients(e),
                }
                for e in entries[: args.limit]
            ]
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    print(f"queue total:              {summary['total']}")
    print(f"deferred:                 {summary['deferred']}")
    print(f"unique recipient domains: {summary['unique_recipient_domains']}")
    print(f"top sender:               {sanitize(summary['top_sender'])} ({summary['top_sender_count']})")
    print(
        f"widest fan-out:           {sanitize(summary['top_fanout_sender'])} "
        f"({summary['top_fanout_domains']} domains)"
    )
    if summary["senders"]:
        print()
        rows = [
            (str(count), truncate(sanitize(sender), 60))
            for sender, count in sorted(summary["senders"].items(), key=lambda kv: -kv[1])[: args.top]
        ]
        print(columns(rows, ["MESSAGES", "SENDER"]))
    if args.detail and entries:
        print()
        rows = [
            (
                str(entry.get("queue_id") or "-"),
                str(entry.get("queue_name") or "-"),
                str(entry.get("message_size") or "-"),
                truncate(sanitize(entry.get("sender") or "<>"), 40),
                truncate(sanitize(", ".join(queue_entry_recipients(entry))), 50),
            )
            for entry in entries[: args.limit]
        ]
        print(columns(rows, ["QUEUE-ID", "QUEUE", "SIZE", "SENDER", "RECIPIENTS"]))
    return 0


def cmd_apply(args, config, operation: str) -> int:
    """Shared implementation for `queue drain`, `queue hold` and `queue release`."""
    flag, verb = OPERATIONS[operation]
    if bool(args.sender) == bool(args.recipient):
        raise UsageError("give exactly one of --sender or --recipient")

    field = "sender" if args.sender else "recipient"
    address = normalize_email(args.sender or args.recipient)

    mailu = Mailu(config)
    entries = mailu.queue_json()
    if field == "sender":
        matched = [e for e in entries if (e.get("sender") or "").lower() == address]
    else:
        matched = [
            e for e in entries
            if any(r.lower() == address for r in queue_entry_recipients(e))
        ]
    queue_ids = [str(e.get("queue_id")) for e in matched if e.get("queue_id")]

    print(f"Matched {len(queue_ids)} message(s) where {field} = {sanitize(address)}")
    if not queue_ids:
        return 0
    if args.dry_run:
        for queue_id in queue_ids[: args.limit]:
            print(f"  {sanitize(queue_id)}")
        if len(queue_ids) > args.limit:
            print(f"  ... and {len(queue_ids) - args.limit} more")
        print("(dry run: nothing changed)")
        return 0

    if not confirm(
        f"{verb} {len(queue_ids)} message(s) for {sanitize(address)}? [y/N] ",
        assume_yes=args.yes,
    ):
        raise AbortedError("aborted: no changes made (use --yes for a non-interactive run)")

    output = mailu.postsuper(flag, queue_ids)
    print(f"Done: {verb} {len(queue_ids)} message(s) for {sanitize(address)}.")
    if output:
        for line in output.splitlines()[:5]:
            print(f"  {sanitize(line)}")
    return 0


def cmd_drain(args, config) -> int:
    return cmd_apply(args, config, "drain")


def cmd_hold(args, config) -> int:
    return cmd_apply(args, config, "hold")


def cmd_release(args, config) -> int:
    return cmd_apply(args, config, "release")


def collect_metrics(config) -> dict:
    """Queue metrics for `mailut watch`.

    An unreadable queue is reported, not hidden behind zeroes: the caller
    prints the error and marks the sample as incomplete.
    """
    try:
        summary = _summarise(Mailu(config).queue_json())
        summary["error"] = None
    except MailutError as exc:
        summary = _summarise([])
        summary["error"] = str(exc)
    return summary
