"""`mailut ips` — real external client IPs from the Mailu front log.

The smtp container only ever sees the front proxy (XCLIENT), so a compromised
account's true source address lives in the front log.  IPv4 only: an IPv6
address cannot be told apart from a syslog time stamp without false positives,
so addresses are taken from the explicit ``client:``/bracketed forms instead of
guessed out of free text.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys

from .mailu import Mailu
from .util import columns, sanitize, truncate

_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_USER_PATTERNS = (
    re.compile(r"sasl_username=([^,\s]+)"),
    re.compile(r"user=<([^>]+)>"),
    re.compile(r'login:\s*"([^"]+)"'),
    re.compile(r"login=([^,\s]+)"),
)


def _username(line: str) -> str | None:
    for pattern in _USER_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


# "Internal" here means what an operator wants hidden: the Docker bridge, the
# LAN and loopback. The ranges are listed explicitly rather than using
# ipaddress.is_private, which also covers the RFC 5737 documentation ranges
# that stand in for real external addresses in examples and fixtures.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


def _is_external(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not any(parsed in network for network in _INTERNAL_NETWORKS)


def tally(text: str, *, include_private: bool = False, exclude=(), user_regex: str | None = None) -> list[dict]:
    excluded = set(exclude)
    matcher = re.compile(user_regex, re.IGNORECASE) if user_regex else None
    counts: dict[str, dict] = {}
    for line in text.splitlines():
        if matcher and not matcher.search(line):
            continue
        user = _username(line)
        seen_on_line = set()
        for candidate in _IPV4.findall(line):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate in excluded or candidate in seen_on_line:
                continue
            if not include_private and not _is_external(candidate):
                continue
            seen_on_line.add(candidate)
            record = counts.setdefault(candidate, {"ip": candidate, "lines": 0, "users": set()})
            record["lines"] += 1
            if user:
                record["users"].add(user)
    rows = [
        {"ip": r["ip"], "lines": r["lines"], "users": sorted(r["users"])}
        for r in counts.values()
    ]
    rows.sort(key=lambda r: (-r["lines"], r["ip"]))
    return rows


def cmd_ips(args, config) -> int:
    mailu = Mailu(config)
    front_service = config.get("mailu", "front_service")
    text = mailu.logs(front_service, since=args.since)

    exclude = [item.strip() for item in (args.exclude or "").split(",") if item.strip()]
    rows = tally(
        text,
        include_private=args.all,
        exclude=exclude,
        user_regex=re.escape(args.user) if args.user else None,
    )[: args.top]

    if args.json:
        json.dump(
            {"service": front_service, "since": args.since, "results": rows},
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    scope = "including private/internal IPs" if args.all else "private/internal IPs hidden"
    print(f'Client IPs from the "{front_service}" log since {args.since} ({scope})')
    if args.user:
        print(f"filtered to lines mentioning: {sanitize(args.user)}")
    if not rows:
        print("  (no matching client IPs found)")
        return 0
    print()
    print(
        columns(
            [
                (
                    str(row["lines"]),
                    row["ip"],
                    str(len(row["users"])),
                    truncate(sanitize(", ".join(row["users"][:3])) if row["users"] else "-", 60),
                )
                for row in rows
            ],
            ["LINES", "IP", "USERS", "SAMPLE-USERS"],
        )
    )
    return 0
