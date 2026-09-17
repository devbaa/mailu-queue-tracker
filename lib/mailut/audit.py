"""`mailut audit add|remove|scopes` — managing collection scopes."""

from __future__ import annotations

import json
import sys

from . import scopes as scope_store
from .util import UsageError, columns, sanitize


def _retention(args, config) -> int:
    value = args.retention if args.retention is not None else config.get("audit", "default_retention_days")
    maximum = config.get("audit", "max_retention_days")
    if value < 1:
        raise UsageError("--retention must be at least 1 day")
    if value > maximum:
        raise UsageError(f"--retention must not exceed audit.max_retention_days ({maximum})")
    return value


def _message_retention(args, config, level: str) -> int | None:
    if args.message_retention is None:
        return None
    if level != "message":
        raise UsageError("--message-retention only applies to --level message")
    maximum = config.get("audit", "max_retention_days")
    if args.message_retention < 1:
        raise UsageError("--message-retention must be at least 1 day")
    if args.message_retention > maximum:
        raise UsageError(f"--message-retention must not exceed audit.max_retention_days ({maximum})")
    return args.message_retention


def cmd_add(args, config, conn) -> int:
    value = scope_store.normalize_target(args.scope_type, getattr(args, "value", None))
    level = args.level or config.get("audit", "default_level")
    config.check_level_allowed(level)  # fails loudly; never downgrades silently
    retention = _retention(args, config)
    message_retention = _message_retention(args, config, level)

    scope, created = scope_store.upsert_scope(
        conn,
        scope_type=args.scope_type,
        value=value,
        mode="include",
        level=level,
        retention_days=retention,
        message_retention_days=message_retention,
    )
    verb = "Added" if created else "Updated"
    print(
        f"{verb} include scope: {scope.scope_type} {sanitize(scope.label())} "
        f"(level {scope.level}, retention {scope.retention_days}d"
        + (f", messages {scope.message_retention_days}d" if scope.message_retention_days else "")
        + ")"
    )
    _print_effect(conn, config, scope)
    return 0


def cmd_remove(args, config, conn) -> int:
    value = scope_store.normalize_target(args.scope_type, getattr(args, "value", None))
    existing = scope_store.get_scope(conn, args.scope_type, value)
    level = existing.level if existing else config.get("audit", "default_level")
    retention = existing.retention_days if existing else config.get("audit", "default_retention_days")

    scope, created = scope_store.upsert_scope(
        conn,
        scope_type=args.scope_type,
        value=value,
        mode="exclude",
        level=level,
        retention_days=retention,
        message_retention_days=existing.message_retention_days if existing else None,
    )
    verb = "Added" if created else "Updated"
    print(f"{verb} exclude scope: {scope.scope_type} {sanitize(scope.label())}")
    print("Future events for this scope will not be collected.")
    print("Existing records are kept until they expire, or until `mailut audit purge` removes them.")
    _print_effect(conn, config, scope)
    return 0


def _print_effect(conn, config, scope) -> None:
    """Show what the change means when a broader rule is also in play."""
    if scope.scope_type == "all":
        return
    all_scope = scope_store.get_scope(conn, "all", scope_store.ALL_VALUE)
    if all_scope is None:
        return
    if scope.mode == "exclude" and all_scope.included:
        print("Note: the 'all' scope stays active for every other recipient.")
    if scope.mode == "include" and not all_scope.included:
        print("Note: the 'all' scope is not collecting; only the scopes listed above are.")


def cmd_scopes(args, config, conn) -> int:
    scopes = scope_store.list_scopes(conn)

    if args.test:
        result = scope_store.describe_resolution(conn, args.test, local_domains=config.local_domains)
        scope = result["scope"]
        # Report what would actually be collected, not what the scope asked
        # for: the host can disable a level after the scope was created, and
        # this answer must agree with `mailut audit scopes`.
        effective = _effective_level(scope["level"], config) if scope else None
        if scope:
            result["effective_level"] = effective
        if args.json:
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        if result["collected"]:
            level = effective if effective == scope["level"] else f"{effective} (asked {scope['level']})"
            print(
                f"{sanitize(args.test)}: collected via {scope['scope_type']} "
                f"{sanitize(scope['scope_value'])} "
                f"(level {level}, retention {scope['retention_days']}d)"
            )
        else:
            print(f"{sanitize(args.test)}: not collected")
        return 0

    if args.json:
        payload = []
        for scope in scopes:
            record = scope.as_dict()
            record["effective_level"] = (
                _effective_level(scope.level, config) if scope.included else None
            )
            payload.append(record)
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if not scopes:
        print("No audit scopes configured: nothing is being collected.")
        print("Enable collection with, for example: mailut audit add domain example.com")
        return 0

    rows = []
    degraded = 0
    for scope in scopes:
        included = scope.included
        level = scope.level
        if included:
            effective = _effective_level(level, config)
            if effective != level:
                # Show what is actually being collected, not just what was asked
                # for: the host configuration can be tightened after a scope is
                # created, and an operator must not read "headers" here while
                # only metadata is being retained.
                level = f"{effective} (asked {level})"
                degraded += 1
        rows.append(
            (
                scope.scope_type,
                scope.label(),
                scope.mode,
                level if included else "-",
                f"{scope.retention_days}d" if included else "-",
                (f"{scope.message_retention_days}d" if scope.message_retention_days and included else "-"),
            )
        )
    print(columns(rows, ["TYPE", "VALUE", "MODE", "LEVEL", "RETENTION", "MSG-RETENTION"]))
    print()
    print("Most specific rule wins (email > domain > all); at equal specificity, exclude wins.")
    if degraded:
        print()
        print(
            f"warning: {degraded} scope(s) ask for a collection level this host disables "
            f"and are collecting metadata only.",
            file=sys.stderr,
        )
        print(
            "         Re-enable audit.allow_headers / audit.allow_messages, or lower the "
            "scope's --level.",
            file=sys.stderr,
        )
    return 0


def _effective_level(level: str, config) -> str:
    """The level actually collected, given what the host currently permits."""
    if level == "headers" and not config.get("audit", "allow_headers"):
        return "metadata"
    if level == "message" and not config.get("audit", "allow_messages"):
        return "metadata"
    return level
