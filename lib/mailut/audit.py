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
        if args.json:
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        if result["collected"]:
            scope = result["scope"]
            print(
                f"{sanitize(args.test)}: collected via {scope['scope_type']} "
                f"{sanitize(scope['scope_value'])} "
                f"(level {scope['level']}, retention {scope['retention_days']}d)"
            )
        else:
            print(f"{sanitize(args.test)}: not collected")
        return 0

    if args.json:
        json.dump([s.as_dict() for s in scopes], sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if not scopes:
        print("No audit scopes configured: nothing is being collected.")
        print("Enable collection with, for example: mailut audit add domain example.com")
        return 0

    rows = []
    for scope in scopes:
        included = scope.included
        rows.append(
            (
                scope.scope_type,
                scope.label(),
                scope.mode,
                scope.level if included else "-",
                f"{scope.retention_days}d" if included else "-",
                (f"{scope.message_retention_days}d" if scope.message_retention_days and included else "-"),
            )
        )
    print(columns(rows, ["TYPE", "VALUE", "MODE", "LEVEL", "RETENTION", "MSG-RETENTION"]))
    print()
    print("Most specific rule wins (email > domain > all); at equal specificity, exclude wins.")
    return 0
