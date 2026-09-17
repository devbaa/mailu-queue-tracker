"""`mailut status` and `mailut doctor`.

``status`` is a concise operational summary.  ``doctor`` is a read-only
diagnostic that exits non-zero when something critical is wrong; it never
changes state, and never touches Mailu's own configuration.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sqlite3
import sys
from pathlib import Path

from . import collector as collector_mod
from . import migrations, payloads as payload_store, release, systemd
from . import scopes as scope_store
from .db import Database, schema_version
from .mailu import Mailu
from .util import (
    EXIT_CHECK_FAILED,
    MailutError,
    classify_bind_address,
    human_bytes,
    sanitize,
)

OK, WARN, FAIL = "ok", "warn", "fail"


def _db_snapshot(config) -> dict:
    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    info = {
        "path": str(config.database),
        "exists": config.database.exists(),
        "size_bytes": database.size_bytes(),
        "schema_version": None,
        "events": None,
        "scopes": None,
        "latest_event": None,
        "latest_purge": None,
        "error": None,
    }
    if not info["exists"]:
        return info
    try:
        conn = database.open_readonly()
    except MailutError as exc:
        info["error"] = str(exc)
        return info
    try:
        info["schema_version"] = schema_version(conn)
        if info["schema_version"] >= 1:
            info["events"] = conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
            info["scopes"] = conn.execute("SELECT COUNT(*) AS n FROM audit_scopes").fetchone()["n"]
            row = conn.execute("SELECT MAX(occurred_at) AS t FROM audit_events").fetchone()
            info["latest_event"] = row["t"]
            row = conn.execute(
                "SELECT finished_at, events FROM purge_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                info["latest_purge"] = {"finished_at": row["finished_at"], "events": row["events"]}
    except sqlite3.Error as exc:
        info["error"] = str(exc)
    finally:
        conn.close()
    return info


def cmd_status(args, config) -> int:
    info = _db_snapshot(config)
    collector_ok, collector_note = collector_mod.probe(config)
    units = systemd.owned_unit_states()
    mailu = Mailu(config)

    payload = {
        "version": release.version(),
        "config": {"path": str(config.path), "present": config.present},
        "mailu": {
            "compose_dir": str(mailu.compose_dir),
            "compose_dir_ok": mailu.compose_dir_ok(),
            "compose_command": config.get("mailu", "compose_command"),
        },
        "database": info,
        "message_storage_bytes": payload_store.storage_bytes(config.message_dir),
        "collector": {"running": collector_ok, "detail": collector_note,
                      "bind": config.get("collector", "bind"),
                      "port": config.get("collector", "port")},
        "units": units,
    }

    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
        sys.stdout.write("\n")
        return 0

    print(f"{release.PROJECT_NAME} {release.version_display()}")
    print(f"  config:           {config.path}" + ("" if config.present else "  (not present; using defaults)"))
    print(f"  Mailu compose:    {mailu.compose_dir}" + ("" if mailu.compose_dir_ok() else "  (no compose file found)"))
    print(f"  database:         {info['path']}" + ("" if info["exists"] else "  (not created yet)"))
    if info["exists"]:
        print(f"  database size:    {human_bytes(info['size_bytes'])}")
        print(f"  schema version:   {info['schema_version']} (expected {migrations.LATEST})")
        print(f"  audit scopes:     {info['scopes']}")
        print(f"  audit events:     {info['events']}")
        print(f"  latest event:     {info['latest_event'] or '-'}")
        if info["latest_purge"]:
            print(f"  latest purge:     {info['latest_purge']['finished_at'] or 'in progress'} "
                  f"({info['latest_purge']['events']} events)")
        else:
            print("  latest purge:     -")
    if info["error"]:
        print(f"  database error:   {sanitize(info['error'])}")
    print(f"  message storage:  {human_bytes(payload['message_storage_bytes'])}")
    print(f"  collector:        {collector_note}")
    print("  units:")
    for unit, state in units.items():
        print(f"    {unit:<24} {state}")
    return 0


def _check(results, name, status, detail):
    results.append({"check": name, "status": status, "detail": detail})


def collect_checks(config) -> list[dict]:
    results: list[dict] = []

    version_info = sys.version_info
    _check(
        results,
        "python",
        OK if version_info >= (3, 9) else FAIL,
        f"{version_info.major}.{version_info.minor}.{version_info.micro}",
    )
    _check(
        results,
        "configuration",
        OK if config.present else WARN,
        f"{config.path}" + ("" if config.present else " missing; built-in defaults in use"),
    )

    mailu = Mailu(config)
    docker = shutil.which(mailu.compose[0])
    _check(results, "docker executable", OK if docker else FAIL, docker or f"{mailu.compose[0]} not found in PATH")
    _check(
        results,
        "mailu compose dir",
        OK if mailu.compose_dir_ok() else FAIL,
        str(mailu.compose_dir) + ("" if mailu.compose_dir_ok() else " (no docker-compose.yml)"),
    )

    if docker and mailu.compose_dir_ok():
        try:
            entries = mailu.queue_json()
            _check(results, "smtp service", OK, f"postqueue reachable ({len(entries)} queued message(s))")
        except MailutError as exc:
            _check(results, "smtp service", WARN, str(exc))
    else:
        _check(results, "smtp service", WARN, "skipped: docker or compose directory unavailable")

    state_dir = config.state_dir
    if state_dir.is_dir():
        mode = stat.S_IMODE(state_dir.stat().st_mode)
        too_open = bool(mode & 0o077)
        _check(
            results,
            "state directory",
            WARN if too_open else OK,
            f"{state_dir} mode {oct(mode)}" + (" (group/other access; expected 0700)" if too_open else ""),
        )
    else:
        _check(results, "state directory", WARN, f"{state_dir} does not exist yet")

    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    if config.database.exists():
        try:
            conn = database.open_readonly()
            try:
                version = schema_version(conn)
            finally:
                conn.close()
            status = OK if version == migrations.LATEST else WARN
            _check(results, "database schema", status, f"version {version} (expected {migrations.LATEST})")
        except (MailutError, sqlite3.Error) as exc:
            _check(results, "database schema", FAIL, str(exc))
        mode = stat.S_IMODE(config.database.stat().st_mode)
        _check(
            results,
            "database permissions",
            WARN if mode & 0o077 else OK,
            f"{config.database} mode {oct(mode)}",
        )
        writable = os.access(config.database, os.W_OK)
        _check(
            results,
            "database writable",
            OK if writable else FAIL,
            "writable" if writable else f"{config.database} is not writable by this user",
        )
    else:
        parent_writable = os.access(config.database.parent, os.W_OK) if config.database.parent.exists() else False
        _check(
            results,
            "database",
            WARN if parent_writable or not config.database.parent.exists() else FAIL,
            f"{config.database} does not exist; it is created on first use",
        )

    if config.message_dir.is_dir():
        mode = stat.S_IMODE(config.message_dir.stat().st_mode)
        _check(
            results,
            "message storage",
            WARN if mode & 0o077 else OK,
            f"{config.message_dir} mode {oct(mode)} ({human_bytes(payload_store.storage_bytes(config.message_dir))})",
        )
    else:
        _check(results, "message storage", OK, f"{config.message_dir} not created (no messages retained)")

    if config.get("audit", "allow_messages"):
        _check(results, "message collection", WARN,
               "audit.allow_messages is true: complete messages may be retained")
    else:
        _check(results, "message collection", OK, "complete messages are disabled (default)")

    bind = config.get("collector", "bind")
    _check(
        results,
        "collector bind",
        OK if bind in ("127.0.0.1", "::1", "localhost") else WARN,
        f"{bind}:{config.get('collector', 'port')}"
        + ("" if bind in ("127.0.0.1", "::1", "localhost") else " (not localhost; the collector is unauthenticated)"),
    )
    running, note = collector_mod.probe(config)
    collector_unit_active = systemd.is_active("mailut-audit.service")
    _check(results, "collector", OK if running else (WARN if not collector_unit_active else FAIL), note)

    if systemd.available():
        for unit in release.OWNED_UNITS:
            state = systemd.show(unit)
            if not state:
                _check(results, unit, WARN, "unit not installed")
                continue
            active = state.get("ActiveState", "unknown")
            enabled = state.get("UnitFileState", "not-installed")
            if unit == "mailut-audit.service":
                status = OK if active == "active" else WARN
            elif unit == "mailut-purge.timer":
                status = OK if active == "active" else WARN
            else:
                status = OK
            _check(results, unit, status, f"{active} ({enabled})")
    else:
        _check(results, "systemd", WARN, "systemd not available; schedule mailut watch/purge another way")

    scope_note = "database not created yet"
    scope_status = WARN
    if config.database.exists():
        try:
            conn = database.open_readonly()
            try:
                if schema_version(conn) >= 1:
                    rows = scope_store.list_scopes(conn)
                    including = [s for s in rows if s.included]
                    scope_note = f"{len(rows)} scope(s), {len(including)} collecting"
                    scope_status = OK if including else WARN
            finally:
                conn.close()
        except (MailutError, sqlite3.Error) as exc:
            scope_note = str(exc)
            scope_status = FAIL
    _check(results, "audit scopes", scope_status, scope_note)

    _check_rspamd(results, config, mailu, docker)
    _check_degraded_scopes(results, config, database)
    return results


def _check_rspamd(results, config, mailu, docker) -> None:
    """Check the Rspamd wiring itself, not merely that our example exists.

    The example snippet under <datadir> is installed by `make install` and is
    always present, so its existence says nothing about whether this host is
    actually exporting anything.  What matters is whether an override exists in
    the Mailu tree that points at this collector, and whether the antispam
    container can reach it.
    """
    override_dir = mailu.rspamd_override_dir
    port = config.get("collector", "port")
    configured = None
    if override_dir.is_dir():
        for candidate in sorted(override_dir.glob("*.conf")):
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "metadata_exporter" in text and f":{port}" in text:
                configured = candidate
                break
    if configured:
        _check(results, "rspamd exporter", OK, f"{configured} posts to port {port}")
    elif override_dir.is_dir():
        _check(
            results,
            "rspamd exporter",
            WARN,
            f"no metadata_exporter targeting port {port} in {override_dir}; "
            f"Rspamd decisions will not be collected (copy "
            f"{Path(release.layout()['datadir']) / 'rspamd' / 'mailut-exporter.conf'} there)",
        )
    else:
        _check(
            results,
            "rspamd exporter",
            WARN,
            f"{override_dir} does not exist; Rspamd decisions will not be collected",
        )

    # Reachability from the container is the other half, and the half that the
    # bind address most often gets wrong.
    if not (docker and mailu.compose_dir_ok()):
        _check(results, "rspamd -> collector", WARN,
               "skipped: docker or compose directory unavailable")
        return
    bind = config.get("collector", "bind")
    target = "127.0.0.1" if classify_bind_address(bind) == "loopback" else bind
    url = f"http://{target}:{port}/health"
    reachable, detail = mailu.probe_url_from_service(mailu.antispam_service, url)
    if reachable is True:
        _check(results, "rspamd -> collector", OK, f"{mailu.antispam_service} can reach {url}")
    elif reachable is False:
        _check(
            results,
            "rspamd -> collector",
            WARN,
            f"{mailu.antispam_service} cannot reach {url} ({detail}); "
            "the exporter's url and collector.bind must agree, and the bind "
            "address must be reachable from the container",
        )
    else:
        _check(results, "rspamd -> collector", WARN, f"not verified: {detail}")


def _check_degraded_scopes(results, config, database) -> None:
    """Warn when a scope asks for more than the host currently permits."""
    if not config.database.exists():
        return
    try:
        conn = database.open_readonly()
    except MailutError:
        return
    try:
        if schema_version(conn) < 1:
            return
        degraded = []
        for scope in scope_store.list_scopes(conn):
            if not scope.included:
                continue
            if scope.level == "headers" and not config.get("audit", "allow_headers"):
                degraded.append(f"{scope.scope_type} {scope.label()} (headers)")
            elif scope.level == "message" and not config.get("audit", "allow_messages"):
                degraded.append(f"{scope.scope_type} {scope.label()} (message)")
    except sqlite3.Error:
        return
    finally:
        conn.close()
    if degraded:
        _check(
            results,
            "scope levels",
            WARN,
            f"{len(degraded)} scope(s) request a level this host disables and are "
            f"collecting metadata only: {', '.join(sanitize(d) for d in degraded[:5])}",
        )
    else:
        _check(results, "scope levels", OK, "every scope's level is permitted by this host")


def cmd_doctor(args, config) -> int:
    results = collect_checks(config)
    failed = [r for r in results if r["status"] == FAIL]
    warned = [r for r in results if r["status"] == WARN]

    if args.json:
        json.dump(
            {"checks": results, "failed": len(failed), "warnings": len(warned)},
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return EXIT_CHECK_FAILED if failed else 0

    width = max(len(r["check"]) for r in results)
    for result in results:
        marker = {OK: "ok  ", WARN: "warn", FAIL: "FAIL"}[result["status"]]
        print(f"[{marker}] {result['check']:<{width}}  {sanitize(result['detail'])}")
    print()
    print(f"{len(results)} checks: {len(failed)} failed, {len(warned)} warning(s).")
    if failed:
        print("Doctor found critical problems; the audit subsystem may not work.")
    return EXIT_CHECK_FAILED if failed else 0
