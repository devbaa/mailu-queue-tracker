"""`mailut uninstall` — remove the application, keep the evidence.

Entirely local: no network, no git checkout, no Makefile.  The installed
manifest is the only list of files that may be removed, so nothing outside the
files this application installed is ever touched.

Default behaviour keeps ``/etc/mailut`` and ``/var/lib/mailut``.  Deleting
retained mail evidence is opt-in, and is confirmed with a typed word rather
than a y/n.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
from pathlib import Path

from .. import payloads as payload_store
from .. import release, systemd
from ..db import Database, schema_version
from ..util import AbortedError, MailutError, confirm, human_bytes, sanitize
from .lock import LifecycleLock
from .manifest import Manifest

# Removal order: files first, then the directories that held them.
REMOVAL_ORDER = ("unit", "man", "program", "library", "data", "manifest")


def _require_root(dry_run: bool) -> None:
    """A dry run changes nothing, and a staging root holds nothing privileged."""
    if dry_run or release.staged_root():
        return
    if os.geteuid() != 0:
        raise MailutError(
            f"{release.COMMAND_NAME} uninstall requires root privileges.\n"
            f"Run: sudo {release.COMMAND_NAME} uninstall"
        )


def data_summary(config) -> dict:
    """A cheap summary of what --remove-data would destroy."""
    summary = {
        "database": str(config.database),
        "database_bytes": 0,
        "events": None,
        "scopes": None,
        "stored_messages": None,
        "payload_bytes": payload_store.storage_bytes(config.message_dir),
        "backups": 0,
        "error": None,
    }
    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    summary["database_bytes"] = database.size_bytes()
    if config.backup_dir.is_dir():
        try:
            summary["backups"] = sum(1 for p in config.backup_dir.iterdir() if p.is_file())
        except OSError:
            pass
    if not config.database.exists():
        summary["error"] = "no database"
        return summary
    try:
        conn = database.open_readonly()
    except MailutError as exc:
        summary["error"] = str(exc)
        return summary
    try:
        if schema_version(conn) >= 1:
            summary["events"] = conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
            summary["scopes"] = conn.execute("SELECT COUNT(*) AS n FROM audit_scopes").fetchone()["n"]
            summary["stored_messages"] = conn.execute(
                "SELECT COUNT(*) AS n FROM audit_payloads WHERE kind = 'message'"
            ).fetchone()["n"]
    except sqlite3.Error as exc:
        summary["error"] = str(exc)
    finally:
        conn.close()
    return summary


def _print_data_summary(summary: dict) -> None:
    print("Retained Mailu Tools data:")
    if summary["error"] and summary["events"] is None:
        print(f"  database:          {summary['database']}  ({sanitize(summary['error'])})")
    else:
        print(f"  audit events:      {summary['events']}")
        print(f"  audit scopes:      {summary['scopes']}")
        print(f"  stored messages:   {summary['stored_messages']}")
    print(f"  database size:     {human_bytes(summary['database_bytes'])}")
    print(f"  payload storage:   {human_bytes(summary['payload_bytes'])}")
    print(f"  database backups:  {summary['backups']}")


def _plan(manifest: Manifest, config, args) -> dict:
    files: list[dict] = []
    for kind in REMOVAL_ORDER:
        files.extend(manifest.files(kinds=(kind,)))

    modified = []
    missing = []
    for entry in files:
        path = Path(entry["path"])
        if not path.exists():
            missing.append(str(path))
            continue
        digest = entry.get("sha256")
        if digest:
            from .manifest import sha256_file

            if sha256_file(path) != digest:
                modified.append(str(path))

    units = [u for u in manifest.units if u in release.OWNED_UNITS]
    active = [u for u in units if systemd.is_active(u)]
    enabled = [u for u in units if systemd.is_enabled(u)]

    removes_config = args.remove_config or args.purge
    removes_data = args.remove_data or args.purge

    return {
        "files": files,
        "missing": missing,
        "modified": modified,
        "directories": manifest.directories(),
        "units": units,
        "active_units": active,
        "enabled_units": enabled,
        "remove_config": removes_config,
        "remove_data": removes_data,
        "config_dir": Path(manifest.layout["confdir"]),
        "state_dir": config.state_dir,
    }


def _print_plan(plan: dict, *, dry_run: bool) -> None:
    prefix = "Would " if dry_run else ""
    if plan["active_units"]:
        print(f"{prefix}stop:")
        for unit in plan["active_units"]:
            print(f"  {unit}")
    if plan["enabled_units"]:
        print(f"{prefix}disable:")
        for unit in plan["enabled_units"]:
            print(f"  {unit}")
    print(f"{prefix}remove {len(plan['files']) - len(plan['missing'])} application file(s):")
    for entry in plan["files"][:40]:
        marker = "  (already absent)" if entry["path"] in plan["missing"] else ""
        print(f"  {entry['path']}{marker}")
    if len(plan["files"]) > 40:
        print(f"  ... and {len(plan['files']) - 40} more")
    print()
    print(f"configuration: {'REMOVE ' if plan['remove_config'] else 'preserve '}{plan['config_dir']}")
    print(f"state/data:    {'REMOVE ' if plan['remove_data'] else 'preserve '}{plan['state_dir']}")


def _remove_tree(path: Path) -> bool:
    try:
        shutil.rmtree(path)
        return True
    except FileNotFoundError:
        return True
    except OSError as exc:
        print(f"error: cannot remove {path}: {exc}", file=sys.stderr)
        return False


def cmd_uninstall(args, config) -> int:
    _require_root(args.dry_run)

    manifest = Manifest.load()
    plan = _plan(manifest, config, args)

    if plan["remove_data"]:
        summary = data_summary(config)
        _print_data_summary(summary)
        print()

    if args.dry_run:
        _print_plan(plan, dry_run=True)
        print("(dry run: nothing was changed)")
        return 0

    _print_plan(plan, dry_run=False)
    print()

    if plan["modified"]:
        print("Modified installed file(s) (they will still be removed; they are application-owned):")
        for path in plan["modified"][:20]:
            print(f"  {path}")
        if len(plan["modified"]) > 20:
            print(f"  ... and {len(plan['modified']) - 20} more")
        print()

    if plan["remove_data"]:
        if not confirm(
            "This will permanently delete Mailu Tools data:\n"
            "\n"
            "  audit scopes\n"
            "  retained SMTP/Rspamd events\n"
            "  SQLite database\n"
            "  stored message payloads\n"
            "  database backups\n"
            "\n"
            'Type "remove" to continue: ',
            assume_yes=args.yes,
            expect="remove",
        ):
            raise AbortedError("aborted: nothing was removed")
    elif not confirm(
        f"Remove {release.PROJECT_NAME} (configuration and audit data are preserved)? [y/N] ",
        assume_yes=args.yes,
    ):
        raise AbortedError("aborted: nothing was removed")

    with LifecycleLock(config.run_dir):
        return _execute(plan, config, manifest)


def _execute(plan: dict, config, manifest: Manifest) -> int:
    errors = 0

    # 1. systemd first: stop and disable before the unit files disappear.
    for unit in plan["active_units"]:
        if not systemd.stop(unit):
            print(f"warning: could not stop {unit}", file=sys.stderr)
    for unit in plan["enabled_units"]:
        systemd.disable(unit)  # a never-enabled unit is not an error

    # 2. Data and configuration, while the interpreter still has its library.
    if plan["remove_data"]:
        if not _remove_tree(plan["state_dir"]):
            errors += 1
    if plan["remove_config"]:
        if not _remove_tree(plan["config_dir"]):
            errors += 1

    # 3. Application files.  The running executable and the package this
    #    process imported from go last, so everything above ran with a
    #    complete installation.
    self_paths = {
        str(Path(sys.argv[0]).resolve()) if sys.argv and sys.argv[0] else "",
        str(Path(manifest.layout["sbindir"]) / release.COMMAND_NAME),
    }
    deferred: list[Path] = []
    for entry in plan["files"]:
        path = Path(entry["path"])
        if str(path) in self_paths or entry.get("type") in ("program", "library"):
            deferred.append(path)
            continue
        errors += 0 if _unlink(path) else 1

    for path in deferred:
        errors += 0 if _unlink(path) else 1

    # 4. Compiled bytecode caches. Python writes these into the library
    #    directory as it runs; they are derived from application-owned files
    #    inside directories this application owns exclusively.
    for directory in plan["directories"]:
        cache = Path(directory) / "__pycache__"
        if cache.is_dir():
            _remove_tree(cache)

    # 5. Now-empty directories that belonged to the application.
    for directory in sorted(plan["directories"], key=len, reverse=True):
        path = Path(directory)
        if not path.is_dir():
            continue
        try:
            next(path.iterdir())
        except StopIteration:
            try:
                path.rmdir()
            except OSError:
                pass
        except OSError:
            pass

    systemd.daemon_reload()

    print()
    print(f"{release.PROJECT_NAME} has been uninstalled.")
    if plan["remove_data"] or plan["remove_config"]:
        removed = []
        if plan["remove_config"]:
            removed.append(str(plan["config_dir"]))
        if plan["remove_data"]:
            removed.append(str(plan["state_dir"]))
        print()
        print("Removed:")
        for item in removed:
            print(f"  {item}")
    preserved = []
    if not plan["remove_config"]:
        preserved.append(str(plan["config_dir"]))
    if not plan["remove_data"]:
        preserved.append(str(plan["state_dir"]))
    if preserved:
        print()
        print("Preserved:")
        for item in preserved:
            print(f"  {item}")
    print()
    print(
        "Your Mailu/Rspamd configuration may still contain a metadata exporter\n"
        "pointing to the Mailu Tools collector. Remove that configuration manually\n"
        f"if it was not installed and owned by {release.COMMAND_NAME}."
    )
    return 1 if errors else 0


def _unlink(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return True  # repeated uninstall is not an error
    except OSError as exc:
        print(f"error: cannot remove {path}: {exc}", file=sys.stderr)
        return False
