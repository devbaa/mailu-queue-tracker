"""`mailut upgrade` — install a newer public release over this one.

The installed application carries everything needed: its version, the canonical
upstream, and the manifest of files it owns.  The original checkout may be long
gone.

Nothing is executed from the network without first verifying a SHA-256 from the
release's own ``SHA256SUMS`` asset, and the artifact is unpacked and validated
in a private temporary directory before a single installed file is touched.
Installation itself is delegated to the *new* release's ``make install``, so
``make install`` and ``mailut upgrade`` can never drift into two different
notions of how this application is installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .. import db as db_mod
from .. import migrations, release, systemd
from ..db import Database
from ..util import (
    AbortedError,
    EXIT_CHECK_FAILED,
    MailutError,
    confirm,
    sanitize,
    to_iso,
    utcnow,
)
from . import archive, upstream
from .lock import LifecycleLock
from .manifest import Manifest


def _require_root() -> None:
    if os.geteuid() != 0:
        raise MailutError(
            f"{release.COMMAND_NAME} upgrade requires root privileges.\n"
            f"Run: sudo {release.COMMAND_NAME} upgrade"
        )


def _require_make() -> str:
    make = shutil.which("make")
    if not make:
        raise MailutError(
            "the `make` utility is required to install a release "
            "(install build-essential / make, or install the release manually)"
        )
    return make


def _installed_version() -> str:
    return release.version()


def _target_release(args) -> dict:
    if args.target_version:
        return upstream.release_by_version(args.target_version)
    return upstream.latest_release(allow_prerelease=args.prerelease)


def _compare(installed: str, target: str) -> int:
    lhs = upstream.parse_version(installed)
    rhs = upstream.parse_version(target)
    return (lhs > rhs) - (lhs < rhs)


def cmd_check(args, config) -> int:
    """Read-only: contacts GitHub, changes nothing, works without root."""
    installed = _installed_version()
    target = _target_release(args)
    print(f"Installed: {installed}")
    print(f"Latest:    {target['version']}" + ("  (prerelease)" if target["prerelease"] else ""))
    order = _compare(installed, target["version"])
    if order < 0:
        print("Update available.")
    elif order == 0:
        print(f"{release.COMMAND_NAME} is up to date.")
    else:
        print(f"Installed version is newer than the published {target['version']}.")
    return 0


def _fetch_release(target: dict, workdir: Path, *, verbose: bool) -> dict:
    tarball_name, checksum_name = upstream.asset_names(target["version"])
    if tarball_name not in target["assets"]:
        raise upstream.UpstreamError(
            f"release {target['version']} does not publish {tarball_name}"
        )
    if checksum_name not in target["assets"]:
        raise upstream.UpstreamError(
            f"release {target['version']} does not publish {checksum_name}; "
            "refusing to install an unverifiable artifact"
        )

    if verbose:
        print(f"  tarball:  {target['assets'][tarball_name]}")
    tarball = upstream.download(target["assets"][tarball_name], workdir / tarball_name)
    checksums_file = upstream.download(
        target["assets"][checksum_name], workdir / checksum_name, max_bytes=65536
    )
    sums = upstream.parse_checksums(checksums_file.read_text(encoding="utf-8", errors="replace"))
    expected = sums.get(tarball_name)
    if not expected:
        raise archive.ArchiveError(
            f"{checksum_name} does not list {tarball_name}; refusing to install it"
        )
    archive.verify_checksum(tarball, expected)
    print("Checksum verified.")

    root = archive.extract(tarball, workdir / "unpacked")
    return archive.validate_tree(root, expected_version=target["version"])


def _schema_of_tree(tree: dict) -> int:
    return int(tree["schema_version"])


def _current_schema(config) -> int:
    if not config.database.exists():
        return 0
    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    try:
        conn = database.open_readonly()
    except MailutError:
        return 0
    try:
        return db_mod.schema_version(conn)
    finally:
        conn.close()


def _backup_database(config, installed_version: str, schema: int) -> Path:
    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    conn = database.connect(create=False, migrate=False)
    try:
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        name = f"mailut-db-{installed_version}-schema{schema}-{stamp}.sqlite3"
        return db_mod.backup(conn, config.backup_dir / name)
    finally:
        conn.close()


def _run_make_install(tree_root: Path, layout: dict, *, verbose: bool) -> None:
    make = _require_make()
    argv = [
        make,
        "-C",
        str(tree_root),
        "install",
        f"PREFIX={layout['prefix']}",
        f"SYSCONFDIR={layout['sysconfdir']}",
        f"LOCALSTATEDIR={layout['localstatedir']}",
        f"SYSTEMD_UNIT_DIR={layout['systemd_unit_dir']}",
        "SKIP_DAEMON_RELOAD=1",
    ]
    if os.environ.get("MAILUT_ROOT"):
        # Staged installs (tests) keep everything under one root.
        argv.append(f"DESTDIR={os.environ['MAILUT_ROOT']}")
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if verbose and proc.stdout:
        for line in proc.stdout.splitlines():
            print(f"  {line}")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise MailutError(
            "installing the new release failed"
            + (f": {detail[-1]}" if detail else "")
            + "\nThe previous installation was left in place as far as make got; "
            "re-run the upgrade once the cause is fixed."
        )


def _installed_command(layout: dict) -> Path:
    return Path(layout["sbindir"]) / release.COMMAND_NAME


def _run_installed(layout: dict, args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    command = _installed_command(layout)
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(command), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def cmd_upgrade(args, config) -> int:
    if args.check:
        return cmd_check(args, config)

    installed = _installed_version()
    if not release.is_installed() and not args.dry_run:
        raise MailutError(
            "this looks like a source checkout, not an installed application. "
            "Use `sudo make install` here instead of `mailut upgrade`."
        )

    if not args.dry_run:
        _require_root()
        _require_make()

    manifest = None
    try:
        manifest = Manifest.load()
    except MailutError as exc:
        if not args.dry_run:
            raise
        print(f"note: {exc}", file=sys.stderr)

    layout = manifest.layout if manifest else release.layout()
    install_layout = manifest.install_layout if manifest else release.DEFAULT_LAYOUT

    target = _target_release(args)
    order = _compare(installed, target["version"])
    print(f"Installed: {installed}")
    print(f"Target:    {target['version']}" + ("  (prerelease)" if target["prerelease"] else ""))

    if order == 0:
        print(f"{release.COMMAND_NAME} is up to date.")
        return 0
    if order > 0 and not args.allow_downgrade:
        raise MailutError(
            f"refusing to downgrade from {installed} to {target['version']}. "
            "Pass --allow-downgrade if the database schema is known to be compatible."
        )

    current_schema = _current_schema(config)

    if args.dry_run:
        return _dry_run(args, target, current_schema, layout, order)

    # Warn before replacing files the operator may have edited on purpose.
    if manifest is not None:
        state = manifest.verify()
        if state["modified"]:
            print()
            print("Modified installed application files detected.")
            print("Upgrade will replace these application-owned files:")
            for path in state["modified"][:20]:
                print(f"  {path}")
            if len(state["modified"]) > 20:
                print(f"  ... and {len(state['modified']) - 20} more")
            if not confirm("Continue? [y/N] ", assume_yes=args.yes):
                raise AbortedError("aborted: nothing was changed")

    with LifecycleLock(config.run_dir):
        print()
        print(f"{release.COMMAND_NAME} {installed} -> {target['version']}")
        print("Downloading release...")
        with tempfile.TemporaryDirectory(prefix="mailut-upgrade-") as tmp:
            workdir = Path(tmp)
            os.chmod(workdir, 0o700)
            tree = _fetch_release(target, workdir, verbose=args.verbose)
            target_schema = _schema_of_tree(tree)
            schema_change = target_schema != current_schema and config.database.exists()

            audit_was_active = systemd.is_active("mailut-audit.service")

            backup_path = None
            if schema_change:
                if audit_was_active:
                    print("Stopping mailut-audit.service for the schema migration...")
                    systemd.stop("mailut-audit.service")
                print(f"Backing up the database (schema {current_schema})...")
                backup_path = _backup_database(config, installed, current_schema)
                print(f"  {backup_path}")

            print("Installing...")
            _run_make_install(tree["root"], install_layout, verbose=args.verbose)

        # From here on, the new release is on disk; the temporary tree is gone.
        if schema_change:
            print(f"Database schema: {current_schema} -> {target_schema}")
            proc = _run_installed(layout, ["--config", str(config.path), "db", "migrate"])
            if proc.returncode != 0:
                print(proc.stdout.strip(), file=sys.stderr)
                print(proc.stderr.strip(), file=sys.stderr)
                print()
                print("Database migration FAILED.", file=sys.stderr)
                if backup_path:
                    print(f"  pre-migration backup: {backup_path}", file=sys.stderr)
                print(f"  schema before migration: {current_schema}", file=sys.stderr)
                print(
                    "  mailut-audit.service was left stopped because the running code and "
                    "the database schema may not match.",
                    file=sys.stderr,
                )
                print("  Manual investigation is required.", file=sys.stderr)
                return 1

        # daemon-reload is enough for the timers and the oneshot services: it
        # re-reads the unit files and re-arms the timers. Only the long-running
        # collector has to be restarted to pick up new code, and only if it was
        # running. Nothing is ever enabled here, so a unit the administrator
        # deliberately left disabled stays disabled.
        systemd.daemon_reload()
        if audit_was_active:
            print("Restarting mailut-audit.service...")
            systemd.restart("mailut-audit.service")

        failures = _verify(config, layout, target["version"], audit_was_active)

    if failures:
        print()
        for failure in failures:
            print(f"post-upgrade check failed: {failure}", file=sys.stderr)
        print("Upgrade installed files but verification failed; manual investigation is required.",
              file=sys.stderr)
        return EXIT_CHECK_FAILED

    print("Upgrade complete.")
    return 0


def _dry_run(args, target: dict, current_schema: int, layout: dict, order: int) -> int:
    print()
    print("Would:")
    print(f"  verify the release artifact for {target['version']} against its SHA256SUMS")
    print("  replace application files under:")
    print(f"    {layout['sbindir']}/{release.COMMAND_NAME}")
    print(f"    {layout['libdir']}")
    print(f"    {layout['datadir']}")
    print("  update man pages")
    print(f"    {layout['mandir']}/man8/{release.COMMAND_NAME}.8")
    print(f"    {layout['mandir']}/man5/{release.COMMAND_NAME}.conf.5")
    print(f"  refresh systemd units in {layout['systemd_unit_dir']}")
    if current_schema and current_schema != release.SCHEMA_VERSION:
        print(f"  back up the database and migrate schema {current_schema} -> (release schema)")
    else:
        print("  leave the database schema unchanged (no backup needed)")
    print("  reload systemd")
    if systemd.is_active("mailut-audit.service"):
        print("  restart mailut-audit.service")
    print()
    print("Preserved: the configuration file, the database, stored messages and backups.")
    print("(dry run: nothing was changed)")
    if order > 0 and not args.allow_downgrade:
        print("This target is older than the installed version; a real run would refuse it.")
    return 0


def _verify(config, layout: dict, expected_version: str, audit_was_active: bool) -> list[str]:
    """Post-upgrade health checks; anything here failing means exit non-zero."""
    failures: list[str] = []

    proc = _run_installed(layout, ["--version"], timeout=30)
    if proc.returncode != 0:
        failures.append(f"`{release.COMMAND_NAME} --version` exited {proc.returncode}")
    elif expected_version not in proc.stdout:
        failures.append(
            f"installed version reports {sanitize(proc.stdout.strip())}, expected {expected_version}"
        )

    proc = _run_installed(layout, ["--config", str(config.path), "config", "check"], timeout=30)
    if proc.returncode != 0:
        failures.append("the configuration file no longer parses")

    if config.database.exists():
        try:
            database = Database(config.database, config.get("storage", "busy_timeout_ms"))
            conn = database.open_readonly()
            try:
                version = db_mod.schema_version(conn)
            finally:
                conn.close()
            if version != migrations.LATEST and version != release.SCHEMA_VERSION:
                failures.append(f"database schema is {version}")
        except MailutError as exc:
            failures.append(f"database does not open: {exc}")

    try:
        manifest = Manifest.load(Path(layout["datadir"]) / "install-manifest.json")
        state = manifest.verify()
        if state["missing"]:
            failures.append(f"{len(state['missing'])} installed file(s) are missing")
        if manifest.version != expected_version:
            failures.append(
                f"install manifest records version {manifest.version}, expected {expected_version}"
            )
    except MailutError as exc:
        failures.append(str(exc))

    if audit_was_active and not systemd.is_active("mailut-audit.service"):
        failures.append("mailut-audit.service was running before the upgrade but is not running now")

    return failures


def record_time() -> str:  # pragma: no cover - trivial
    return to_iso(utcnow())
