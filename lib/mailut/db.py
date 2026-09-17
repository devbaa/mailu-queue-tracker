"""SQLite access: connection settings, automatic migration, backups."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

from . import migrations
from .util import MailutError, to_iso, utcnow

# Mail metadata is sensitive: the database and its directory are owner-only.
DB_MODE = 0o600
DIR_MODE = 0o700


class Database:
    """A connection factory for the audit database.

    Opening the database always leaves it migrated to the current schema, so
    no command has to remember to initialise anything.
    """

    def __init__(self, path, busy_timeout_ms: int = 5000):
        self.path = Path(path)
        self.busy_timeout_ms = int(busy_timeout_ms)

    # -- connecting ----------------------------------------------------------
    def connect(self, *, create: bool = True, migrate: bool = True) -> sqlite3.Connection:
        if not self.path.exists():
            if not create:
                raise MailutError(f"database does not exist: {self.path}")
            self._prepare_directory()
        try:
            conn = sqlite3.connect(
                str(self.path),
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,  # explicit transactions only
                # The collector serves requests on worker threads; every write
                # goes through one lock in mailut.collector.Ingestor, so the
                # connection may cross threads safely.
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise MailutError(f"cannot open database {self.path}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        self._restrict(conn)
        if migrate:
            migrate_database(conn)
        return conn

    def open_readonly(self) -> sqlite3.Connection:
        """Open without creating or migrating (for status/doctor reporting)."""
        if not self.path.exists():
            raise MailutError(f"database does not exist: {self.path}")
        conn = sqlite3.connect(
            f"file:{self.path}?mode=ro", uri=True, timeout=self.busy_timeout_ms / 1000.0
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        return conn

    # -- helpers -------------------------------------------------------------
    def _prepare_directory(self) -> None:
        parent = self.path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            os.chmod(parent, DIR_MODE)
        except OSError as exc:
            raise MailutError(f"cannot create state directory {parent}: {exc}") from exc

    def _restrict(self, conn: sqlite3.Connection) -> None:
        """Keep the database (and its WAL sidecars) owner-readable only."""
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            try:
                if candidate.exists() and stat.S_IMODE(candidate.stat().st_mode) != DB_MODE:
                    os.chmod(candidate, DB_MODE)
            except OSError:
                pass  # a read-only or foreign-owned file is reported by `doctor`

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            try:
                total += candidate.stat().st_size
            except OSError:
                pass
        return total


def schema_version(conn: sqlite3.Connection) -> int:
    """Return the applied schema version (0 when the database is empty)."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return int(row["v"] or 0)


def migrate_database(conn: sqlite3.Connection) -> tuple[int, int]:
    """Apply outstanding migrations.  Returns ``(from_version, to_version)``."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER PRIMARY KEY,
            applied_at  TEXT NOT NULL,
            description TEXT
        )
        """
    )
    current = schema_version(conn)
    if current > migrations.LATEST:
        raise MailutError(
            f"database schema version {current} is newer than this build supports "
            f"({migrations.LATEST}); install a newer {'mailut'} release"
        )
    for version, description, statements in migrations.MIGRATIONS:
        if version <= current:
            continue
        try:
            conn.execute("BEGIN IMMEDIATE")
            for statement in statements:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                (version, to_iso(utcnow()), description),
            )
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            conn.execute("ROLLBACK")
            raise MailutError(f"migration to schema version {version} failed: {exc}") from exc
    return current, migrations.LATEST


def backup(conn: sqlite3.Connection, destination: Path) -> Path:
    """Take a consistent copy using SQLite's own backup API.

    A plain file copy of a live WAL database can be torn; this cannot.
    """
    destination = Path(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(destination.parent, DIR_MODE)
    except OSError as exc:
        raise MailutError(f"cannot create backup directory {destination.parent}: {exc}") from exc

    tmp = destination.with_name(destination.name + ".partial")
    try:
        if tmp.exists():
            tmp.unlink()
        target = sqlite3.connect(str(tmp))
        try:
            os.chmod(tmp, DB_MODE)
            with target:
                conn.backup(target)
        finally:
            target.close()
        os.replace(tmp, destination)
        os.chmod(destination, DB_MODE)
    except (sqlite3.Error, OSError) as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise MailutError(f"database backup to {destination} failed: {exc}") from exc
    return destination
