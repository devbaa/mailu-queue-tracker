"""Storage for retained headers and raw RFC822 messages.

Headers are small and are kept inline in ``audit_payloads.content``.  Complete
messages are gzipped into ``<state_dir>/messages/YYYY/MM/DD/`` under a
generated name — never a name derived from the sender, subject or any other
attacker-controlled text — and only referenced from SQLite.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import secrets
from pathlib import Path

from .util import MailutError

FILE_MODE = 0o600
DIR_MODE = 0o700


def _safe_child(root: Path, *parts: str) -> Path:
    """Join under ``root`` and refuse anything that escapes it."""
    candidate = root.joinpath(*parts)
    root_resolved = root.resolve() if root.exists() else root.absolute()
    resolved = candidate.absolute()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise MailutError(f"refusing to write outside the message store: {candidate}") from exc
    return candidate


def store_message(message_dir: Path, occurred_at, data: bytes) -> dict:
    """Write one gzipped message and return its payload metadata."""
    message_dir = Path(message_dir)
    day = _safe_child(
        message_dir,
        f"{occurred_at.year:04d}",
        f"{occurred_at.month:02d}",
        f"{occurred_at.day:02d}",
    )
    try:
        day.mkdir(parents=True, exist_ok=True)
        for directory in (message_dir, day.parent.parent, day.parent, day):
            os.chmod(directory, DIR_MODE)
    except OSError as exc:
        raise MailutError(f"cannot create message directory {day}: {exc}") from exc

    digest = hashlib.sha256(data).hexdigest()
    name = f"{occurred_at.strftime('%H%M%S')}-{secrets.token_hex(8)}.eml.gz"
    path = _safe_child(day, name)

    tmp = path.with_name(path.name + ".partial")
    try:
        # mtime=0 keeps the gzip container byte-stable for a given input.
        with open(os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE), "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                gz.write(data)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise MailutError(f"cannot store message payload: {exc}") from exc

    try:
        stored = path.stat().st_size
    except OSError:
        stored = None
    return {
        "path": str(path),
        "stored_bytes": stored,
        "original_bytes": len(data),
        "sha256": digest,
    }


def read_message(path: str | Path) -> bytes:
    try:
        with gzip.open(str(path), "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise MailutError(f"cannot read message payload {path}: {exc}") from exc


def remove_file(path: str | Path, message_dir: Path) -> bool:
    """Delete one stored payload file.

    Returns True when the file is gone afterwards (including when it was
    already missing, which keeps purging idempotent).  Refuses paths outside
    the configured message directory.
    """
    target = Path(path)
    root = Path(message_dir).absolute()
    try:
        target.absolute().relative_to(root)
    except ValueError as exc:
        raise MailutError(f"refusing to delete a payload outside {root}: {target}") from exc
    try:
        target.unlink()
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise MailutError(f"cannot delete payload {target}: {exc}") from exc
    return True


def prune_empty_dirs(message_dir: Path) -> int:
    """Remove day/month/year directories left empty by a purge."""
    root = Path(message_dir)
    if not root.is_dir():
        return 0
    removed = 0
    for directory in sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True):
        try:
            next(directory.iterdir())
        except StopIteration:
            try:
                directory.rmdir()
                removed += 1
            except OSError:
                pass
        except OSError:
            pass
    return removed


def storage_bytes(message_dir: Path) -> int:
    total = 0
    root = Path(message_dir)
    if not root.is_dir():
        return 0
    for path in root.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            pass
    return total
