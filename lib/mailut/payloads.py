"""Clean-up of stored headers and raw messages.

Nothing writes these any more: mailut collects from the Mailu container logs,
which carry no message content.  The ``audit_payloads`` table remains part of
the schema, so purge and uninstall still know how to remove a payload and its
file safely -- never outside the configured message directory.
"""

from __future__ import annotations

from pathlib import Path

from .util import MailutError



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
