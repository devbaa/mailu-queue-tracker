"""An OS-level lock that serialises upgrade, uninstall and schema migration.

``flock`` is used rather than a PID file: the kernel releases it when the
process dies, so a crashed upgrade cannot wedge every later one.
"""

from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path

from .. import release
from ..util import LockedError, MailutError

LOCK_NAME = "lifecycle.lock"


class LifecycleLock:
    """Context manager holding an exclusive, non-blocking lock."""

    def __init__(self, run_dir: str | Path | None = None):
        self.path = Path(run_dir or release.layout()["rundir"]) / LOCK_NAME
        self._fd: int | None = None

    def __enter__(self) -> "LifecycleLock":
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o755)
        except OSError as exc:
            raise MailutError(f"cannot create {self.path.parent}: {exc}") from exc
        try:
            self._fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o644)
        except OSError as exc:
            raise MailutError(f"cannot open lock file {self.path}: {exc}") from exc
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._fd)
            self._fd = None
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise LockedError(
                    f"Another {release.COMMAND_NAME} lifecycle operation is currently running."
                ) from exc
            raise MailutError(f"cannot lock {self.path}: {exc}") from exc
        try:
            os.ftruncate(self._fd, 0)
            os.write(self._fd, f"{os.getpid()}\n".encode("ascii"))
        except OSError:
            pass
        return self

    def __exit__(self, *_exc) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None
