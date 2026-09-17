"""The install manifest: the authoritative list of application-owned files.

``make install`` generates it by walking what it has just installed (see
``tools/gen-manifest.py``), so there is exactly one list and it cannot drift
from what the Makefile actually does.  ``mailut upgrade`` and
``mailut uninstall`` both work from it, which is why neither needs the source
checkout it was installed from.

Mutable operator data — the configuration file, the database, retained
messages and database backups — is deliberately *not* in the manifest.  It is
listed under ``preserved`` so that uninstall can report what it is keeping.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .. import release
from ..util import MailutError

MANIFEST_VERSION = 1

# Ordered most-specific-first so uninstall removes files before directories.
FILE_TYPES = ("program", "library", "data", "man", "unit", "manifest")


class Manifest:
    def __init__(self, data: dict, path: Path):
        self.data = data
        self.path = path

    # -- loading -------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path | None = None) -> "Manifest":
        path = Path(path) if path else release.manifest_path()
        if not path.is_file():
            raise MailutError(
                f"install manifest not found at {path}: this does not look like an "
                f"installed {release.COMMAND_NAME} (install it with `make install`)"
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MailutError(f"install manifest {path} is unreadable: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("files"), list):
            raise MailutError(f"install manifest {path} is malformed: no file list")
        if data.get("manifest_version") != MANIFEST_VERSION:
            raise MailutError(
                f"install manifest {path} has unsupported version "
                f"{data.get('manifest_version')!r} (expected {MANIFEST_VERSION})"
            )
        for entry in data["files"]:
            if not isinstance(entry, dict) or not entry.get("path"):
                raise MailutError(f"install manifest {path} is malformed: bad file entry")
        return cls(_rebase(data), path)

    # -- accessors -----------------------------------------------------------
    @property
    def version(self) -> str:
        return str(self.data.get("version") or "0.0.0")

    @property
    def layout(self) -> dict:
        """Where the files are, as this process should address them."""
        layout = dict(release.DEFAULT_LAYOUT)
        layout.update(self.data.get("layout") or {})
        return layout

    @property
    def install_layout(self) -> dict:
        """The layout as `make install` variables, without any staging root.

        Under MAILUT_ROOT the paths above are re-based for addressing; the
        Makefile takes DESTDIR separately, so it must get the real prefixes.
        """
        layout = dict(release.DEFAULT_LAYOUT)
        layout.update(self.data.get("layout_raw") or self.data.get("layout") or {})
        return layout

    @property
    def units(self) -> list[str]:
        return [str(u) for u in (self.data.get("units") or [])]

    @property
    def preserved(self) -> list[str]:
        return [str(p) for p in (self.data.get("preserved") or [])]

    def files(self, *, kinds=None) -> list[dict]:
        entries = self.data["files"]
        if kinds is None:
            return list(entries)
        return [e for e in entries if e.get("type") in kinds]

    def directories(self) -> list[str]:
        return [str(d) for d in (self.data.get("directories") or [])]

    # -- verification --------------------------------------------------------
    def verify(self) -> dict:
        """Compare installed files against the manifest.

        Returns ``{"missing": [...], "modified": [...], "ok": n}``.  A file
        without a recorded hash (the manifest itself) is only checked for
        existence.
        """
        missing: list[str] = []
        modified: list[str] = []
        ok = 0
        for entry in self.data["files"]:
            path = Path(entry["path"])
            if not path.exists():
                missing.append(str(path))
                continue
            digest = entry.get("sha256")
            if not digest:
                ok += 1
                continue
            if sha256_file(path) != digest:
                modified.append(str(path))
            else:
                ok += 1
        return {"missing": missing, "modified": modified, "ok": ok}


def _rebase(data: dict) -> dict:
    """Re-base manifest paths under ``MAILUT_ROOT`` when staging (tests).

    The manifest always records the real runtime paths; only a staged install
    needs them moved, and only the test harness sets that variable.
    """
    import os

    root = os.environ.get("MAILUT_ROOT")
    if not root:
        return data
    base = Path(root)

    def move(value: str) -> str:
        return str(base / str(value).lstrip("/"))

    data = dict(data)
    data["layout_raw"] = dict(data.get("layout") or {})
    data["files"] = [{**entry, "path": move(entry["path"])} for entry in data["files"]]
    data["directories"] = [move(d) for d in (data.get("directories") or [])]
    data["preserved"] = [move(p) for p in (data.get("preserved") or [])]
    data["layout"] = {k: move(v) for k, v in (data.get("layout") or {}).items()}
    return data


def sha256_file(path: str | Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()
