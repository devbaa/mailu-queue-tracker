"""Safe extraction of a downloaded release tarball.

A release artifact is treated as untrusted until it has been checksum-verified
*and* every member has been inspected.  Python's ``data`` extraction filter
(3.12+) is applied where available, but the checks below are performed
regardless so the behaviour is identical on older interpreters.
"""

from __future__ import annotations

import hashlib
import tarfile
from pathlib import Path

from ..util import MailutError


class ArchiveError(MailutError):
    pass


def sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path: Path, expected: str) -> None:
    """Fail closed: there is deliberately no way to skip this."""
    actual = sha256(path)
    if actual.lower() != str(expected).lower():
        raise ArchiveError(
            f"checksum mismatch for {path.name}: expected {expected}, got {actual}. "
            "The download was not installed."
        )


def _check_member(member: tarfile.TarInfo) -> None:
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        raise ArchiveError(f"archive member uses an absolute path: {name}")
    parts = Path(name).parts
    if ".." in parts:
        raise ArchiveError(f"archive member escapes the extraction directory: {name}")
    if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
        raise ArchiveError(f"archive contains a device or fifo entry: {name}")
    if member.issym() or member.islnk():
        target = member.linkname
        if target.startswith("/"):
            raise ArchiveError(f"archive contains an absolute link: {name} -> {target}")
        resolved = (Path(name).parent / target).parts
        depth = 0
        for part in resolved:
            if part == "..":
                depth -= 1
                if depth < 0:
                    raise ArchiveError(f"archive link escapes the extraction directory: {name} -> {target}")
            elif part not in (".", ""):
                depth += 1
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ArchiveError(f"archive contains an unsupported entry type: {name}")


def extract(tarball: Path, destination: Path, *, max_total_bytes: int = 512 * 1024 * 1024) -> Path:
    """Validate every member, then extract into ``destination``.

    Returns the single top-level directory of the archive.
    """
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(str(tarball), "r:*") as archive:
            members = archive.getmembers()
            total = 0
            roots = set()
            for member in members:
                _check_member(member)
                total += max(member.size, 0)
                if total > max_total_bytes:
                    raise ArchiveError(f"archive expands to more than {max_total_bytes} bytes")
                first = Path(member.name).parts
                if first:
                    roots.add(first[0])
            if len(roots) != 1:
                raise ArchiveError(
                    f"archive must contain exactly one top-level directory, found {len(roots)}"
                )
            try:
                archive.extractall(str(destination), members=members, filter="data")
            except TypeError:  # Python < 3.12 has no extraction filters
                archive.extractall(str(destination), members=members)  # noqa: S202 - members validated above
    except tarfile.TarError as exc:
        raise ArchiveError(f"cannot read release archive {tarball.name}: {exc}") from exc
    except OSError as exc:
        raise ArchiveError(f"cannot extract release archive {tarball.name}: {exc}") from exc

    root = destination / roots.pop()
    if not root.is_dir():
        raise ArchiveError("release archive did not contain the expected directory")
    return root


REQUIRED_MEMBERS = ("Makefile", "VERSION", "SCHEMA_VERSION", "bin/mailut", "lib/mailut/cli.py")


def validate_tree(root: Path, *, expected_version: str | None = None) -> dict:
    """Check that an unpacked artifact really is a Mailu Tools release tree."""
    for name in REQUIRED_MEMBERS:
        if not (root / name).exists():
            raise ArchiveError(f"release archive is missing {name}: refusing to install it")
    try:
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
        schema = int((root / "SCHEMA_VERSION").read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        raise ArchiveError(f"release archive has unreadable version metadata: {exc}") from exc
    if expected_version and version != expected_version:
        raise ArchiveError(
            f"release archive declares version {version} but {expected_version} was requested"
        )
    return {"version": version, "schema_version": schema, "root": root}
