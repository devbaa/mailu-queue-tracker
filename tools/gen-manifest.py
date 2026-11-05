#!/usr/bin/env python3
"""Generate the install manifest from what `make install` has just staged.

The manifest is derived from the installed tree rather than from a second
hand-maintained file list, so the Makefile and the application can never
disagree about which files this release owns.

Paths are recorded as they will exist at runtime: DESTDIR is stripped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

MANIFEST_VERSION = 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_path(path: Path, destdir: str) -> str:
    text = str(path)
    if destdir and text.startswith(destdir.rstrip("/")):
        text = text[len(destdir.rstrip("/")):]
    return text or "/"


def walk(root: Path):
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destdir", default="", help="staging prefix to strip from paths")
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--layout", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--unit", action="append", default=[], metavar="NAME")
    parser.add_argument("--preserve", action="append", default=[], metavar="PATH")
    parser.add_argument("--owned", action="append", default=[], metavar="TYPE:PATH",
                        help="a staged file or directory this release owns")
    parser.add_argument("--directory", action="append", default=[], metavar="PATH",
                        help="a runtime directory this release owns (removed when empty)")
    args = parser.parse_args(argv)

    layout = {}
    for item in args.layout:
        key, _, value = item.partition("=")
        layout[key] = value

    files = []
    seen = set()
    for item in args.owned:
        kind, _, target = item.partition(":")
        root = Path(target)
        for path in walk(root):
            runtime = runtime_path(path, args.destdir)
            if runtime in seen:
                continue
            seen.add(runtime)
            files.append(
                {
                    "path": runtime,
                    "type": kind,
                    "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                    "sha256": sha256(path),
                }
            )

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "project": "Mailu Tools",
        "command": "mailut",
        "version": args.version,
        "layout": layout,
        "units": args.unit,
        "preserved": args.preserve,
        "directories": args.directory,
        "files": files,
    }
    # The manifest cannot hash itself; it is recorded so uninstall removes it.
    manifest["files"].append(
        {"path": runtime_path(Path(args.output), args.destdir), "type": "manifest",
         "mode": "0o644", "sha256": None}
    )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o644)
    print(f"install manifest: {len(manifest['files'])} file(s) -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
