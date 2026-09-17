#!/usr/bin/env python3
"""Write the buildinfo.json that lets an installed mailut know its own version.

After installation there is no VERSION file and no git checkout, so this is
where `mailut version`, `mailut upgrade` and `mailut uninstall` learn what is
installed and where.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path


def git_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() or None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--layout", action="append", default=[], metavar="KEY=VALUE")
    args = parser.parse_args(argv)

    layout = {}
    for item in args.layout:
        key, _, value = item.partition("=")
        layout[key] = value

    payload = {
        "version": args.version,
        "commit": git_commit(Path(args.source_root)),
        "built_at": datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "layout": layout,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o644)
    return 0


if __name__ == "__main__":
    sys.exit(main())
