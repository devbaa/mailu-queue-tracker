"""Immutable release and installation metadata for Mailu Tools.

This module is the single place that knows

  * the product / command names,
  * the canonical public upstream repository,
  * how to find the version of the *installed* application, and
  * the filesystem layout the application was installed with.

Everything the lifecycle commands (``mailut version``, ``mailut upgrade``,
``mailut uninstall``) need must be answerable from here without a git
checkout, without network access and without the directory ``make install``
was originally run from.

``make install`` writes ``buildinfo.json`` next to this file; that file is the
authoritative source once installed.  In a source checkout we fall back to the
``VERSION`` file at the top of the tree (plus ``git describe`` when available,
purely as a convenience for developers).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

PROJECT_NAME = "Mailu Tools"
COMMAND_NAME = "mailut"

# Canonical public upstream.  Defined once; never spell the URL out elsewhere.
UPSTREAM_OWNER = "devbaa"
UPSTREAM_REPO = "mailu-queue-tracker"
UPSTREAM_URL = f"https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO}"
UPSTREAM_API = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}"

# Testing aid: the release API can be redirected, but only together with
# MAILUT_ROOT — that is, only for an installation staged under a throwaway
# root. On a real installation this is ignored, so no environment variable can
# point an upgrade at a different upstream.
if os.environ.get("MAILUT_ROOT") and os.environ.get("MAILUT_UPSTREAM_API"):
    UPSTREAM_API = os.environ["MAILUT_UPSTREAM_API"]

# Release artifacts published with every GitHub release.
RELEASE_TARBALL_TEMPLATE = "mailut-{version}.tar.gz"
RELEASE_CHECKSUM_ASSET = "SHA256SUMS"

# Bumped whenever the SQLite schema changes; see mailut.migrations.
SCHEMA_VERSION = 1

# Default (upstream) installation layout.  Overridden by buildinfo.json.
DEFAULT_LAYOUT = {
    "prefix": "/usr/local",
    "sysconfdir": "/etc",
    "localstatedir": "/var",
    "sbindir": "/usr/local/sbin",
    "libdir": "/usr/local/lib/mailut",
    "datadir": "/usr/local/share/mailut",
    "mandir": "/usr/local/share/man",
    "systemd_unit_dir": "/etc/systemd/system",
    "confdir": "/etc/mailut",
    "statedir": "/var/lib/mailut",
    "rundir": "/run/mailut",
}

# Units owned by this application, in the order they should be stopped.
OWNED_UNITS = (
    "mailut-audit.service",
    "mailut-watch.timer",
    "mailut-watch.service",
    "mailut-purge.timer",
    "mailut-purge.service",
)

_PKG_DIR = Path(__file__).resolve().parent
_BUILDINFO_PATH = _PKG_DIR / "buildinfo.json"

_cache: dict | None = None


def _source_tree_root() -> Path | None:
    """Return the checkout root when running from a source tree, else None."""
    root = _PKG_DIR.parent.parent  # lib/mailut/ -> lib/ -> <root>
    if (root / "VERSION").is_file() and (root / "Makefile").is_file():
        return root
    return None


def _git_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=7", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = out.stdout.strip()
    return commit or None


def buildinfo() -> dict:
    """Return installation metadata (cached).

    Keys: version, commit, built_at, installed, layout, manifest.
    """
    global _cache
    if _cache is not None:
        return _cache

    info: dict = {
        "version": "0.0.0",
        "commit": None,
        "built_at": None,
        "installed": False,
        "layout": dict(DEFAULT_LAYOUT),
    }

    if _BUILDINFO_PATH.is_file():
        try:
            data = json.loads(_BUILDINFO_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            info["version"] = str(data.get("version") or info["version"])
            info["commit"] = data.get("commit") or None
            info["built_at"] = data.get("built_at") or None
            info["installed"] = True
            layout = data.get("layout")
            if isinstance(layout, dict):
                info["layout"].update({k: str(v) for k, v in layout.items()})
    else:
        root = _source_tree_root()
        if root is not None:
            try:
                info["version"] = (root / "VERSION").read_text(encoding="utf-8").strip()
            except OSError:
                pass
            info["commit"] = _git_commit(root)

    info["layout"] = _apply_env_overrides(info["layout"])
    info["manifest"] = str(Path(info["layout"]["datadir"]) / "install-manifest.json")
    _cache = info
    return info


def staged_root() -> str | None:
    """The staging root this process addresses, or None for a real install.

    ``MAILUT_ROOT`` re-bases *every* layout path, so a process running under it
    cannot reach the real installation at all.  The test suite uses it to
    exercise upgrade and uninstall without touching the filesystem; it is
    documented in mailut(8) as a testing aid only.
    """
    return os.environ.get("MAILUT_ROOT") or None


def _apply_env_overrides(layout: dict) -> dict:
    root = staged_root()
    if not root:
        return layout
    base = Path(root)
    return {k: str(base / str(v).lstrip("/")) for k, v in layout.items()}


def version() -> str:
    return buildinfo()["version"]


def version_display() -> str:
    """``1.0.0`` or ``1.0.0 (a1b2c3d)`` — the version without the command name."""
    info = buildinfo()
    if info["commit"]:
        return f"{info['version']} ({info['commit']})"
    return str(info["version"])


def version_string() -> str:
    """What `mailut version` prints: ``mailut 1.0.0 (a1b2c3d)``."""
    return f"{COMMAND_NAME} {version_display()}"


def layout() -> dict:
    return buildinfo()["layout"]


def manifest_path() -> Path:
    return Path(buildinfo()["manifest"])


def is_installed() -> bool:
    return bool(buildinfo()["installed"])
