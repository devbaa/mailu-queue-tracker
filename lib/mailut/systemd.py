"""Thin, read-mostly wrapper around systemctl.

Every call is an argument vector; failures are reported rather than raised, so
a host without systemd degrades to "unknown" instead of breaking commands.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from . import release


def available() -> bool:
    if os.environ.get("MAILUT_NO_SYSTEMD"):
        return False
    return shutil.which("systemctl") is not None and os.path.isdir("/run/systemd/system")


def _run(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def show(unit: str, properties=("ActiveState", "UnitFileState", "SubState")) -> dict:
    if not available():
        return {}
    try:
        proc = _run(["show", unit, "--property=" + ",".join(properties), "--no-pager"])
    except (OSError, subprocess.SubprocessError):
        return {}
    values = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    return values


def is_active(unit: str) -> bool:
    return show(unit).get("ActiveState") == "active"


def is_enabled(unit: str) -> bool:
    return show(unit).get("UnitFileState") in ("enabled", "enabled-runtime", "static")


def unit_state(unit: str) -> str:
    values = show(unit)
    if not values:
        return "unknown"
    active = values.get("ActiveState", "unknown")
    enabled = values.get("UnitFileState", "not-installed") or "not-installed"
    return f"{active} ({enabled})"


def daemon_reload() -> bool:
    if not available():
        return False
    try:
        return _run(["daemon-reload"], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def stop(unit: str) -> bool:
    if not available():
        return False
    try:
        return _run(["stop", unit], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def start(unit: str) -> bool:
    if not available():
        return False
    try:
        return _run(["start", unit], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def restart(unit: str) -> bool:
    if not available():
        return False
    try:
        return _run(["restart", unit], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def disable(unit: str) -> bool:
    if not available():
        return False
    try:
        return _run(["disable", unit], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def owned_unit_states() -> dict:
    """State of every unit this application owns (never touches Mailu's own)."""
    return {unit: unit_state(unit) for unit in release.OWNED_UNITS}
