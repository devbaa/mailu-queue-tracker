"""Public GitHub release discovery and artifact download.

Everything here uses unauthenticated public HTTPS through the Python standard
library, so no GitHub account, token, ``gh`` CLI or SSH key is ever required.
``HTTPS_PROXY``/``NO_PROXY`` are honoured because urllib reads them.

The network is contacted only by the lifecycle commands: ordinary commands
never call into this module.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from .. import release
from ..util import MailutError

USER_AGENT = f"{release.COMMAND_NAME}/{release.version()} (+{release.UPSTREAM_URL})"
TIMEOUT = 30
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")

# A release whose tag or name carries any of these is a prerelease even if
# GitHub's own flag was not set.
_PRERELEASE_HINTS = ("alpha", "beta", "rc", "dev", "pre", "snapshot")


class UpstreamError(MailutError):
    """Release discovery or download failed."""


def parse_version(text: str) -> tuple:
    """Parse ``1.4.0`` / ``v1.4.0`` / ``1.4.0-rc.1`` into a sortable key."""
    value = str(text).strip()
    if value.startswith("v"):
        value = value[1:]
    match = _VERSION_RE.match(value)
    if not match:
        raise UpstreamError(f"not a semantic version: {text!r}")
    major, minor, patch, pre = match.groups()
    # A prerelease sorts before its release: (1,4,0,0,...) < (1,4,0,1)
    if pre:
        return (int(major), int(minor), int(patch), 0, pre)
    return (int(major), int(minor), int(patch), 1, "")


def normalize_version(text: str) -> str:
    value = str(text).strip()
    return value[1:] if value.startswith("v") else value


def is_prerelease(entry: dict) -> bool:
    if entry.get("prerelease") or entry.get("draft"):
        return True
    text = f"{entry.get('tag_name', '')} {entry.get('name', '')}".lower()
    return any(hint in text for hint in _PRERELEASE_HINTS)


def _open(url: str, *, accept: str = "application/vnd.github+json"):
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": accept}
    )
    try:
        return urllib.request.urlopen(request, timeout=TIMEOUT)  # noqa: S310 - https only, fixed host
    except urllib.error.HTTPError as exc:
        if exc.code == 403 and "rate limit" in str(exc.reason).lower():
            raise UpstreamError(
                "GitHub rate-limited this host. Unauthenticated release lookups are "
                "limited per IP; try again later."
            ) from exc
        if exc.code == 404:
            raise UpstreamError(f"not found: {url}") from exc
        raise UpstreamError(f"GitHub returned HTTP {exc.code} for {url}") from exc
    except urllib.error.URLError as exc:
        raise UpstreamError(f"cannot reach GitHub ({exc.reason})") from exc
    except OSError as exc:
        raise UpstreamError(f"cannot reach GitHub ({exc})") from exc


def _get_json(url: str):
    with _open(url) as response:
        raw = response.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise UpstreamError(f"release metadata from {url} is implausibly large")
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise UpstreamError(f"release metadata from {url} is malformed: {exc}") from exc


def _as_release(entry) -> dict:
    if not isinstance(entry, dict) or not entry.get("tag_name"):
        raise UpstreamError("release metadata is malformed: no tag_name")
    try:
        version = normalize_version(entry["tag_name"])
        parse_version(version)
    except UpstreamError as exc:
        raise UpstreamError(f"release metadata is malformed: {exc}") from exc
    assets = {}
    for asset in entry.get("assets") or []:
        if isinstance(asset, dict) and asset.get("name") and asset.get("browser_download_url"):
            assets[str(asset["name"])] = str(asset["browser_download_url"])
    return {
        "version": version,
        "tag": entry["tag_name"],
        "prerelease": is_prerelease(entry),
        "published_at": entry.get("published_at"),
        "assets": assets,
        "html_url": entry.get("html_url"),
    }


def latest_release(*, allow_prerelease: bool = False) -> dict:
    """Discover the newest release.

    One request in the common case: GitHub's ``releases/latest`` already
    excludes prereleases and drafts.  The full list is fetched only when
    prereleases were explicitly asked for.
    """
    if not allow_prerelease:
        entry = _as_release(_get_json(f"{release.UPSTREAM_API}/releases/latest"))
        if entry["prerelease"]:
            # GitHub says it is the latest but the tag looks like a prerelease;
            # fall through to the list rather than installing it.
            return _newest_stable(_get_json(f"{release.UPSTREAM_API}/releases?per_page=30"))
        return entry

    entries = _get_json(f"{release.UPSTREAM_API}/releases?per_page=30")
    if not isinstance(entries, list) or not entries:
        raise UpstreamError("no releases are published upstream")
    candidates = [_as_release(e) for e in entries if isinstance(e, dict) and not e.get("draft")]
    if not candidates:
        raise UpstreamError("no installable releases are published upstream")
    return max(candidates, key=lambda r: parse_version(r["version"]))


def _newest_stable(entries) -> dict:
    if not isinstance(entries, list):
        raise UpstreamError("release metadata is malformed: expected a list")
    candidates = [
        _as_release(e)
        for e in entries
        if isinstance(e, dict) and not e.get("draft")
    ]
    stable = [c for c in candidates if not c["prerelease"]]
    if not stable:
        raise UpstreamError("no stable release is published upstream")
    return max(stable, key=lambda r: parse_version(r["version"]))


def release_by_version(version: str) -> dict:
    """Look up one published release by version.

    Only a version is accepted — never a URL — so ``--version`` can never point
    the upgrader at arbitrary remote code.
    """
    wanted = normalize_version(version)
    parse_version(wanted)  # rejects anything that is not a semantic version
    for tag in (f"v{wanted}", wanted):
        try:
            return _as_release(_get_json(f"{release.UPSTREAM_API}/releases/tags/{tag}"))
        except UpstreamError as exc:
            if "not found" not in str(exc):
                raise
    raise UpstreamError(f"release {wanted} is not published at {release.UPSTREAM_URL}")


def asset_names(version: str) -> tuple[str, str]:
    return release.RELEASE_TARBALL_TEMPLATE.format(version=version), release.RELEASE_CHECKSUM_ASSET


def download(url: str, destination: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> Path:
    """Stream one asset to disk, refusing an implausibly large transfer."""
    destination = Path(destination)
    written = 0
    try:
        with _open(url, accept="application/octet-stream") as response, open(destination, "wb") as handle:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise UpstreamError(f"download from {url} exceeded {max_bytes} bytes")
                handle.write(chunk)
    except OSError as exc:
        raise UpstreamError(f"download of {url} failed: {exc}") from exc
    if written == 0:
        raise UpstreamError(f"download of {url} was empty")
    return destination


def parse_checksums(text: str) -> dict:
    """Parse a ``sha256sum`` style SHA256SUMS file."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, name = parts
        if len(digest) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            continue
        sums[name.lstrip("*")] = digest.lower()
    return sums
