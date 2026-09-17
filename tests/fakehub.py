"""A local stand-in for GitHub's public release API.

The upgrade tests must never touch the network, so this serves release metadata
and assets from a temporary directory and the tests point
``mailut.release.UPSTREAM_API`` at it.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import shutil
import subprocess
import tarfile
import threading
from pathlib import Path


class FakeHub:
    """Serves ``/releases/...`` metadata and ``/assets/...`` files."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.assets = self.root / "assets"
        self.assets.mkdir(parents=True, exist_ok=True)
        self.releases: list[dict] = []
        self.fail_paths: set[str] = set()
        self.raw_bodies: dict[str, bytes] = {}
        self.requests: list[str] = []

        hub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):  # noqa: N802
                path = self.path.split("?", 1)[0]
                hub.requests.append(path)
                if path in hub.fail_paths:
                    self.send_error(500, "boom")
                    return
                if path in hub.raw_bodies:
                    body = hub.raw_bodies[path]
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == "/releases/latest":
                    stable = [r for r in hub.releases if not r["prerelease"] and not r.get("draft")]
                    if not stable:
                        self.send_error(404, "no releases")
                        return
                    return self._json(hub._entry(stable[-1]))
                if path == "/releases":
                    return self._json([hub._entry(r) for r in reversed(hub.releases)])
                if path.startswith("/releases/tags/"):
                    tag = path.rsplit("/", 1)[1]
                    for entry in hub.releases:
                        if entry["tag"] == tag:
                            return self._json(hub._entry(entry))
                    self.send_error(404, "not found")
                    return
                if path.startswith("/assets/"):
                    name = path[len("/assets/"):]
                    candidate = hub.assets / name
                    if not candidate.is_file():
                        self.send_error(404, "no such asset")
                        return
                    body = candidate.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_error(404, "not found")

            def _json(self, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    @property
    def api(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    # -- building releases --------------------------------------------------
    def _entry(self, release: dict) -> dict:
        return {
            "tag_name": release["tag"],
            "name": release["tag"],
            "prerelease": release["prerelease"],
            "draft": release.get("draft", False),
            "published_at": "2026-09-17T00:00:00Z",
            "html_url": f"{self.api}/releases/{release['tag']}",
            "assets": [
                {"name": name, "browser_download_url": f"{self.api}/assets/{name}"}
                for name in release["assets"]
            ],
        }

    def add_release(self, version, *, assets, prerelease=False, draft=False, tag=None):
        self.releases.append(
            {
                "tag": tag or f"v{version}",
                "version": version,
                "prerelease": prerelease,
                "draft": draft,
                "assets": list(assets),
            }
        )

    def publish_tree(self, source: Path, version: str, *, schema_version=1,
                     mutate=None, checksum_override=None, with_checksums=True,
                     prerelease=False):
        """Build mailut-<version>.tar.gz from a source tree and publish it."""
        build = self.root / f"build-{version}"
        shutil.rmtree(build, ignore_errors=True)
        tree = build / f"mailut-{version}"
        tree.mkdir(parents=True)

        listing = subprocess.run(
            ["git", "-C", str(source), "ls-files", "-z"],
            capture_output=True, check=True,
        ).stdout.split(b"\0")
        for raw in listing:
            if not raw:
                continue
            relative = raw.decode()
            destination = tree / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)

        (tree / "VERSION").write_text(f"{version}\n", encoding="utf-8")
        (tree / "SCHEMA_VERSION").write_text(f"{schema_version}\n", encoding="utf-8")
        if mutate:
            mutate(tree)

        tarball_name = f"mailut-{version}.tar.gz"
        tarball = self.assets / tarball_name
        with tarfile.open(tarball, "w:gz") as archive:
            archive.add(tree, arcname=f"mailut-{version}")

        assets = [tarball_name]
        if with_checksums:
            digest = checksum_override or hashlib.sha256(tarball.read_bytes()).hexdigest()
            (self.assets / "SHA256SUMS").write_text(
                f"{digest}  {tarball_name}\n", encoding="utf-8"
            )
            assets.append("SHA256SUMS")
        self.add_release(version, assets=assets, prerelease=prerelease)
        return tarball
