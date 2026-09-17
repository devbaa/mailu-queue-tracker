"""Talking to the Mailu containers.

Every invocation is an argument vector handed straight to :mod:`subprocess`;
no shell is involved, so an envelope address or a HELO name can never be
interpreted as a command.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from .util import MailutError

# Test hooks: when set, these replace the docker invocations with a fixture.
ENV_QUEUE = "MAILUT_QUEUE_FILE"
ENV_SMTP_LOG = "MAILUT_SMTP_LOG_FILE"
ENV_FRONT_LOG = "MAILUT_FRONT_LOG_FILE"
ENV_POSTSUPER_OUT = "MAILUT_POSTSUPER_OUT"
ENV_BRIDGE_GATEWAYS = "MAILUT_BRIDGE_GATEWAYS"


class Mailu:
    def __init__(self, config):
        self.config = config
        self.compose_dir = Path(config.get("mailu", "compose_dir"))
        self.compose = config.compose_argv
        self.smtp_service = config.get("mailu", "smtp_service")
        self.front_service = config.get("mailu", "front_service")
        self.antispam_service = config.get("mailu", "antispam_service")

    @property
    def rspamd_override_dir(self):
        """Where Mailu expects Rspamd overrides to be dropped."""
        return self.compose_dir / "overrides" / "rspamd"

    @property
    def docker_argv(self) -> list[str]:
        """The plain ``docker`` command, for subcommands Compose does not have."""
        first = self.compose[0]
        if Path(first).name == "docker":
            return [first]
        return ["docker"]

    def service_container(self, service: str) -> tuple[str | None, str | None]:
        """Container id of a running Compose service.  Returns (id, error)."""
        try:
            proc = self._run(["ps", "-q", service], timeout=30)
        except MailutError as exc:
            return None, str(exc)
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()
            return None, detail[-1] if detail else f"docker compose ps {service} failed"
        ids = proc.stdout.split()
        if not ids:
            return None, f"no running container for the {service} service"
        return ids[0], None

    def service_networks(self, service: str) -> tuple[set, str | None]:
        """Names of the Docker networks ``service``'s container is attached to."""
        container, error = self.service_container(service)
        if error:
            return set(), error
        try:
            proc = subprocess.run(
                [*self.docker_argv, "inspect", "--format",
                 "{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}",
                 container],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return set(), f"cannot inspect the {service} container: {exc}"
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()
            return set(), detail[-1] if detail else f"docker inspect {service} failed"
        return {name.strip() for name in proc.stdout.split() if name.strip()}, None

    def service_bridge_gateways(self, service: str) -> tuple[set, str | None]:
        """Gateways of the *bridge* networks attached to ``service``.

        Both halves of that description matter, because this is what decides
        whether an unauthenticated port is safe to open.

        *bridge*: only the bridge driver gives the "reachable from containers on
        this host, and from nothing off it" property.  A ``macvlan`` or
        ``ipvlan`` network attaches containers straight to the physical LAN and
        its configured gateway is typically the real upstream router -- Docker's
        own documentation uses examples like ``--gateway=192.168.32.254`` -- and
        Docker does not install the packet-filtering rules there that it
        installs for bridge networks.  An overlay gateway spans hosts.  Treating
        any of those as host-local would be wrong.

        *attached to service*: a gateway belonging to some unrelated Docker
        project on the same machine is no use either.  The antispam container
        cannot reach it, so approving it would produce a collector that Rspamd
        cannot post to.

        Returns ``(addresses, error)``; ``error`` set means discovery could not
        be performed, which is not the same as "no such gateway exists".
        """
        fixture = os.environ.get(ENV_BRIDGE_GATEWAYS)
        if fixture is not None:
            if fixture.startswith("!"):
                return set(), fixture[1:] or "discovery unavailable"
            return {a.strip() for a in fixture.split(",") if a.strip()}, None
        networks, error = self.service_networks(service)
        if error:
            return set(), error
        if not networks:
            return set(), None
        try:
            proc = subprocess.run(
                [*self.docker_argv, "network", "inspect", "--format",
                 "{{.Driver}}{{range .IPAM.Config}} {{.Gateway}}{{end}}", *sorted(networks)],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return set(), f"cannot inspect docker networks: {exc}"
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()
            return set(), detail[-1] if detail else "docker network inspect failed"
        gateways = set()
        for line in proc.stdout.splitlines():
            fields = line.split()
            if not fields or fields[0] != "bridge":
                continue  # macvlan, ipvlan, overlay: not host-local
            for candidate in fields[1:]:
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                gateways.add(candidate)
        return gateways, None

    # -- primitives ----------------------------------------------------------
    def available(self) -> bool:
        return shutil.which(self.compose[0]) is not None

    def compose_dir_ok(self) -> bool:
        if not self.compose_dir.is_dir():
            return False
        return any(
            (self.compose_dir / name).is_file()
            for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
        )

    def _run(self, args: list[str], *, timeout: int = 120, check: bool = False) -> subprocess.CompletedProcess:
        argv = [*self.compose, *args]
        try:
            proc = subprocess.run(
                argv,
                cwd=str(self.compose_dir) if self.compose_dir.is_dir() else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise MailutError(f"{self.compose[0]} not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise MailutError(f"timed out after {timeout}s running: {' '.join(argv)}") from exc
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise MailutError(
                f"command failed ({proc.returncode}): {' '.join(argv)}"
                + (f": {detail[-1]}" if detail else "")
            )
        return proc

    def exec_service(self, service: str, args: list[str], *, stdin: str | None = None,
                     timeout: int = 120) -> subprocess.CompletedProcess:
        argv = [*self.compose, "exec", "-T", service, *args]
        try:
            return subprocess.run(
                argv,
                cwd=str(self.compose_dir) if self.compose_dir.is_dir() else None,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise MailutError(f"{self.compose[0]} not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise MailutError(f"timed out after {timeout}s running: {' '.join(argv)}") from exc

    # -- data sources --------------------------------------------------------
    def queue_json(self) -> list[dict]:
        """Return the Postfix queue as a list of dicts (``postqueue -j``)."""
        fixture = os.environ.get(ENV_QUEUE)
        if fixture:
            raw = Path(fixture).read_text(encoding="utf-8", errors="replace")
        else:
            proc = self.exec_service(self.smtp_service, ["postqueue", "-j"])
            if proc.returncode != 0:
                detail = (proc.stderr or "").strip().splitlines()
                raise MailutError(
                    "cannot read the Postfix queue"
                    + (f": {detail[-1]}" if detail else " (is the smtp container running?)")
                )
            raw = proc.stdout
        entries = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue  # tolerate a partial line rather than failing the command
            if isinstance(entry, dict):
                entries.append(entry)
        return entries

    def postsuper(self, operation: str, queue_ids: list[str]) -> str:
        """Run ``postsuper -d|-h|-H -`` with the ids on stdin."""
        if operation not in ("-d", "-h", "-H"):
            raise MailutError(f"unsupported postsuper operation {operation!r}")
        payload = "".join(f"{qid}\n" for qid in queue_ids)
        fixture = os.environ.get(ENV_POSTSUPER_OUT)
        if fixture:
            Path(fixture).write_text(payload, encoding="utf-8")
            return f"(captured {len(queue_ids)} queue ids)"
        proc = self.exec_service(self.smtp_service, ["postsuper", operation, "-"], stdin=payload)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise MailutError("postsuper failed" + (f": {detail[-1]}" if detail else ""))
        return (proc.stderr or proc.stdout or "").strip()

    def logs(self, service: str, *, since: str | None = None, timestamps: bool = True,
             timeout: int = 180) -> str:
        fixture = os.environ.get(
            ENV_SMTP_LOG if service == self.smtp_service else ENV_FRONT_LOG
        )
        if fixture:
            return Path(fixture).read_text(encoding="utf-8", errors="replace")
        args = ["logs", "--no-color"]
        if timestamps:
            args.append("--timestamps")
        if since:
            args.append(f"--since={since}")
        args.append(service)
        proc = self._run(args, timeout=timeout)
        if proc.returncode != 0 and not proc.stdout:
            detail = (proc.stderr or "").strip().splitlines()
            raise MailutError(
                f"cannot read logs for service {service!r}"
                + (f": {detail[-1]}" if detail else "")
            )
        return proc.stdout


    def probe_url_from_service(self, service: str, url: str, *, timeout: int = 20):
        """Can ``service`` reach ``url``?  Returns (True/False/None, detail).

        ``None`` means "could not determine" — the container has no HTTP client
        we recognise, or docker itself failed.  That is reported as unverified
        rather than as a failure, because it says nothing about the wiring.
        """
        script = (
            "if command -v curl >/dev/null 2>&1; then "
            f"curl -fsS -m 5 -o /dev/null {shlex.quote(url)} && echo MAILUT_OK; "
            "elif command -v wget >/dev/null 2>&1; then "
            f"wget -q -T 5 -O /dev/null {shlex.quote(url)} && echo MAILUT_OK; "
            "else echo MAILUT_NO_CLIENT; fi"
        )
        try:
            proc = self.exec_service(service, ["sh", "-c", script], timeout=timeout)
        except MailutError as exc:
            return None, str(exc)
        output = (proc.stdout or "") + (proc.stderr or "")
        if "MAILUT_NO_CLIENT" in output:
            return None, f"no curl or wget in the {service} container"
        if "MAILUT_OK" in output:
            return True, "ok"
        if proc.returncode != 0 and not output.strip():
            return None, f"docker exec into {service} failed"
        detail = (output.strip().splitlines() or ["no response"])[-1]
        return False, detail[:200]


def queue_entry_recipients(entry: dict) -> list[str]:
    out = []
    for recipient in entry.get("recipients") or []:
        if isinstance(recipient, dict):
            address = recipient.get("address")
            if address:
                out.append(str(address))
    return out
