"""Talking to the Mailu containers.

Every invocation is an argument vector handed straight to :mod:`subprocess`;
no shell is involved, so an envelope address or a HELO name can never be
interpreted as a command.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .util import MailutError

# Test hooks: when set, these replace the docker invocations with a fixture.
ENV_QUEUE = "MAILUT_QUEUE_FILE"
ENV_SMTP_LOG = "MAILUT_SMTP_LOG_FILE"
ENV_FRONT_LOG = "MAILUT_FRONT_LOG_FILE"
ENV_POSTSUPER_OUT = "MAILUT_POSTSUPER_OUT"


class Mailu:
    def __init__(self, config):
        self.config = config
        self.compose_dir = Path(config.get("mailu", "compose_dir"))
        self.compose = config.compose_argv
        self.smtp_service = config.get("mailu", "smtp_service")
        self.front_service = config.get("mailu", "front_service")

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


def queue_entry_recipients(entry: dict) -> list[str]:
    out = []
    for recipient in entry.get("recipients") or []:
        if isinstance(recipient, dict):
            address = recipient.get("address")
            if address:
                out.append(str(address))
    return out
