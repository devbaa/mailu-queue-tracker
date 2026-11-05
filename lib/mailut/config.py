"""Configuration: /etc/mailut/mailut.conf (INI, parsed with configparser).

The file holds *static host* configuration only.  Mutable audit scopes live in
SQLite; the configuration file is never used as a database.
"""

from __future__ import annotations

import configparser
import os
import shlex
from pathlib import Path

from . import release
from .util import MailutError, UsageError

# Every level the database can record.  Only the first can be collected: the
# Mailu container logs, which are where evidence comes from, carry no message
# headers or bodies.  The other two remain valid stored values so that the
# schema does not change, but no scope can be created at them.
LEVELS = ("metadata", "headers", "message")
COLLECTABLE_LEVELS = ("metadata",)

_NO_CONTENT = (
    "mailut collects from the Mailu container logs, which carry no message "
    "headers or bodies; only 'metadata' can be collected"
)

# section -> key -> (default, kind).  This table is the single source of truth
# for defaults and is also what mailut.conf(5) documents.
DEFAULTS: dict[str, dict[str, tuple[object, str]]] = {
    "mailu": {
        "compose_dir": ("/opt/mailu", "str"),
        "compose_command": ("docker compose", "str"),
        "smtp_service": ("smtp", "str"),
        "front_service": ("front", "str"),
        "antispam_service": ("antispam", "str"),
        "local_domains": ("", "list"),
    },
    "storage": {
        "state_dir": ("", "str"),  # empty -> <localstatedir>/lib/mailut
        "database": ("", "str"),  # empty -> <state_dir>/mailut.sqlite3
        "message_dir": ("", "str"),  # empty -> <state_dir>/messages
        "backup_dir": ("", "str"),  # empty -> <state_dir>/backups
        "busy_timeout_ms": (5000, "int"),
    },
    "audit": {
        "default_retention_days": (30, "int"),
        "default_level": ("metadata", "str"),
        "store_accepted": (True, "bool"),
        "max_retention_days": (3650, "int"),
    },
    "collector": {
        "log_poll_seconds": (30, "int"),
        "log_lookback": ("10m", "str"),
        "ingest_smtp_logs": (True, "bool"),
        "ingest_rspamd_logs": (True, "bool"),
    },
    "watch": {
        "window": ("15m", "str"),
        "retention_days": (90, "int"),
        "queue_warn": (200, "int"),
        "queue_crit": (500, "int"),
        "deferred_warn": (100, "int"),
        "deferred_crit": (300, "int"),
        "sender_sent_warn": (50, "int"),
        "sender_sent_crit": (150, "int"),
        "bulk_sender_msgs": (50, "int"),
        "multi_sender_warn": (3, "int"),
        "multi_sender_crit": (5, "int"),
        "sender_queue_warn": (100, "int"),
        "sender_queue_crit": (300, "int"),
        "rcpt_domains_warn": (25, "int"),
        "rcpt_domains_crit": (50, "int"),
        "bounce_defer_rate_warn": (20, "int"),
        "bounce_defer_rate_crit": (40, "int"),
        "spam_block_warn": (1, "int"),
        "spam_block_crit": (5, "int"),
    },
}

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def default_config_path() -> Path:
    return Path(release.layout()["confdir"]) / "mailut.conf"


class Config:
    """Parsed configuration with typed accessors and derived paths."""

    def __init__(self, values: dict, path: Path | None, present: bool):
        self._values = values
        self.path = path
        self.present = present

    # -- construction --------------------------------------------------------
    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        if path is None:
            path = os.environ.get("MAILUT_CONF") or default_config_path()
        path = Path(path)
        values = {s: {k: v[0] for k, v in keys.items()} for s, keys in DEFAULTS.items()}

        present = path.is_file()
        if present:
            parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
            try:
                with path.open(encoding="utf-8") as handle:
                    parser.read_file(handle)
            except (OSError, configparser.Error) as exc:
                raise MailutError(f"cannot read configuration {path}: {exc}") from exc
            for section in parser.sections():
                if section not in DEFAULTS:
                    raise MailutError(f"{path}: unknown configuration section [{section}]")
                for key, raw in parser.items(section):
                    if key not in DEFAULTS[section]:
                        raise MailutError(f"{path}: unknown setting {key} in [{section}]")
                    values[section][key] = _coerce(path, section, key, raw)

        config = cls(values, path, present)
        config.validate()
        return config

    # -- accessors -----------------------------------------------------------
    def get(self, section: str, key: str):
        try:
            return self._values[section][key]
        except KeyError as exc:  # pragma: no cover - programming error
            raise KeyError(f"no such setting {section}.{key}") from exc

    def items(self):
        for section in sorted(self._values):
            for key in sorted(self._values[section]):
                yield section, key, self._values[section][key]

    # -- derived paths -------------------------------------------------------
    @property
    def state_dir(self) -> Path:
        value = self.get("storage", "state_dir")
        if value:
            return Path(value)
        return Path(release.layout()["statedir"])

    @property
    def database(self) -> Path:
        value = self.get("storage", "database")
        return Path(value) if value else self.state_dir / "mailut.sqlite3"

    @property
    def message_dir(self) -> Path:
        value = self.get("storage", "message_dir")
        return Path(value) if value else self.state_dir / "messages"

    @property
    def backup_dir(self) -> Path:
        value = self.get("storage", "backup_dir")
        return Path(value) if value else self.state_dir / "backups"

    @property
    def run_dir(self) -> Path:
        return Path(release.layout()["rundir"])

    @property
    def compose_argv(self) -> list[str]:
        """The compose command as an argument vector (never a shell string)."""
        return shlex.split(self.get("mailu", "compose_command"))

    @property
    def local_domains(self) -> list[str]:
        return [d.lower() for d in self.get("mailu", "local_domains")]

    # -- validation ----------------------------------------------------------
    def validate(self) -> None:
        where = str(self.path) if self.path else "<defaults>"
        level = self.get("audit", "default_level")
        if level not in COLLECTABLE_LEVELS:
            raise MailutError(f"{where}: audit.default_level must be 'metadata': {_NO_CONTENT}")
        for section, key in (
            ("audit", "default_retention_days"),
            ("audit", "max_retention_days"),
            ("watch", "retention_days"),
        ):
            if self.get(section, key) < 1:
                raise MailutError(f"{where}: {section}.{key} must be >= 1")
        if self.get("collector", "log_poll_seconds") < 1:
            raise MailutError(f"{where}: collector.log_poll_seconds must be >= 1")
        if not self.compose_argv:
            raise MailutError(f"{where}: mailu.compose_command must not be empty")
        for domain in self.get("mailu", "local_domains"):
            if "." not in domain:
                raise MailutError(f"{where}: mailu.local_domains contains an invalid domain {domain!r}")

    def check_level_allowed(self, level: str) -> None:
        """Raise unless ``level`` can actually be collected.

        Never accept a level and then quietly collect less: an operator who
        asked for headers or messages must be told they will not get them.
        """
        if level not in LEVELS:
            raise UsageError(f"invalid collection level {level!r}: expected one of {', '.join(LEVELS)}")
        if level not in COLLECTABLE_LEVELS:
            raise UsageError(f"collection level {level!r} is not available: {_NO_CONTENT}")


def _coerce(path: Path, section: str, key: str, raw: str):
    _default, kind = DEFAULTS[section][key]
    text = raw.strip()
    if kind == "int":
        try:
            return int(text)
        except ValueError as exc:
            raise MailutError(f"{path}: {section}.{key} must be an integer, got {raw!r}") from exc
    if kind == "bool":
        lowered = text.lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
        raise MailutError(f"{path}: {section}.{key} must be a boolean, got {raw!r}")
    if kind == "list":
        return [item.strip() for item in text.replace(",", " ").split() if item.strip()]
    return text
