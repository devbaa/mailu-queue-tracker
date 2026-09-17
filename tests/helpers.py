"""Shared test helpers: a throwaway host layout, config and database."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
MAILUT = ROOT / "bin" / "mailut"

sys.path.insert(0, str(ROOT / "lib"))

DEFAULT_CONF = """\
[mailu]
compose_dir = {compose_dir}
compose_command = /bin/false
smtp_service = smtp
front_service = front

[storage]
state_dir = {state_dir}

[audit]
default_retention_days = 30
default_level = metadata
store_accepted = true
allow_headers = true
allow_messages = {allow_messages}
message_retention_days = 30
message_max_bytes = {message_max_bytes}

[collector]
bind = 127.0.0.1
port = 18765

[watch]
window = 15m
queue_warn = 20
queue_crit = 50
deferred_warn = 10
deferred_crit = 30
sender_sent_warn = 10
sender_sent_crit = 25
bulk_sender_msgs = 10
multi_sender_warn = 3
multi_sender_crit = 5
sender_queue_warn = 20
sender_queue_crit = 50
rcpt_domains_warn = 10
rcpt_domains_crit = 20
"""


class MailutTestCase(unittest.TestCase):
    """Base case giving each test its own state directory and config file."""

    allow_messages = "false"
    message_max_bytes = 26214400
    extra_config = ""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mailut-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state_dir = self.tmp / "state"
        self.compose_dir = self.tmp / "mailu"
        self.compose_dir.mkdir(parents=True)
        (self.compose_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        self.conf_path = self.tmp / "mailut.conf"
        self.conf_path.write_text(
            DEFAULT_CONF.format(
                compose_dir=self.compose_dir,
                state_dir=self.state_dir,
                allow_messages=self.allow_messages,
                message_max_bytes=self.message_max_bytes,
            )
            + self.extra_config,
            encoding="utf-8",
        )
        self._conn = None

    def config(self):
        from mailut.config import Config

        return Config.load(self.conf_path)

    def db(self):
        """An open, migrated connection (closed automatically)."""
        if self._conn is None:
            from mailut.db import Database

            config = self.config()
            database = Database(config.database, config.get("storage", "busy_timeout_ms"))
            self._conn = database.connect()
            self.addCleanup(self._conn.close)
        return self._conn

    def store(self):
        from mailut.events import EventStore

        return EventStore(self.db(), self.config())

    # -- running the real CLI -------------------------------------------------
    def run_cli(self, *args, env=None, input_text=None, expect=None):
        environment = dict(os.environ)
        environment.pop("MAILUT_CONF", None)
        environment["PYTHONPATH"] = str(ROOT / "lib")
        if env:
            environment.update(env)
        proc = subprocess.run(
            [sys.executable, str(MAILUT), "--config", str(self.conf_path), *args],
            capture_output=True,
            text=True,
            input=input_text,
            env=environment,
            timeout=120,
        )
        if expect is not None and proc.returncode != expect:
            self.fail(
                f"`mailut {' '.join(args)}` exited {proc.returncode}, expected {expect}\n"
                f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            )
        return proc


def make_event(**kwargs):
    """Build an Event with sensible defaults for the fields tests do not set."""
    from mailut.events import Event
    from mailut.util import utcnow

    params = {
        "occurred_at": utcnow(),
        "source": "postfix",
        "stage": "data",
        "action": "accept",
        "envelope_from": "sender@example.net",
        "envelope_to": "user@example.com",
    }
    params.update(kwargs)
    return Event(**params)
