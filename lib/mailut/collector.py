"""The audit collector daemon (``mailut audit collect``).

Two sources feed the same event store:

  * a small HTTP endpoint on localhost that the Rspamd metadata exporter posts
    JSON to, and
  * a poller that reads the Mailu smtp container log for the evidence Rspamd
    never sees (pre-DATA and policy rejections, local delivery outcomes).

The log poller keeps a cursor in SQLite and asks Docker only for lines newer
than it, so restarting the service does not re-ingest history; event
fingerprints catch whatever overlap remains.

Logging goes to stdout/stderr, which is journald under systemd.  There is no
application log file.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hmac
import json
import logging
import signal
import sqlite3
import stat
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import scopes as scope_store
from .db import Database
from .events import EventStore
from .ingest import postfix as postfix_ingest
from .ingest import rspamd as rspamd_ingest
from .mailu import Mailu
from .util import (
    MailutError,
    classify_bind_address,
    from_iso,
    parse_duration,
    to_iso,
    utcnow,
)

log = logging.getLogger("mailut.collector")

CURSOR_KEY = "smtp_log_cursor"

# The shortest token we will accept.  A token this size is only reasonable if
# it was generated randomly, which the documentation tells the operator to do.
MIN_TOKEN_BYTES = 16


def read_token(config) -> str | None:
    """The shared ingestion token, or None when authentication is disabled.

    The token file is a secret, so it must not be readable by anyone but its
    owner: a group- or world-readable token is refused rather than used, since
    quietly accepting it would make the endpoint look authenticated while the
    secret sits where any local account can read it.
    """
    configured = config.get("collector", "token_file")
    if not configured:
        return None
    path = Path(configured)
    try:
        info = path.stat()
    except OSError as exc:
        raise MailutError(f"cannot read collector.token_file {path}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise MailutError(f"collector.token_file {path} is not a regular file")
    if info.st_mode & 0o077:
        raise MailutError(
            f"collector.token_file {path} is readable by other accounts "
            f"(mode {info.st_mode & 0o777:04o}); run: chmod 600 {path}"
        )
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MailutError(f"cannot read collector.token_file {path}: {exc}") from exc
    if not token:
        raise MailutError(f"collector.token_file {path} is empty")
    if len(token) < MIN_TOKEN_BYTES:
        raise MailutError(
            f"the token in {path} is only {len(token)} characters; use at least "
            f"{MIN_TOKEN_BYTES} random ones (for example: openssl rand -hex 32)"
        )
    if any(ch.isspace() for ch in token):
        raise MailutError(f"the token in {path} contains whitespace; it must be a single word")
    return token


def presented_token(header: str | None) -> str | None:
    """The token an ``Authorization`` header carries, if we understand it.

    Two schemes are accepted.  ``Bearer`` is what a human with curl will reach
    for.  ``Basic`` is what Rspamd's metadata_exporter can actually send: its
    http backend builds the header from the rule's ``user``/``password`` and
    offers no way to set an arbitrary one, so the token travels as the
    password and the username is not a secret.
    """
    if not header:
        return None
    scheme, _, rest = header.partition(" ")
    rest = rest.strip()
    if not rest:
        return None
    if scheme.lower() == "bearer":
        return rest
    if scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(rest, validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return None
        _, sep, password = decoded.partition(":")
        return password if sep else None
    return None


class Ingestor:
    """Serialises all writes to the audit database behind one lock."""

    def __init__(self, config):
        self.config = config
        self.database = Database(config.database, config.get("storage", "busy_timeout_ms"))
        self.conn = self.database.connect()
        self.lock = threading.Lock()
        self.store = EventStore(self.conn, config)
        self.stats = {"stored": 0, "duplicate": 0, "out_of_scope": 0, "errors": 0, "unparsed": 0}
        # Postfix logs a message-id and a size before the delivery line that
        # carries the recipient, so enrichment can arrive before the event it
        # belongs to. Remember a bounded number of recent queue ids.
        self.pending: "OrderedDict[str, dict]" = OrderedDict()
        self.pending_limit = 5000

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass

    def ingest_event(self, event) -> dict:
        known = self.pending.get(event.queue_id) if event.queue_id else None
        if known:
            if event.message_id is None and not event.pre_data:
                event.message_id = known.get("message_id")
            if event.message_size is None:
                event.message_size = known.get("message_size")
        with self.lock:
            result = self.store.store(event)
        self.stats[result["status"]] = self.stats.get(result["status"], 0) + 1
        return result

    def _remember(self, data: dict) -> None:
        queue_id = data["queue_id"]
        entry = self.pending.setdefault(queue_id, {})
        for key in ("message_id", "message_size"):
            if data.get(key) is not None:
                entry[key] = data[key]
        self.pending.move_to_end(queue_id)
        while len(self.pending) > self.pending_limit:
            self.pending.popitem(last=False)

    def enrich(self, data: dict) -> None:
        queue_id = data.get("queue_id")
        if not queue_id:
            return
        self._remember(data)
        with self.lock:
            if data.get("message_id"):
                self.store.attach_message_id(queue_id, data["message_id"])
            if data.get("message_size") is not None:
                try:
                    self.conn.execute("BEGIN IMMEDIATE")
                    self.conn.execute(
                        "UPDATE audit_events SET message_size = ? "
                        "WHERE queue_id = ? AND message_size IS NULL",
                        (data["message_size"], queue_id),
                    )
                    self.conn.execute("COMMIT")
                except sqlite3.Error:
                    self.conn.execute("ROLLBACK")

    def get_state(self, key: str) -> str | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT value FROM collector_state WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self.lock:
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                self.conn.execute(
                    "INSERT INTO collector_state (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = excluded.value, "
                    "updated_at = excluded.updated_at",
                    (key, value, to_iso(utcnow())),
                )
                self.conn.execute("COMMIT")
            except sqlite3.Error:
                self.conn.execute("ROLLBACK")

    def has_scopes(self) -> bool:
        with self.lock:
            return bool(scope_store.list_scopes(self.conn))


def ingest_rspamd_payload(ingestor: Ingestor, data) -> dict:
    """Ingest one exporter payload; returns a small result summary."""
    events = rspamd_ingest.parse(data, message_limit=ingestor.config.get("audit", "message_max_bytes"))
    summary = {"events": len(events), "stored": 0, "duplicate": 0, "out_of_scope": 0}
    for event in events:
        result = ingestor.ingest_event(event)
        summary[result["status"]] = summary.get(result["status"], 0) + 1
    return summary


def ingest_log_text(ingestor: Ingestor, text: str) -> dict:
    """Ingest a block of Postfix log lines; malformed lines are skipped."""
    summary = {"lines": 0, "stored": 0, "duplicate": 0, "out_of_scope": 0, "unparsed": 0, "enriched": 0}
    latest: _dt.datetime | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        summary["lines"] += 1
        parsed = postfix_ingest.parse_line(line)
        if parsed is None:
            summary["unparsed"] += 1
            continue
        if isinstance(parsed, dict):
            ingestor.enrich(parsed)
            summary["enriched"] += 1
            continue
        try:
            result = ingestor.ingest_event(parsed)
        except MailutError as exc:
            log.warning("ingest failed: %s", exc)
            ingestor.stats["errors"] += 1
            continue
        summary[result["status"]] = summary.get(result["status"], 0) + 1
        if latest is None or parsed.occurred_at > latest:
            latest = parsed.occurred_at
    summary["latest"] = latest
    return summary


class _Handler(BaseHTTPRequestHandler):
    server_version = "mailut"
    sys_version = ""
    ingestor: Ingestor  # injected on the server instance

    def log_message(self, fmt, *args):  # keep journald readable
        log.debug("%s %s", self.address_string(), fmt % args)

    def _reply(self, code: int, payload: dict, headers=()) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _authenticated(self) -> bool:
        """True when the request carries the shared token, or none is required."""
        expected = self.server.token
        if expected is None:
            return True
        presented = presented_token(self.headers.get("Authorization"))
        if presented is None:
            return False
        return hmac.compare_digest(presented, expected)

    def _deny(self) -> None:
        # Say which schemes work, but never echo what was presented.
        log.warning("rejected unauthenticated ingest from %s", self.address_string())
        self.server.ingestor.stats["unauthenticated"] = (
            self.server.ingestor.stats.get("unauthenticated", 0) + 1
        )
        # The body was never read, so this connection cannot be reused.
        self.close_connection = True
        self._reply(401, {"error": "authentication required"}, headers=[
            ("WWW-Authenticate", 'Basic realm="mailut", charset="UTF-8"'),
        ])

    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.rstrip("/") in ("/health", "/healthz"):
            # Liveness stays open so the exporter and doctor can check wiring
            # before a token is agreed, but the counters are only for callers
            # that proved they belong here.
            if self._authenticated():
                self._reply(200, {"status": "ok", "auth": self.server.token is not None,
                                  "stats": self.server.ingestor.stats})
            else:
                self._reply(200, {"status": "ok", "auth": True})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - http.server API
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path not in ("/", "/rspamd", "/events"):
            self._reply(404, {"error": "not found"})
            return
        if not self._authenticated():
            self._deny()
            return
        limit = self.server.max_body_bytes
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reply(400, {"error": "invalid Content-Length"})
            return
        if length <= 0:
            self._reply(400, {"error": "empty body"})
            return
        if length > limit:
            self._reply(413, {"error": f"body exceeds {limit} bytes"})
            return
        try:
            raw = self.rfile.read(length)
        except OSError as exc:
            self._reply(400, {"error": f"cannot read body: {exc}"})
            return
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            self._reply(400, {"error": f"invalid JSON: {exc}"})
            return

        payloads = data if isinstance(data, list) else [data]
        if len(payloads) > 100:
            self._reply(413, {"error": "too many records in one request"})
            return
        totals = {"events": 0, "stored": 0, "duplicate": 0, "out_of_scope": 0}
        try:
            for payload in payloads:
                summary = ingest_rspamd_payload(self.server.ingestor, payload)
                for key, value in summary.items():
                    totals[key] = totals.get(key, 0) + value
        except rspamd_ingest.IngestError as exc:
            self._reply(400, {"error": str(exc)})
            return
        except MailutError as exc:
            log.error("ingest failed: %s", exc)
            self._reply(500, {"error": "ingest failed"})
            return
        except Exception as exc:  # pragma: no cover - never kill the daemon
            log.exception("unexpected ingest failure: %s", exc)
            self._reply(500, {"error": "ingest failed"})
            return
        self._reply(200, {"status": "ok", **totals})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, ingestor: Ingestor, max_body_bytes: int, token: str | None = None):
        self.ingestor = ingestor
        self.max_body_bytes = max_body_bytes
        self.token = token
        super().__init__(address, _Handler)

    def handle_error(self, request, client_address):  # pragma: no cover
        log.warning("collector request from %s failed", client_address[0], exc_info=True)


class LogPoller(threading.Thread):
    """Periodically ingest new lines from the Mailu smtp container log."""

    def __init__(self, ingestor: Ingestor, stop: threading.Event):
        super().__init__(name="mailut-log-poller", daemon=True)
        self.ingestor = ingestor
        self.stop = stop
        self.config = ingestor.config
        self.mailu = Mailu(self.config)
        self.interval = self.config.get("collector", "log_poll_seconds")

    def _since(self) -> str:
        cursor = self.ingestor.get_state(CURSOR_KEY)
        if cursor:
            try:
                # Re-read one second of overlap; fingerprints de-duplicate it.
                when = from_iso(cursor) - _dt.timedelta(seconds=1)
                return to_iso(when)
            except MailutError:
                pass
        lookback = parse_duration(self.config.get("collector", "log_lookback"))
        return to_iso(utcnow() - lookback)

    def poll_once(self) -> dict:
        since = self._since()
        text = self.mailu.logs(self.config.get("mailu", "smtp_service"), since=since)
        summary = ingest_log_text(self.ingestor, text)
        latest = summary.get("latest")
        # Advance the cursor even when nothing matched, so a quiet server does
        # not keep re-reading the same window forever.
        self.ingestor.set_state(CURSOR_KEY, to_iso(latest or utcnow()))
        return summary

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                summary = self.poll_once()
                if summary["stored"] or summary["enriched"]:
                    log.info(
                        "smtp log: %d line(s), %d stored, %d duplicate, %d out of scope, %d enriched",
                        summary["lines"], summary["stored"], summary["duplicate"],
                        summary["out_of_scope"], summary["enriched"],
                    )
            except MailutError as exc:
                log.warning("smtp log poll failed: %s", exc)
            except Exception as exc:  # pragma: no cover - keep the daemon alive
                log.exception("smtp log poll crashed: %s", exc)
            self.stop.wait(self.interval)


def assess_bind(config, mailu=None) -> dict:
    """Decide whether the configured bind address is safe to listen on.

    The question is who can reach the port. Being in an RFC 1918 range does not
    answer it: a host's LAN or VPC address is private and reachable from every
    other machine on that network. Nor does "some Docker network has this
    gateway" answer it, because a macvlan or ipvlan gateway is usually the real
    upstream router and an unrelated project's bridge is not reachable from
    Mailu anyway.

    What does answer it is whether the address is the gateway of a *bridge*
    network that the *antispam container is actually attached to*: reachable
    from the container that must post to us, and from nothing off this host.

    Returns ``{"category", "detail", "safe"}`` where category is one of
    loopback, bridge-gateway, unverified, wildcard or public.
    """
    bind = config.get("collector", "bind")
    syntactic = classify_bind_address(bind)
    if syntactic == "loopback":
        return {"category": "loopback", "detail": f"{bind} is loopback", "safe": True}
    if syntactic == "wildcard":
        return {
            "category": "wildcard",
            "detail": f"{bind} listens on every interface",
            "safe": False,
        }

    mailu = mailu or Mailu(config)
    service = mailu.antispam_service
    gateways, error = mailu.service_bridge_gateways(service)
    if bind in gateways:
        return {
            "category": "bridge-gateway",
            "detail": (
                f"{bind} is the gateway of a Docker bridge network attached to "
                f"the {service} container"
            ),
            "safe": True,
        }
    if error:
        return {
            "category": "unverified",
            "detail": (
                f"cannot confirm {bind} is the gateway of a bridge network "
                f"attached to {service} ({error})"
            ),
            "safe": False,
        }
    known = ", ".join(sorted(gateways)) if gateways else "none found"
    return {
        "category": "public" if syntactic == "public" else "unverified",
        "detail": (
            f"{bind} is not the gateway of a Docker bridge network attached to "
            f"the {service} container (those gateways: {known}); it may be "
            f"reachable from other machines"
        ),
        "safe": False,
    }


def cmd_collect(args, config) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    ingestor = Ingestor(config)
    if not ingestor.has_scopes():
        log.warning(
            "no audit scopes are configured: nothing will be collected "
            "(try: mailut audit add domain example.com)"
        )

    bind = config.get("collector", "bind")
    port = config.get("collector", "port")
    token = read_token(config)  # fails loudly on an unusable token file
    exposure = assess_bind(config)
    if not exposure["safe"] and not args.allow_remote:
        raise MailutError(
            f"refusing to bind the collector to {bind}: {exposure['detail']}.\n"
            "Use the loopback address, or the gateway of a Docker bridge network "
            "the antispam container is attached to, so that only containers on "
            "this host can reach it (see the Rspamd section of docs/install.md), "
            "or pass --allow-remote if it is firewalled and you accept the risk.\n"
            "Setting collector.token_file is worthwhile either way, but it does "
            "not make a widely reachable bind address safe on its own."
        )
    if exposure["category"] == "bridge-gateway":
        log.info(
            "collector bound to %s:%d (%s); make sure your firewall does not "
            "forward that port", bind, port, exposure["detail"],
        )
    elif not exposure["safe"]:
        log.warning(
            "collector bound to %s:%d with --allow-remote: %s.", bind, port, exposure["detail"],
        )
    if token is None:
        log.warning(
            "collector.token_file is not set: any process that can reach %s:%d "
            "can post fabricated audit evidence. See mailut.conf(5).", bind, port,
        )
    else:
        log.info("ingestion requires the shared token from %s",
                 config.get("collector", "token_file"))

    stop = threading.Event()

    if args.once:
        # Diagnostics: do exactly one log poll, synchronously, and exit. No
        # server, no background thread -- "once" has to mean once.
        try:
            if not config.get("collector", "ingest_smtp_logs") or args.no_log_poll:
                log.info("smtp log ingestion is disabled; nothing to poll")
                return 0
            summary = LogPoller(ingestor, stop).poll_once()
            log.info(
                "smtp log: %d line(s), %d stored, %d duplicate, %d out of scope, "
                "%d enriched, %d unparsed",
                summary["lines"], summary["stored"], summary["duplicate"],
                summary["out_of_scope"], summary["enriched"], summary["unparsed"],
            )
            return 0
        finally:
            ingestor.close()

    try:
        server = _Server((bind, port), ingestor, config.get("collector", "max_body_bytes"), token)
    except OSError as exc:
        ingestor.close()
        raise MailutError(f"cannot bind collector to {bind}:{port}: {exc}") from exc

    poller = None
    if config.get("collector", "ingest_smtp_logs") and not args.no_log_poll:
        poller = LogPoller(ingestor, stop)
        poller.start()

    def _shutdown(_signum, _frame):
        log.info("shutting down")
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("collector listening on %s:%d", bind, port)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()
        if poller is not None:
            poller.join(timeout=5)
        ingestor.close()
        log.info("stopped: %s", ingestor.stats)
    return 0


def cmd_ingest(args, config) -> int:
    """Read events from a file or stdin (replay, testing, manual import)."""
    import sys

    text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
    ingestor = Ingestor(config)
    try:
        if args.source == "rspamd":
            totals = {"events": 0, "stored": 0, "duplicate": 0, "out_of_scope": 0, "invalid": 0}
            stripped = text.strip()
            documents = []
            if stripped.startswith("["):
                documents = json.loads(stripped)
            else:
                for line in stripped.splitlines():
                    if line.strip():
                        documents.append(json.loads(line))
            for document in documents:
                try:
                    summary = ingest_rspamd_payload(ingestor, document)
                except rspamd_ingest.IngestError as exc:
                    print(f"skipped one record: {exc}", file=sys.stderr)
                    totals["invalid"] += 1
                    continue
                for key, value in summary.items():
                    totals[key] = totals.get(key, 0) + value
        else:
            totals = ingest_log_text(ingestor, text)
            totals.pop("latest", None)
        json.dump(totals, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    finally:
        ingestor.close()
    return 0


def probe(config, *, timeout: float = 2.0) -> tuple[bool, str]:
    """Is a collector answering on the configured address?  (used by doctor)"""
    import urllib.error
    import urllib.request

    bind = config.get("collector", "bind")
    host = "127.0.0.1" if bind in ("0.0.0.0", "::") else bind
    url = f"http://{host}:{config.get('collector', 'port')}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed localhost URL
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return True, f"responding at {host}:{config.get('collector', 'port')} ({payload.get('status')})"
    except urllib.error.URLError as exc:
        return False, f"no collector at {host}:{config.get('collector', 'port')} ({exc.reason})"
    except Exception as exc:  # pragma: no cover
        return False, f"collector probe failed: {exc}"
