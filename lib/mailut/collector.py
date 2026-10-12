"""The audit collector daemon (``mailut audit collect``).

It reads two Mailu container logs and turns them into audit events:

  * the **antispam** log, where Rspamd writes one line per scanned message
    with its action, score and symbols; and
  * the **smtp** log, where Postfix records what Rspamd never sees: pre-DATA
    and policy rejections, and local delivery outcomes.

Both are read with ``docker compose logs --since``, the same way an operator
would.  Nothing listens on the network and nothing in Mailu's configuration is
changed: if Mailu is running and its logs are readable, collection works.

Each log has its own cursor in SQLite, and only lines newer than it are
requested, so restarting the service does not re-ingest history; event
fingerprints catch whatever overlap remains.

Logging goes to stdout/stderr, which is journald under systemd.  There is no
application log file.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import signal
import sqlite3
import threading
from collections import OrderedDict

from . import scopes as scope_store
from .db import Database
from .events import EventStore
from .ingest import postfix as postfix_ingest
from .ingest import rspamd as rspamd_ingest
from .mailu import Mailu
from .util import MailutError, from_iso, parse_duration, to_iso, utcnow

log = logging.getLogger("mailut.collector")

# One cursor per log, so that a quiet antispam log cannot hold back the smtp
# one or the other way round.  The smtp key predates the antispam source and
# keeps its name so an existing cursor is honoured.
SOURCES = {
    "smtp": {"cursor": "smtp_log_cursor", "service_key": "smtp_service", "enabled": "ingest_smtp_logs"},
    "antispam": {"cursor": "antispam_log_cursor", "service_key": "antispam_service", "enabled": "ingest_rspamd_logs"},
}
CURSOR_KEY = SOURCES["smtp"]["cursor"]


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


def _new_summary() -> dict:
    return {"lines": 0, "stored": 0, "duplicate": 0, "out_of_scope": 0, "unparsed": 0,
            "enriched": 0, "skipped": 0}


def _store(ingestor: Ingestor, event, summary: dict) -> _dt.datetime | None:
    try:
        result = ingestor.ingest_event(event)
    except MailutError as exc:
        log.warning("ingest failed: %s", exc)
        ingestor.stats["errors"] += 1
        return None
    summary[result["status"]] = summary.get(result["status"], 0) + 1
    return event.occurred_at


def ingest_log_text(ingestor: Ingestor, text: str) -> dict:
    """Ingest a block of Postfix log lines; malformed lines are skipped."""
    summary = _new_summary()
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
        when = _store(ingestor, parsed, summary)
        if when is not None and (latest is None or when > latest):
            latest = when
    summary["latest"] = latest
    return summary


def ingest_rspamd_text(ingestor: Ingestor, text: str) -> dict:
    """Ingest a block of antispam log lines.

    Most lines in that log are not per-message results (startup, milter
    chatter, module messages); they count as unparsed and are ignored.
    """
    summary = _new_summary()
    latest: _dt.datetime | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        summary["lines"] += 1
        events = rspamd_ingest.parse_line(line)
        if events is None:
            summary["unparsed"] += 1
            continue
        if not events:
            summary["skipped"] += 1  # authenticated submission, or no recipient
            continue
        for event in events:
            when = _store(ingestor, event, summary)
            if when is not None and (latest is None or when > latest):
                latest = when
    summary["latest"] = latest
    return summary


_PARSERS = {"smtp": ingest_log_text, "antispam": ingest_rspamd_text}


class LogPoller(threading.Thread):
    """Periodically ingest new lines from the Mailu container logs."""

    def __init__(self, ingestor: Ingestor, stop: threading.Event, sources=None):
        super().__init__(name="mailut-log-poller", daemon=True)
        self.ingestor = ingestor
        self.stop = stop
        self.config = ingestor.config
        self.mailu = Mailu(self.config)
        self.interval = self.config.get("collector", "log_poll_seconds")
        self.sources = list(sources) if sources is not None else enabled_sources(self.config)

    def _since(self, source: str) -> str:
        cursor = self.ingestor.get_state(SOURCES[source]["cursor"])
        if cursor:
            try:
                # Re-read one second of overlap; fingerprints de-duplicate it.
                when = from_iso(cursor) - _dt.timedelta(seconds=1)
                return to_iso(when)
            except MailutError:
                pass
        lookback = parse_duration(self.config.get("collector", "log_lookback"))
        return to_iso(utcnow() - lookback)

    def poll_source(self, source: str) -> dict:
        service = self.config.get("mailu", SOURCES[source]["service_key"])
        # The cursor records how far the log has been read, which is "up to
        # when this call began": Docker returns every line logged before then.
        # It is taken before the call, so a line logged while Docker was
        # answering is read again next time (and de-duplicated) rather than
        # skipped.  It is deliberately not the time of the last event seen:
        # in a quiet period that event is re-found on every poll, so the cursor
        # would never move and each poll would re-read everything since the
        # last mail.
        started = utcnow()
        text = self.mailu.logs(service, since=self._since(source))
        summary = _PARSERS[source](self.ingestor, text)
        self.ingestor.set_state(SOURCES[source]["cursor"], to_iso(started))
        return summary

    def poll_once(self) -> dict:
        """Poll every enabled source once.  Returns {source: summary}.

        A failure reading one log is logged and does not stop the other.
        """
        results = {}
        for source in self.sources:
            try:
                results[source] = self.poll_source(source)
            except MailutError as exc:
                log.warning("%s log poll failed: %s", source, exc)
                results[source] = {"error": str(exc)}
        return results

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                for source, summary in self.poll_once().items():
                    if summary.get("stored") or summary.get("enriched"):
                        log.info(
                            "%s log: %d line(s), %d stored, %d duplicate, %d out of scope, %d enriched",
                            source, summary["lines"], summary["stored"], summary["duplicate"],
                            summary["out_of_scope"], summary["enriched"],
                        )
            except Exception as exc:  # pragma: no cover - keep the daemon alive
                log.exception("log poll crashed: %s", exc)
            self.stop.wait(self.interval)


def enabled_sources(config) -> list[str]:
    return [name for name, spec in SOURCES.items() if config.get("collector", spec["enabled"])]


def cmd_collect(args, config) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    sources = enabled_sources(config)
    if not sources:
        raise MailutError(
            "both collector.ingest_smtp_logs and collector.ingest_rspamd_logs are "
            "false: there is nothing to collect"
        )

    ingestor = Ingestor(config)
    if not ingestor.has_scopes():
        log.warning(
            "no audit scopes are configured: nothing will be collected "
            "(try: mailut audit add domain example.com)"
        )
    stop = threading.Event()
    poller = LogPoller(ingestor, stop, sources)

    if args.once:
        # Diagnostics: poll each log exactly once, synchronously, and exit.
        try:
            for source, summary in poller.poll_once().items():
                if "error" in summary:
                    continue
                log.info(
                    "%s log: %d line(s), %d stored, %d duplicate, %d out of scope, "
                    "%d enriched, %d skipped, %d unparsed",
                    source, summary["lines"], summary["stored"], summary["duplicate"],
                    summary["out_of_scope"], summary["enriched"], summary["skipped"],
                    summary["unparsed"],
                )
            return 0
        finally:
            ingestor.close()

    def _shutdown(_signum, _frame):
        log.info("shutting down")
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("collecting from the %s log(s) every %ds", " and ".join(sources), poller.interval)
    poller.start()
    try:
        while poller.is_alive():
            poller.join(timeout=1)
    finally:
        stop.set()
        poller.join(timeout=5)
        ingestor.close()
        log.info("stopped: %s", ingestor.stats)
    return 0


def cmd_ingest(args, config) -> int:
    """Read log lines from a file or stdin (replay, testing, manual import)."""
    import sys

    if args.file == "-":
        text = sys.stdin.read()
    else:
        with open(args.file, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    ingestor = Ingestor(config)
    try:
        parser = ingest_rspamd_text if args.source == "rspamd" else ingest_log_text
        totals = parser(ingestor, text)
        totals.pop("latest", None)
        json.dump(totals, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    finally:
        ingestor.close()
    return 0
