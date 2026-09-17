# Architecture

Small, boring and deterministic on purpose: Python 3 standard library, SQLite,
systemd, no framework, no runtime dependencies to install.

## Shape

```
bin/mailut                 launcher: finds the package, calls mailut.cli.main
lib/mailut/
  cli.py                   the whole argparse tree; commands are imported lazily
  release.py               product name, canonical upstream, version, layout
  config.py                INI parsing, defaults, validation, derived paths
  db.py                    connections, pragmas, automatic migration, backups
  migrations.py            schema, as an ordered, versioned list
  scopes.py                collection scopes and precedence
  events.py                the event model, classification, fingerprint, storage
  payloads.py              gzipped message storage under the state directory
  query.py                 audit show / stats
  purge.py                 audit purge
  collector.py             the daemon: HTTP endpoint + log poller
  ingest/rspamd.py         exporter payload -> events
  ingest/postfix.py        Postfix log line -> event or enrichment
  mailu.py                 docker compose / postqueue / postsuper, as argv
  queuecmd.py              queue list / drain / hold / release
  ips.py                   front-log client IP investigation
  watch.py                 watch sampling and report
  status.py                status and doctor
  systemd.py               read-mostly systemctl wrapper
  lifecycle/               manifest, lock, upstream, archive, upgrade, uninstall
tools/                     build-time helpers (buildinfo, install manifest)
```

`cli.py` imports command modules only when a command runs, so `mailut --help`
and `mailut version` stay fast and do not touch SQLite.

## Data flow

```
                     Rspamd (antispam container)
                             │  metadata_exporter, JSON over HTTP
                             ▼
  Mailu smtp log  ──────► collector ──────► SQLite ──────► mailut audit show
   (docker logs,          (HTTP +          (WAL,            mailut audit stats
    polled with a         poller)          FK on)           mailut audit purge
    stored cursor)            │
                              └──────────► /var/lib/mailut/messages/  (optional)
```

Two sources, because neither sees everything:

- **Rspamd** sees scanned messages: score, action, symbols, authentication
  results, subject, message id. It never sees a session Postfix refused before
  `DATA`.
- **Postfix** sees the whole SMTP conversation: connection, HELO, MAIL FROM,
  RCPT TO rejections, policy rejections, and local delivery outcomes.

Both produce the same `Event`, which is bound to a scope, given an expiry, and
written through one code path (`events.EventStore.store`).

## The collector

`mailut audit collect` (run by `mailut-audit.service`) is a foreground daemon:

- a `ThreadingHTTPServer` bound to `127.0.0.1` by default, accepting
  `POST /rspamd` with a JSON object or a small array, with a body-size limit;
- a poller thread that runs one `docker compose logs --since <cursor>` per
  interval — one Docker call per poll, never one per event.

All database writes go through a single connection behind one lock, which keeps
the write path simple and avoids SQLite lock contention with itself.

Restart safety comes from two independent mechanisms: the log cursor in
`collector_state`, and the event fingerprint's uniqueness constraint. The poller
deliberately re-reads one second of overlap; the fingerprint discards it.

Unrecognised or malformed log lines are counted and skipped — the parser returns
`None` rather than raising, because a daemon must not die on a log line.

## Schema

```
schema_migrations   applied migrations
audit_scopes        all/domain/email x include/exclude, level, retention
audit_events        one observed decision
audit_symbols       normalised Rspamd symbols (queryable)
audit_payloads      retained headers (inline) or messages (file reference)
collector_state     log cursor and other collector bookkeeping
watch_samples       queue/abuse samples from `mailut watch`
purge_runs          what each purge did
```

Indexes are deliberate, one per documented query filter, rather than one per
column: `occurred_at`, `expires_at`, `(envelope_to, occurred_at)`,
`(envelope_to_domain, occurred_at)`, `(envelope_from, occurred_at)`,
`(action, occurred_at)`, `queue_id`, `message_id`,
`(remote_ip, occurred_at)`, `audit_symbols(symbol)`,
`audit_payloads(expires_at)`.

Timestamps are stored in one format only: UTC, `YYYY-MM-DDTHH:MM:SSZ`. Human
output prints them as stored, labelled with `Z`.

### Migrations

`migrations.MIGRATIONS` is an ordered list of `(version, description,
statements)`. Opening the database applies whatever is outstanding, inside a
transaction per migration, and records it in `schema_migrations`. A database
newer than the running build is refused rather than used.

Adding one: append an entry, bump `release.SCHEMA_VERSION`, never edit a
released entry. `make dist` writes `SCHEMA_VERSION` into the release tarball so
`mailut upgrade` can tell whether a schema change is coming *before* installing
anything, and take a backup only when one is.

## Performance

SQLite is a deliberate choice: this is an operational record for one mail
server, not a data warehouse. Still:

- every write is in an explicit transaction, every statement is parameterised;
- queries stream with `fetchmany`, and `--json` is JSON Lines so nothing has to
  be buffered whole;
- purges work in batches of 500;
- WAL mode, with a checkpoint on `mailut db optimize`;
- `VACUUM` runs only when explicitly asked for (`mailut db optimize --vacuum`),
  never on a schedule;
- Docker is invoked once per poll or per command, never per event.

## Lifecycle

The installed application knows three things without any checkout:

- its **version**, from `buildinfo.json` written next to the package by
  `make install`;
- its **canonical upstream**, from `release.py`, defined once;
- its **files**, from `/usr/local/share/mailut/install-manifest.json`.

The manifest is generated by walking the tree `make install` has just created,
so the Makefile and the application cannot drift into two different file lists.
It records path, type, mode and SHA-256 for each file, plus the owned units, the
owned directories and the *preserved* (mutable) paths, which are deliberately
not part of it.

`mailut upgrade` discovers a release over public HTTPS, verifies the tarball
against the release's own `SHA256SUMS`, validates the unpacked tree, and then
delegates installation to that tree's `make install` — so remote upgrade and
`sudo make install` cannot implement different semantics. `mailut uninstall`
works from the manifest alone and needs no network at all.

`/run/mailut/lifecycle.lock` (an `flock`, not a PID file) serialises upgrade,
uninstall and schema migration.

## Deliberate non-goals

No web UI, no customer authentication, no billing, no notification integrations,
no Prometheus/Grafana/Elasticsearch, no PostgreSQL or Redis, no quarantine
release, no IMAP browsing, no AI classification. The commercial tier names a
customer portal might use are not in the data model either — retention and level
are numbers and enums, and a billing system can map its own names onto them.

This repository is the collection, storage and query layer. Something else can
be the portal.
