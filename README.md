# Mailu Tools (`mailut`)

A small Linux administration tool for a [Mailu](https://mailu.io) mail server.
One command, standard paths, man pages, systemd units and a SQLite database.

It does three things:

- **queue and abuse work** — inspect the Postfix queue, drain or hold mail from
  a compromised account, find the real client IPs behind the Mailu front proxy;
- **watch** — sample queue size, delivery outcomes and per-sender volume on a
  timer, so an incident is visible after the fact;
- **audit** — record what the server decided about *inbound* mail: who tried to
  send it, whether it was rejected, greylisted, classified as spam, accepted or
  delivered, with the Rspamd score and symbols behind the decision.

The audit subsystem is an evidence store, not another mailbox. It exists to
answer "did this server ever see this message, and what did it do with it?"

## Install

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
make test
sudo make install

mailut --help
man mailut
```

Installing does not start anything. Enable what you want:

```bash
sudo systemctl enable --now mailut-audit.service   # audit collector
sudo systemctl enable --now mailut-purge.timer     # daily retention purge
sudo systemctl enable --now mailut-watch.timer     # queue sampling
```

or `sudo make enable` for all three.

Requires Python 3.9+ (standard library only — no pip packages), Docker Compose
and a Mailu installation. See [docs/install.md](docs/install.md).

## Configure

Edit `/etc/mailut/mailut.conf` — at minimum `compose_dir`. Every setting is
documented in `man 5 mailut.conf` and in the installed example at
`/usr/local/share/mailut/mailut.conf.example`.

```bash
mailut config check
mailut doctor
```

`mailut doctor` verifies configuration, Docker, the database, permissions, that
the Rspamd log can be read, and the systemd units. It changes nothing.

## Queue and abuse

```bash
mailut status
mailut queue list

mailut queue drain --sender compromised@example.com --dry-run
mailut queue drain --sender compromised@example.com
mailut queue hold  --sender compromised@example.com

mailut ips --since 6h
mailut ips --since 6h --user compromised@example.com

mailut watch --print
mailut report
```

Destructive queue commands take `--dry-run` and `--yes`, and ask before acting
when run on a terminal. Address matching is exact and case-insensitive.

## Audit

Collection is **opt-in**. Nothing is recorded until you add a scope.

```bash
mailut audit add all
mailut audit add domain customer.example --retention 365
mailut audit add email legal@example.com

mailut audit remove domain internal.example.com
mailut audit add email monitored@internal.example.com

mailut audit scopes
```

The most specific rule wins (`email` > `domain` > `all`); at equal specificity,
exclusion wins. So the commands above collect everything except
`internal.example.com`, and inside that domain collect exactly one address.

Then query it:

```bash
mailut audit show --recipient john@example.com --since 7d
mailut audit show --sender supplier@example.net --domain example.com --since 30d --json
mailut audit show --symbol RBL_SPAMHAUS_SBL --since 30d
mailut audit stats --domain example.com --since 30d
```

There is nothing to wire up. `mailut-audit.service` reads two Mailu container
logs with `docker compose logs`, the same way you would by hand:

- **antispam**: Rspamd's line for every scanned message, with its action,
  score and symbols;
- **smtp**: the Postfix rejections made before DATA, and local deliveries,
  which Rspamd never sees.

Nothing listens on the network, and no Mailu or Rspamd configuration changes.
`mailut audit doctor` reads the recent antispam log and confirms its lines are
recognised.

Because the logs carry no message headers or bodies, only metadata is ever
collected. Full instructions in [docs/install.md](docs/install.md); audit
details in [docs/audit.md](docs/audit.md).

### Two things that are not the same

| Command | Effect |
| --- | --- |
| `mailut audit remove …` | stops **future** collection; deletes nothing |
| `mailut audit purge …` | **deletes** retained evidence |

Default retention is 30 days, default collection level is metadata only, and
complete message retention is disabled by default.

```bash
mailut audit purge --expired --dry-run
mailut audit purge --expired --yes
```

`mailut-purge.timer` runs the expired purge daily.

### Mail rejected before DATA

If Postfix refuses a sender during the connection, or after `HELO`,
`MAIL FROM` or `RCPT TO`, the sending server never transmitted any headers or
body. Such an event therefore has **no Subject, no Message-ID and no body** —
`mailut` reports them as `unavailable (rejected before DATA)` and never invents
them. Remote IP, HELO, envelope addresses, the SMTP response and the Postfix
reason are all still recorded.

And when a search finds nothing, the answer is "no matching SMTP activity was
recorded during the retained period" — never "the sender did not send it". This
server's records only establish what this server observed.

## Upgrade and remove

Upgrade from your checkout; configuration and audit data are kept, and the
database is copied before any schema change:

```bash
git pull && sudo make install && sudo systemctl restart mailut-audit.service
```

Remove:

```bash
sudo mailut uninstall                  # keeps config and audit data
sudo mailut uninstall --remove-config
sudo mailut uninstall --remove-data    # deletes retained mail evidence
sudo mailut uninstall --purge          # == --remove-config --remove-data
```

Uninstall works from the install manifest, offline, and without the checkout.
See [docs/operations.md](docs/operations.md).

## Layout

```
/usr/local/sbin/mailut                     command
/usr/local/lib/mailut/                     application library
/usr/local/share/mailut/                   example config, install manifest
/usr/local/share/man/man8/mailut.8         manual
/usr/local/share/man/man5/mailut.conf.5    configuration manual
/etc/mailut/mailut.conf                    configuration
/var/lib/mailut/mailut.sqlite3             audit database (0600)
/var/lib/mailut/backups/                   copies taken before schema migrations
```

## Tests

```bash
make test     # unit + CLI + staged-install tests; no Mailu, Docker or network
make check    # byte-compile, unit files, man pages
```

## Documentation

- [docs/install.md](docs/install.md) — installation, what the collector reads, systemd
- [docs/audit.md](docs/audit.md) — scopes, retention, querying
- [docs/architecture.md](docs/architecture.md) — how it is put together
- [docs/operations.md](docs/operations.md) — day-to-day, upgrading, uninstall
- [SECURITY.md](SECURITY.md) — threat model and handling of untrusted data

`man 8 mailut` and `man 5 mailut.conf` are the reference.

## Note on history

This repository previously held `mailu-queue-tracker`, a set of shell scripts
(`mailu-queue-watch.sh` and friends). Mailu Tools replaces them entirely and is
intentionally **not** backward compatible: the command, configuration file,
paths and systemd units are all new. See
[docs/operations.md](docs/operations.md#migrating-from-mailu-queue-tracker).

This code was written with AI assistance and reviewed before release.
