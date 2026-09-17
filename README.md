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

`mailut doctor` verifies configuration, Docker, the database, permissions, the
collector and the systemd units. It changes nothing.

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
mailut audit add email legal@example.com --level headers

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
mailut audit show --symbol RBL_SPAMHAUS --since 30d
mailut audit stats --domain example.com --since 30d
```

To receive Rspamd decisions, copy the shipped exporter snippet into your Mailu
overrides — `mailut` never edits Mailu configuration itself:

```bash
sudo cp /usr/local/share/mailut/rspamd/mailut-exporter.conf \
        /opt/mailu/overrides/rspamd/
cd /opt/mailu && sudo docker compose restart antispam
mailut audit doctor
```

The antispam container cannot reach the host's loopback address, so the
exporter's `url` and `collector.bind` must both name an address it *can* reach
— usually the Docker bridge gateway, `172.17.0.1`. `mailut` accepts a
non-loopback bind only if it is the gateway of a **bridge** network the
**antispam container is actually attached to**: a merely private address could
be your LAN, a `macvlan` gateway is usually the real upstream router, and an
unrelated project's bridge is not reachable from Mailu at all. An address it
cannot verify is refused, not assumed safe.

Set `collector.token_file` as well, and put the same token in the exporter's
`password`. The bind rules decide who can reach the collector; the token
decides who may submit evidence, which is what stops another container on the
same network forging audit records.

`mailut audit doctor` checks every part of this: that an override in your Mailu
tree posts to this collector's address, that the container can actually reach
that URL, and that the exporter's credentials will be accepted. Full
instructions in [docs/install.md](docs/install.md); audit details in
[docs/audit.md](docs/audit.md).

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

```bash
mailut upgrade --check
sudo mailut upgrade
sudo mailut upgrade --version 1.1.0
sudo mailut upgrade --dry-run

sudo mailut uninstall                  # keeps config and audit data
sudo mailut uninstall --remove-config
sudo mailut uninstall --remove-data    # deletes retained mail evidence
sudo mailut uninstall --purge          # == --remove-config --remove-data
```

Upgrades come from this project's public GitHub releases. No GitHub account or
token is needed, the release tarball's SHA-256 is always verified, and the
original clone is not required — delete it after installing if you like.
Ordinary uninstall preserves `/etc/mailut` and `/var/lib/mailut`.

See [docs/operations.md](docs/operations.md).

## Layout

```
/usr/local/sbin/mailut                     command
/usr/local/lib/mailut/                     application library
/usr/local/share/mailut/                   example config, Rspamd snippet, manifest
/usr/local/share/man/man8/mailut.8         manual
/usr/local/share/man/man5/mailut.conf.5    configuration manual
/etc/mailut/mailut.conf                    configuration
/var/lib/mailut/mailut.sqlite3             audit database (0600)
/var/lib/mailut/messages/                  stored messages, if enabled (0700)
/run/mailut/                               lifecycle lock
```

## Tests

```bash
make test     # unit + CLI + staged-install tests; no Mailu, Docker or network
make check    # byte-compile, unit files, man pages
```

## Documentation

- [docs/install.md](docs/install.md) — installation, Rspamd wiring, systemd
- [docs/audit.md](docs/audit.md) — scopes, levels, retention, querying
- [docs/architecture.md](docs/architecture.md) — how it is put together
- [docs/operations.md](docs/operations.md) — day-to-day, upgrade, uninstall, releases
- [SECURITY.md](SECURITY.md) — threat model and handling of untrusted data

`man 8 mailut` and `man 5 mailut.conf` are the reference.

## Note on history

This repository previously held `mailu-queue-tracker`, a set of shell scripts
(`mailu-queue-watch.sh` and friends). Mailu Tools replaces them entirely and is
intentionally **not** backward compatible: the command, configuration file,
paths and systemd units are all new. See
[docs/operations.md](docs/operations.md#migrating-from-mailu-queue-tracker).

This code was written with AI assistance and reviewed before release.
