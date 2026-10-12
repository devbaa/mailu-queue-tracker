# Installing Mailu Tools

## Requirements

- Linux with systemd (systemd is optional; without it, schedule `mailut watch`
  and `mailut audit purge --expired --yes` yourself)
- Python 3.9 or newer — standard library only, no pip packages
- Docker and Docker Compose, with a working Mailu installation
- `make` and the `install` utility to install, and for `mailut upgrade`
- root, because reading the Mailu queue and container logs needs the Docker
  socket

## Install from source

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
make test
sudo make install
```

`make install` puts files in the conventional places:

| Path | Contents |
| --- | --- |
| `/usr/local/sbin/mailut` | the command (0755) |
| `/usr/local/lib/mailut/` | application library (0644 files) |
| `/usr/local/share/mailut/` | example config, Rspamd snippet, install manifest |
| `/usr/local/share/man/man8/mailut.8` | manual |
| `/usr/local/share/man/man5/mailut.conf.5` | configuration manual |
| `/etc/mailut/mailut.conf` | configuration (0640), **only if absent** |
| `/var/lib/mailut/` | state (0700): database, messages, backups |
| `/etc/systemd/system/mailut-*` | units |

An existing `/etc/mailut/mailut.conf` is never overwritten, by an install or an
upgrade. The shipped example is always refreshed at
`/usr/local/share/mailut/mailut.conf.example`, so you can diff against it.

### Variables

The conventional ones are honoured:

```bash
make install PREFIX=/usr SYSCONFDIR=/etc LOCALSTATEDIR=/var \
             SYSTEMD_UNIT_DIR=/usr/lib/systemd/system
```

`DESTDIR` works for packaging and for inspecting an install without touching
the system:

```bash
rm -rf /tmp/mailut-root
make install DESTDIR=/tmp/mailut-root
find /tmp/mailut-root -type f
```

A staged install skips `systemctl daemon-reload`.

## Configure

```bash
sudoedit /etc/mailut/mailut.conf
mailut config check
```

At minimum set `compose_dir` to the directory holding your Mailu
`docker-compose.yml`. If your service names differ from Mailu's defaults, set
`smtp_service`, `front_service` and `antispam_service` too.

Setting `local_domains` is recommended if you intend to use the `all` audit
scope: it stops outbound recipients being swept into the audit.

Every setting is documented in `man 5 mailut.conf`.

## Enable services

Installing and enabling are separate steps; nothing starts by itself.

```bash
sudo systemctl enable --now mailut-audit.service   # log collector (long-running)
sudo systemctl enable --now mailut-purge.timer     # daily retention purge
sudo systemctl enable --now mailut-watch.timer     # queue sampling, every 5 min
```

or:

```bash
sudo make enable
```

Check them:

```bash
systemctl status mailut-audit.service
journalctl -u mailut-audit.service -f
systemctl list-timers 'mailut-*'
```

The collector on its own records nothing until a scope exists — see
[audit.md](audit.md).

### Why these units run as root

`mailut-audit.service` and `mailut-watch.service` reach the Docker socket to
read the Mailu queue and container logs. A dedicated unprivileged user, or
`PrivateNetwork=yes`, or `ProtectSystem=strict` would break that access, so the
units apply the hardening that is compatible with it — `NoNewPrivileges`,
`PrivateTmp`, `ProtectSystem=full`, `ProtectHome`, kernel/cgroup protections,
`MemoryDenyWriteExecute`, a restricted address-family set — rather than
directives that would silently stop collection. `mailut-purge.service` needs no
network at all and adds `PrivateNetwork=yes`.

## What the collector reads

There is nothing to wire up. `mailut-audit.service` reads two Mailu container
logs with `docker compose logs`, exactly as you would by hand:

```bash
cd /opt/mailu
docker compose logs --since 10m antispam   # Rspamd: one line per scanned message
docker compose logs --since 10m smtp       # Postfix: rejections before DATA, deliveries
```

Nothing listens on the network, and no Mailu or Rspamd configuration changes.
If Mailu is running and those commands work for root, collection works. If the
antispam container is not up yet — at boot, for example — that poll fails, is
logged, and is retried at the next interval; it does not crash the service.

The antispam lines are Rspamd's default per-message log line, which Mailu does
not customise. Check that this host's lines are recognised:

```bash
mailut audit doctor
```

The `rspamd log` check reads the recent antispam log and parses it the way the
collector will. It passes when the lines are present and recognised, warns
when there are none in the window (no mail was scanned yet), and fails when
lines are present but none is recognised — meaning Rspamd's `log_format` was
changed on this host, so no Rspamd decision would be recorded.

Two limits come from the log itself:

- **No headers or bodies.** The logs contain neither, so only metadata is
  collected; `mailut audit add --level headers` is refused with that reason.
- **Long recipient lists are cut.** Rspamd names at most `log_task_max_elts`
  recipients per line (7 by default). A message to more is attributed to those
  only, and the event's reason says so; the other recipients still appear in
  the smtp log as they are delivered or rejected.

`doctor` also checks the database, the Mailu compose directory and services,
permissions, scope levels and the units. It changes nothing and exits 4 if a
critical check fails.

## Without systemd

Run the collector under whatever supervisor you have:

```
/usr/local/sbin/mailut audit collect
```

and schedule the periodic work, for example with cron:

```cron
*/5 * * * * root /usr/local/sbin/mailut watch
17 3  * * * root /usr/local/sbin/mailut audit purge --expired --yes
```

## Upgrading

```bash
mailut upgrade --check
sudo mailut upgrade
```

or re-run `sudo make install` from a newer checkout — both preserve
configuration and data and both go through the same install path. See
[operations.md](operations.md).

## Removing

```bash
sudo mailut uninstall          # keeps /etc/mailut and /var/lib/mailut
sudo make uninstall            # same thing, via the installed manifest
```

`make uninstall` delegates to `mailut uninstall`, so there is only one removal
implementation, and neither destroys audit data by default.
