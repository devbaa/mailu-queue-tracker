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
sudo systemctl enable --now mailut-audit.service   # collector (long-running)
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

## Wire up Rspamd

Mailu Tools never edits Mailu or Rspamd configuration. The exporter snippet is
installed as data for you to copy deliberately:

```bash
sudo mkdir -p /opt/mailu/overrides/rspamd
sudo cp /usr/local/share/mailut/rspamd/mailut-exporter.conf \
        /opt/mailu/overrides/rspamd/
```

The container cannot reach the host's loopback address, so **the default
`bind = 127.0.0.1` does not work for this** — both ends have to point at an
address the container can reach. On a normal Linux Docker install that is the
bridge gateway, usually `172.17.0.1`:

```bash
ip -4 addr show docker0        # find your gateway address
```

Set **both** sides to it:

```ini
# /etc/mailut/mailut.conf
[collector]
bind = 172.17.0.1
port = 8765
```

```text
# the url in mailut-exporter.conf
url = "http://172.17.0.1:8765/rspamd";
```

That address is reachable by containers on this host and by nothing else, as
long as your firewall does not forward the port — which matters, because the
collector is unauthenticated. `mailut` refuses a wildcard (`0.0.0.0`) or a
publicly routable bind unless you pass `--allow-remote` deliberately.

If your Mailu network is not the default bridge, use that network's gateway
address instead.

Then restart the container and verify:

```bash
cd /opt/mailu && sudo docker compose restart antispam
mailut audit doctor
```

`doctor` checks that the database is writable, the collector answers, the Mailu
compose directory looks right and the smtp service is reachable; that an Rspamd
override in your Mailu tree actually targets this collector's port; that the
antispam container can reach the collector; that no scope asks for a collection
level the host disables; and the state of the units. It changes nothing and
exits 4 if a critical check fails.

The two Rspamd checks are the ones that catch a half-finished setup: `rspamd
exporter` looks for a `metadata_exporter` in `<compose_dir>/overrides/rspamd/`
pointing at your collector port, and `rspamd -> collector` runs an HTTP request
*from inside the antispam container*. If the container has neither `curl` nor
`wget`, that second check reports "not verified" rather than passing.

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
