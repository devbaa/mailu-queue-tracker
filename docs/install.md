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
long as your firewall does not forward the port.

`mailut` verifies this rather than guessing. It asks Docker which networks the
**antispam container** is attached to, inspects only those, and accepts the
bind only if it is the gateway of one of them **and that network uses the
bridge driver** (or if the bind is loopback). Three things it deliberately does
*not* accept:

- **A merely private address.** Your LAN or VPC address is private too, and
  binding there would expose the collector to every machine on that network.
- **A `macvlan` or `ipvlan` gateway.** Those drivers put containers directly on
  the physical network, and the gateway is normally your real upstream router —
  Docker's own documentation uses examples like `--gateway=192.168.32.254`.
  Docker does not apply to them the packet-filtering rules it creates for
  bridge networks either.
- **The gateway of an unrelated Docker project.** The antispam container cannot
  reach it, so the collector would simply never receive anything.

An address Docker cannot be queried about is refused rather than assumed safe.
Anything else requires `--allow-remote` deliberately.

If your Mailu network is not the default bridge, use that network's gateway.
This prints exactly what `mailut` looks at:

```bash
cd /opt/mailu
docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{println $n}}{{end}}' \
  "$(docker compose ps -q antispam)" |
  xargs docker network inspect \
    -f '{{.Name}} {{.Driver}}{{range .IPAM.Config}} {{.Gateway}}{{end}}'
```

Use a gateway from a line whose driver is `bridge`.

### The shared token (required)

Restricting the bind address controls *who can reach* the collector. It does
not establish *who is posting*: another container on the same bridge could
submit invented audit records. Since the point of the audit trail is to be
evidence, the collector **will not start without a shared secret**.

```bash
sudo mailut audit token generate
```

That writes a random token to `/etc/mailut/collector.token` (mode `0600`,
directory created if needed) and prints the two lines to paste into the
exporter rule:

```text
# in mailut-exporter.conf, alongside the url
user = "mailut";
password = "<the generated token>";
```

`make enable` runs `mailut audit token generate --if-missing`, so a fresh
install gets one automatically; an existing token is never replaced unless you
pass `--force`, because that would stop Rspamd submitting until its `password`
is updated too. Print the current value with `mailut audit token show`.

Rspamd's `metadata_exporter` cannot send an arbitrary header, but its HTTP
backend does send Basic credentials built from `user`/`password`, and `mailut`
accepts the token as the password. `Authorization: Bearer <token>` also works,
which is easier with `curl`.

`mailut` refuses to use a token file other accounts can read, and refuses to
start on a missing, empty or too-short one rather than quietly accepting
everything. `/health` stays unauthenticated so you can check wiring, but
reports its counters only to authenticated callers.

`mailut audit doctor` fails if the token is missing or unusable, and fails if
the exporter's password does not match the one the collector expects — a
mismatch that would otherwise show up only as silently missing evidence, since
every export would be rejected with 401.

If you genuinely need an open endpoint, say so explicitly:

```ini
[collector]
allow_unauthenticated = true
```

`doctor` warns for as long as that is set, and the collector repeats the
warning at every start.

### IPv6

An IPv6 bind works the same way: `bind = ::1`, or the IPv6 gateway of a bridge
network the antispam container is attached to. Write the exporter URL with
brackets, as URLs require:

```text
url = "http://[fd00::1]:8765/rspamd";
```

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

The two Rspamd checks are the ones that catch a half-finished setup. `rspamd
exporter` finds the `metadata_exporter` in `<compose_dir>/overrides/rspamd/`,
reads the URL it actually posts to, and compares it with the collector's
address and port — so an exporter aimed at the wrong host is reported, not
accepted because it happens to mention the right port. `rspamd -> collector`
then makes an HTTP request to **that same URL** from inside the antispam
container. If the container has neither `curl` nor `wget`, the second check
reports "not verified" rather than passing.

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
