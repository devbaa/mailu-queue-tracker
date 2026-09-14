# Operations

The service is normally already installed on the Mailu host. Day-to-day work should use the installed commands in `/usr/local/sbin` and the config at `/etc/mailu-queue-watch.conf`.

## Queue cleanup

Check before deleting:

```bash
sudo mailu-queue-drain.sh --dry-run user@example.com
```

Delete queued messages whose envelope sender exactly matches the address:

```bash
sudo mailu-queue-drain.sh user@example.com
```

Match a recipient instead:

```bash
sudo mailu-queue-drain.sh --dry-run --recipient victim@example.com
sudo mailu-queue-drain.sh --recipient victim@example.com
```

Hold messages instead of deleting them:

```bash
sudo mailu-queue-drain.sh --hold user@example.com
```

Matching is exact and case-insensitive. The helper exits with an error if it cannot read the Postfix queue; a queue-read failure must not be mistaken for zero matches.

Queue cleanup does not disable a Mailu account. Secure or disable the compromised account separately before or while draining its queued mail.

## Watcher

Run one read-only check:

```bash
sudo mailu-queue-watch.sh --print
```

Check systemd:

```bash
systemctl status mailu-queue-watch.timer
systemctl list-timers mailu-queue-watch.timer
journalctl -u mailu-queue-watch.service --since '1 hour ago'
```

Watch logs:

```bash
tail -f /var/log/mailu-queue-watch.log /var/log/mailu-queue-alerts.log
```

## Source IPs

```bash
sudo mailu-front-ips.sh --since 6h
sudo mailu-front-ips.sh --since 6h --user user@example.com
```

## Alerts

```bash
sudo mailu-alert-test.sh --print
sudo mailu-alert-test.sh
```

The first command prints the test notification without sending it. The second sends to configured channels.

## Configuration

The installed configuration is:

```text
/etc/mailu-queue-watch.conf
```

Important values are `COMPOSE_DIR`, `COMPOSE_CMD`, `SMTP_SERVICE`, `FRONT_SERVICE`, thresholds, and optional notification settings. The file may contain secrets and is installed with mode `0600`.

The repository template is [`etc/mailu-queue-watch.conf.example`](../etc/mailu-queue-watch.conf.example).

## Update

From the existing checkout:

```bash
git pull
sudo ./install.sh
```

The installer replaces the installed scripts, parsers, and systemd units but keeps an existing `/etc/mailu-queue-watch.conf`.

Installed commands:

```text
/usr/local/sbin/mailu-queue-watch.sh
/usr/local/sbin/mailu-queue-report.sh
/usr/local/sbin/mailu-front-ips.sh
/usr/local/sbin/mailu-queue-drain.sh
/usr/local/sbin/mailu-alert-test.sh
```

## Uninstall

Remove installed scripts, parsers, and systemd units while preserving configuration, logs, and state:

```bash
sudo ./install.sh --uninstall
```

Remove those retained files as well:

```bash
sudo ./install.sh --purge
```

If custom `LOG_FILE`, `ALERT_FILE`, or `STATE_DIR` paths are configured, remove those custom paths manually after a purge.

## Fresh install

Only needed on a new host:

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
sudo ./install.sh
```

Then edit `/etc/mailu-queue-watch.conf` and verify with:

```bash
sudo mailu-queue-watch.sh --print
```

## Tests

From the repository checkout:

```bash
tests/run.sh
```

The test suite does not require a running Mailu instance; it feeds synthetic fixtures through the scripts' test hooks.
