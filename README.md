# mailu-queue-tracker

Small Mailu/Postfix queue watcher for detecting unusual SMTP activity and cleaning queued mail from a compromised account.

The normal deployment is an installed systemd service. Configuration is in:

```text
/etc/mailu-queue-watch.conf
```

## Remove an email address from the queue

Always check first:

```bash
sudo mailu-queue-drain.sh --dry-run user@example.com
```

Then delete all queued messages whose **envelope sender** is exactly that address:

```bash
sudo mailu-queue-drain.sh user@example.com
```

The command shows the number of matches and asks for confirmation before deleting them. It exits with an error if the Postfix queue cannot be read; a read failure is not reported as zero matches.

Skip confirmation when needed:

```bash
sudo mailu-queue-drain.sh --yes user@example.com
```

Match by **recipient** instead of sender:

```bash
sudo mailu-queue-drain.sh --dry-run --recipient victim@example.com
sudo mailu-queue-drain.sh --recipient victim@example.com
```

Hold matching messages instead of deleting them:

```bash
sudo mailu-queue-drain.sh --hold user@example.com
```

Matching is exact and case-insensitive. `example.com` will not match `user@example.com`.

Queue cleanup does **not** disable the Mailu account or stop new mail from being submitted. Secure or disable a compromised account separately.

## Check the watcher

```bash
sudo mailu-queue-watch.sh --print
systemctl status mailu-queue-watch.timer
systemctl list-timers mailu-queue-watch.timer
```

View logs:

```bash
tail -f /var/log/mailu-queue-watch.log /var/log/mailu-queue-alerts.log
```

## Find source IPs

```bash
sudo mailu-front-ips.sh --since 6h
sudo mailu-front-ips.sh --since 6h --user user@example.com
```

## Update the installed service

From the existing checkout:

```bash
git pull
sudo ./install.sh
```

The installer updates scripts, parsers, and systemd units while keeping an existing `/etc/mailu-queue-watch.conf`.

For a new host only:

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
sudo ./install.sh
```

## Commands

```text
mailu-queue-watch.sh       check queue and SMTP activity
mailu-queue-drain.sh       delete or hold queued mail for one address
mailu-front-ips.sh         inspect source IPs and authenticated users
mailu-queue-report.sh      summary report
mailu-alert-test.sh        test configured alerts
```

## Tests

```bash
tests/run.sh
```

See [`docs/install.md`](docs/install.md) for the concise operator guide, [`docs/thresholds.md`](docs/thresholds.md) for tuning, and [`docs/incident-response.md`](docs/incident-response.md) for containment steps.
