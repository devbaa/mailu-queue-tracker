# mailu-queue-tracker

Small Mailu/Postfix queue watcher for detecting unusual SMTP activity and cleaning queued mail from a compromised account.

The watcher runs from systemd every 5 minutes. Configuration is in:

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

The command shows the number of matching messages and asks for confirmation before deleting them.

To skip the confirmation prompt:

```bash
sudo mailu-queue-drain.sh --yes user@example.com
```

To match by **recipient** instead of sender:

```bash
sudo mailu-queue-drain.sh --dry-run --recipient victim@example.com
sudo mailu-queue-drain.sh --recipient victim@example.com
```

To hold matching messages instead of deleting them:

```bash
sudo mailu-queue-drain.sh --hold user@example.com
```

Matching is exact and case-insensitive. `example.com` will not match `user@example.com`.

Removing mail from the queue does **not** disable the Mailu account or stop new mail from being submitted. Disable or secure a compromised account separately.

## Check the watcher

Run one check manually:

```bash
sudo mailu-queue-watch.sh --print
```

Check the timer:

```bash
systemctl status mailu-queue-watch.timer
systemctl list-timers mailu-queue-watch.timer
```

View logs:

```bash
tail -f /var/log/mailu-queue-watch.log /var/log/mailu-queue-alerts.log
```

## Find source IPs

Show external client IPs seen by the Mailu front container:

```bash
sudo mailu-front-ips.sh --since 6h
```

Filter for one account:

```bash
sudo mailu-front-ips.sh --since 6h --user user@example.com
```

## Install or update

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
sudo ./install.sh
```

For an existing checkout:

```bash
git pull
sudo ./install.sh
```

An existing `/etc/mailu-queue-watch.conf` is kept during updates.

## Main commands

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

More detailed operational notes remain under [`docs/`](docs/).
