# Install, configure, use, update & uninstall

A complete operational guide for `mailu-queue-tracker`. For the *what/why* see
the [README](../README.md); for tuning see [thresholds.md](thresholds.md); for
the signals see [signals.md](signals.md).

- [Requirements](#requirements)
- [Install](#install)
- [Configure](#configure)
- [Verify](#verify)
- [How it works](#how-it-works)
- [Using it](#using-it)
- [Schedule without systemd (cron)](#schedule-without-systemd-cron)
- [Update](#update)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- A host running **Mailu via `docker compose`**, with shell access as **root**
  (the watcher talks to Docker and writes to `/var/log` and `/var/lib`).
- **bash**, **awk** (mawk or gawk), and coreutils (`grep`, `sed`, `sort`,
  `uniq`, `cut`, `tr`, `date`) — present on any standard Linux host.
- **`docker compose`** (v2) or **`docker-compose`** (v1, set `COMPOSE_CMD`).
- **systemd** for the 5-minute timer (optional — use cron otherwise).
- **`curl`** only if you want Telegram/Slack notifications.

No database, agent, or language runtime is needed.

## Install

From a checkout on the Mailu host:

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
sudo ./install.sh            # installs files, config, and the 5-minute timer
```

`sudo ./install.sh --no-enable` installs everything but does **not** start the
timer (handy if you want to run manually first).

What the installer puts where:

| Path | Mode | What |
| --- | --- | --- |
| `/usr/local/sbin/mailu-queue-watch.sh` | 0755 | the watcher |
| `/usr/local/sbin/mailu-queue-report.sh` | 0755 | weekly-review summary |
| `/usr/local/sbin/mailu-front-ips.sh` | 0755 | real source-IP finder |
| `/usr/local/lib/mailu-queue-watch/*.awk` | 0644 | queue/front parsers |
| `/etc/mailu-queue-watch.conf` | 0600 | your config (copied from the example **only if absent**) |
| `/etc/systemd/system/mailu-queue-watch.{service,timer}` | 0644 | scheduling |
| `/var/lib/mailu-queue-watch/` | 0750 | state, `notify-state`, `snapshots/` |
| `/var/log/mailu-queue-watch.log` | — | metrics (created on first run) |
| `/var/log/mailu-queue-alerts.log` | — | alerts (created on first alert) |

The installer is **idempotent** — re-running it updates the scripts and units
while keeping your existing config (see [Update](#update)).

## Configure

Edit `/etc/mailu-queue-watch.conf`. At minimum set where your compose file lives:

```bash
COMPOSE_DIR="/opt/mailu"          # directory containing your docker-compose.yml
COMPOSE_CMD="docker compose"      # or "docker-compose" for the v1 binary
```

Then, optionally, notifications and thresholds:

```bash
TELEGRAM_BOT_TOKEN="..."          # from @BotFather
TELEGRAM_CHAT_ID="..."
SLACK_WEBHOOK_URL="..."           # incoming webhook
ALERT_COMMAND=""                  # or pipe the alert to any command via stdin
```

The shipped thresholds suit a **busy** server. On a small/transactional server
they are far too high — lower them (there's a ready-to-paste profile in
[thresholds.md](thresholds.md)). The full option list with comments is in
[`etc/mailu-queue-watch.conf.example`](../etc/mailu-queue-watch.conf.example).

> The config holds secrets, so it is installed `chmod 600`. It is also
> git-ignored — only the `.example` template is committed.

## Verify

```bash
sudo mailu-queue-watch.sh --print     # compute metrics, print them, change nothing
```

You should get a line like `severity=ok ... queue_total=… top_sasl=…`. If every
value is `0`, the script can't reach your queue/logs — see
[Troubleshooting](#troubleshooting). Check the timer is scheduled:

```bash
systemctl list-timers | grep mailu-queue-watch
```

---

## How it works

```
systemd timer (every 5 min)
        │
        ▼
mailu-queue-watch.sh ──► docker compose exec smtp postqueue -j   (queue snapshot)
        │            └─► docker compose logs --since=WINDOW smtp  (recent log window)
        │
        ├─ parse (lib/parse-queue.awk) → queue size, per-sender backlog, rcpt fan-out
        ├─ count log signals → sent/bounced/deferred, rate-limits, spam blocks, SASL senders
        ├─ evaluate thresholds → severity = ok | warning | critical, with reasons[]
        │
        ├─► append one key=value line to  /var/log/mailu-queue-watch.log   (always)
        └─ if not ok:
             ├─► append detail to         /var/log/mailu-queue-alerts.log
             ├─► snapshot queue + logs to /var/lib/mailu-queue-watch/snapshots/<ts>/
             └─► notify (Telegram/Slack/command) — rate-limited by ALERT_COOLDOWN_MINUTES
```

- **Run cycle.** The timer triggers a `oneshot` service that runs the watcher
  once. Each run is an independent point-in-time measurement over the last
  `WINDOW` (default `15m`); windows overlap because the timer fires every 5 min.
- **Severity.** The highest level any signal reaches. `reasons=` lists each
  signal that fired (e.g. `rate_limit_seen`, `multiple_bulk_senders_gt_5`). Full
  list in [thresholds.md](thresholds.md); meanings in [signals.md](signals.md).
- **Cooldown.** A sustained incident does **not** notify every 5 minutes:
  `notify-state` records the last notification; re-notify happens only after
  `ALERT_COOLDOWN_MINUTES`, *except* a warning→critical escalation always fires
  immediately. The metrics and alert **logs** are still written every run.
- **Queue can read 0 during an incident.** If Mailu's per-user rate limiter
  rejects abuse at `RCPT`, nothing queues — which is why the log signals
  (`rate_limits`, `top_sasl`, `bulk_senders`) matter, not queue size alone.
- **Safety.** Parsed fields are attacker-controlled and are never `eval`-ed or
  put in a shell command; alerts are metadata-only. See [SECURITY.md](../SECURITY.md).

---

## Using it

### Run manually

```bash
sudo mailu-queue-watch.sh                 # full run: log, alert, snapshot, notify
sudo mailu-queue-watch.sh --print         # print metrics only; write/notify nothing
sudo mailu-queue-watch.sh --dry-run       # compute + show what WOULD alert; write nothing
sudo mailu-queue-watch.sh --config /path/to.conf
```

### Watch the output

```bash
tail -f /var/log/mailu-queue-watch.log    # one metrics line per run
tail -f /var/log/mailu-queue-alerts.log   # detailed records when thresholds trip
```

### Read a metrics line

```
time=… severity=critical queue_total=812 deferred_queue=640
  sent_15m=18 bounced_15m=70 deferred_15m=590 bounce_defer_rate_pct=97
  rate_limits_15m=4 spam_blocks_15m=210
  top_sasl=noreply@example.com top_sasl_count=430 bulk_senders=7
  queue_top_sender=… queue_top_domain_sender=… queue_top_domain_count=180
```

`severity`/`reasons` are the headline; `top_sasl*` and `bulk_senders` say *which*
and *how many* credentials; `rate_limits`/`spam_blocks` are reputation events.
Every field is defined in **[glossary.md](glossary.md)**.

### Weekly review

```bash
sudo mailu-queue-report.sh                # recent alerts, noisiest senders, hits
sudo mailu-queue-report.sh --lines 100
```

### Drain abusive mail from the queue

Removing a compromised account doesn't clear its queued mail — drain it per
address (exact match, dry-run first, confirm prompt):

```bash
sudo mailu-queue-drain.sh --dry-run noreply@mx.example.com   # count only
sudo mailu-queue-drain.sh noreply@mx.example.com             # delete
sudo mailu-queue-drain.sh --hold noreply@mx.example.com      # hold instead
sudo mailu-queue-drain.sh -r victim@honeypot.example       # match by recipient
```

### Find an attacker's source IP

The `smtp` log only shows the front (XCLIENT); the real IP is in the front log:

```bash
sudo mailu-front-ips.sh --since 6h                  # top external IPs + accounts
sudo mailu-front-ips.sh --since 6h --user noreply@  # narrow to a suspect account
```

### Responding to an alert

Start in alert-only mode; don't auto-delete mail or disable accounts on day one.
The containment playbook (disable the account, drain the queue, block the IP,
reputation cleanup) is in [incident-response.md](incident-response.md).

---

## Schedule without systemd (cron)

If the host has no systemd, the installer skips the units. Add a cron entry:

```cron
*/5 * * * * root /usr/local/sbin/mailu-queue-watch.sh --config /etc/mailu-queue-watch.conf >/dev/null 2>&1
```

(Drop the `root` column in a user crontab.)

---

## Update

The installer is idempotent, so updating is just:

```bash
cd mailu-queue-tracker
git pull
sudo ./install.sh            # overwrites scripts/parsers/units; KEEPS your config
```

This replaces `/usr/local/sbin/*` scripts, the `lib/*.awk` parsers, and the
systemd units, then reloads and re-enables the timer. Your
`/etc/mailu-queue-watch.conf`, logs, and snapshots are left untouched.

After a release that adds new options, compare your config with the template to
pick up new tunables (missing options just fall back to built-in defaults, so
nothing breaks if you skip this):

```bash
diff -u /etc/mailu-queue-watch.conf etc/mailu-queue-watch.conf.example
```

---

## Uninstall

```bash
sudo ./install.sh --uninstall    # remove scripts, parsers, and systemd units
```

This stops/disables the timer and removes the installed binaries and units, but
**keeps** your config and logs so you don't lose history or settings. To remove
everything:

```bash
sudo ./install.sh --purge        # also deletes config, state dir, and default logs
```

`--purge` removes `/etc/mailu-queue-watch.conf`, `/var/lib/mailu-queue-watch/`
(including snapshots), and the default `/var/log/mailu-queue-*.log`. If you
configured custom `LOG_FILE` / `ALERT_FILE` / `STATE_DIR` paths, delete those
manually. Both modes require root.

---

## Troubleshooting

**All metrics are `0` / `--print` shows everything empty.**
The script can't reach the queue or logs. Check, from the host:

```bash
cd /opt/mailu && docker compose exec -T smtp postqueue -p   # does this work?
docker compose logs --since=15m smtp | head                 # any output?
```

Fixes: point `COMPOSE_DIR` at the directory with your `docker-compose.yml`;
confirm the service name matches `SMTP_SERVICE` (default `smtp`); for the legacy
binary set `COMPOSE_CMD="docker-compose"`.

**No notifications even though alerts appear in the log.**
Confirm `TELEGRAM_*` / `SLACK_WEBHOOK_URL` are set and `curl` is installed; check
you aren't inside the `ALERT_COOLDOWN_MINUTES` window; run `--print` to confirm
`severity` actually crosses a threshold. Use `--dry-run` to see the exact alert
text that would be sent.

**Counts look low / rates seem wrong.**
Docker's `json-file` log driver may rotate out lines inside your `WINDOW`. Check
`docker compose logs --since=15m smtp | wc -l`, and raise the container log
retention or shorten `WINDOW` if needed.

**`permission denied` running manually.**
Run as root (`sudo`); the systemd service already runs as root.

**systemd diagnostics.**
```bash
systemctl status mailu-queue-watch.timer
systemctl list-timers | grep mailu-queue-watch
journalctl -u mailu-queue-watch.service --since '1 hour ago'
```

**Test it end-to-end without touching production** — feed a fixture in:
```bash
QUEUE_SOURCE_CMD="printf ''" \
LOG_SOURCE_CMD="cat tests/fixtures/smtp-incident.log" \
MQW_LIB_DIR=lib bin/mailu-queue-watch.sh --config /dev/null --print
```
