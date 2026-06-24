# mailu-queue-tracker

Early detection of **compromised-account / abusive bulk SMTP** on a
[Mailu](https://github.com/mailu/mailu) (Postfix) host.

When an account password is compromised, the symptom is sudden authenticated
bulk sending: the queue grows, messages defer/bounce, remote servers reject mail
as *spam / blacklisted / blocked*, and Postfix/Mailu rate limits start firing.
This tracker watches queue **behaviour by sender, source, destination and
rejection reason** — not just queue size — and alerts before the damage spreads.

It is intentionally small: a Bash script driven by a config file, run every 5
minutes by a systemd timer, talking to your existing Mailu containers via
`docker compose`. No agent, no database.

```
docker compose ──► postqueue -j / -p ─┐
                                       ├─► mailu-queue-watch.sh ─► metrics log
docker compose ──► smtp container logs ┘            │                alert log
                                                    │                snapshot
                                                    └─► Telegram / Slack / cmd
```

## What it tracks

Every run it samples (see [docs/signals.md](docs/signals.md)):

| Signal | Source | Why it matters |
| --- | --- | --- |
| Total / deferred queue size | `postqueue` | Backlog from undeliverable bulk mail |
| Messages queued **per envelope sender** | `postqueue` | One account dominating the queue |
| Distinct **recipient domains per sender** | `postqueue` | Honeypot blasts fan out across many domains |
| Sent / bounced / deferred in the window | smtp logs | Delivery health and bounce/defer rate |
| Remote *spam/blacklist/blocked* replies | smtp logs | Reputation damage in progress |
| Rate-limit rejections | smtp logs | Postfix/Mailu throttling an abuser |
| Top authenticated **SASL** senders | smtp logs | *Which credential* is sending |
| **Count of bulk-like SASL senders** | smtp logs | *Several* accounts blasting at once — a credential dump or attacker-provisioned senders |

The combination that points at compromise — rather than a normal transient
delivery hiccup — is: **one (or several) SASL senders spiking + remote
spam/blacklist rejections + rate-limit hits + a rising deferred queue.**

## Quick start

```bash
git clone https://github.com/devbaa/mailu-queue-tracker.git
cd mailu-queue-tracker
sudo ./install.sh                 # installs scripts, config, systemd timer
sudo nano /etc/mailu-queue-watch.conf   # set COMPOSE_DIR + notifications
```

Then verify it can read your Mailu queue and logs:

```bash
sudo mailu-queue-watch.sh --print     # compute + print metrics, change nothing
```

You should see a `severity=ok ... queue_total=... top_sasl=...` line. The timer
runs the watcher every 5 minutes; tail the output with:

```bash
tail -f /var/log/mailu-queue-watch.log /var/log/mailu-queue-alerts.log
```

`install.sh --uninstall` removes the scripts and units (leaving your config and
logs); `--purge` removes everything. On hosts without systemd, run
`mailu-queue-watch.sh` from cron instead.

📖 **Full guide:** [docs/install.md](docs/install.md) covers installation, how it
works, day-to-day usage, updating, uninstalling, cron, and troubleshooting.

## Configuration

All behaviour lives in `/etc/mailu-queue-watch.conf` (sourced as Bash). The
essentials:

```bash
COMPOSE_DIR="/opt/mailu"          # dir containing your Mailu docker-compose.yml
COMPOSE_CMD="docker compose"      # use "docker-compose" for the legacy binary
TELEGRAM_BOT_TOKEN="..."          # optional
TELEGRAM_CHAT_ID="..."            # optional
SLACK_WEBHOOK_URL="..."           # optional
```

See [`etc/mailu-queue-watch.conf.example`](etc/mailu-queue-watch.conf.example)
for every option, and **[docs/thresholds.md](docs/thresholds.md)** for tuning —
the shipped defaults suit a busy server and are usually **far too high for a
small transactional server**, where you should lower them sharply.

Secrets live only in the config file (installed `chmod 600`). Alerts are
**metadata-only**: no recipient lists or message contents are ever sent.

## Alerts

When any threshold is crossed the watcher:

1. appends a detailed record to `/var/log/mailu-queue-alerts.log`;
2. snapshots the queue and recent `smtp`/`front` logs under
   `/var/lib/mailu-queue-watch/snapshots/<timestamp>/` (evidence for later);
3. sends a notification — **rate-limited** by `ALERT_COOLDOWN_MINUTES` so a
   sustained incident does not page you every 5 minutes, while an escalation
   (warning → critical) always notifies immediately.

Notification channels: Telegram, Slack incoming webhook, and/or an arbitrary
`ALERT_COMMAND` (the alert text is piped to it on stdin — e.g. `mail`, PagerDuty
`curl`, etc.).

A sample critical alert:

```
Mailu queue alert
noreply@example.com sent 430 messages in 15m and 97% are failing — rate-limited, rejected as spam/blacklisted, 7 accounts sending at once.

severity=critical
reasons=sasl_sender_sent_gt_150 multiple_bulk_senders_gt_5 rate_limit_seen spam_blacklist_blocks_ge_5
queue_total=812
deferred_queue=640
sent_15m=18 bounced_15m=70 deferred_15m=590
bounce_defer_rate=97%
rate_limits_15m=4
spam_blocks_15m=210
top_sasl_sender=noreply@example.com (430 msgs/15m)
bulk_senders=7 (>= 50 msgs each)
queue_top_sender=noreply@example.com (610 queued)
top_recipient_fanout=noreply@example.com (180 domains)
```

## Finding the attacker's source IP

The Mailu `front` proxies submission to the `smtp` container via `XCLIENT`, so
the `smtp` log only ever shows the front's own address. The real external IP is
in the **front** log:

```bash
mailu-front-ips.sh --since 6h                 # top external client IPs + users
mailu-front-ips.sh --since 6h --user noreply@  # narrow to a suspect account
```

It hides private/internal hops by default and lists, per IP, how many lines and
which usernames authenticated from it — feed the result to your firewall /
fail2ban. (If a compromised account shows *only* the front's own IP, the
submissions came through the front and you need the front nginx logs, not the
`smtp` ones — which is exactly when this helper earns its keep.)

## Draining abusive mail from the queue

Removing/disabling a compromised account stops new sending but leaves its mail
in the queue (Postfix keeps retrying it to the honeypots). Clear it per address —
**exact** match, dry-run first, with a confirm prompt:

```bash
mailu-queue-drain.sh --dry-run noreply@mx.example.com   # how many would go
mailu-queue-drain.sh noreply@mx.example.com             # delete (asks to confirm)
mailu-queue-drain.sh --hold noreply@mx.example.com      # hold instead (postsuper -H to release)
mailu-queue-drain.sh -r victim@honeypot.example       # match by recipient instead
```

`example.com` won't match `noreply@mx.example.com` (the address must be exact), and
it only ever touches the address you name, so legitimate forwarded mail sitting
in the queue is left alone — safer than `postsuper -d ALL` on a multi-tenant host.

## Responding to an alert

Start in **alert-only** mode. Don't auto-delete mail or auto-disable accounts on
day one — you may have legitimate transactional spikes. Once you trust the
thresholds, see **[docs/incident-response.md](docs/incident-response.md)** for
the containment playbook (disabling the compromised account in Mailu admin,
draining the queue, and the safe-vs-risky automatic actions).

## Metrics & dashboards

Each run appends one `key=value` line to `/var/log/mailu-queue-watch.log`, easy
to ship to Loki/Elastic or grep directly. Set `PROM_TEXTFILE` to also export
Prometheus metrics via the node_exporter textfile collector
(`mailu_queue_total`, `mailu_bounce_defer_rate_percent`,
`mailu_spam_block_rejections`, …).

`mailu-queue-report.sh` prints a weekly-review summary: recent alerts, noisiest
SASL senders, and the samples where spam/blacklist or rate-limit hits appeared.

## How it reads the queue

It prefers `postqueue -j` (JSON, Postfix ≥ 3.1 — what Mailu ships), which gives
robust per-message sender/recipient data, and falls back to parsing the classic
`postqueue -p` text listing. Log windows come from `docker compose logs --since`.

> **Note:** per-message attribution requires the messages to still be in the
> queue / recent logs. If the container log driver rotates aggressively, widen
> the retention or reduce the sample `WINDOW`. Deferred-queue counts in the text
> (`-p`) fallback are approximate; the JSON path is exact.

## Prevention (defence in depth)

This tracker *detects*. To *prevent*, also: enforce strong/unique passwords,
enable Mailu's per-user message rate limits (Admin → user settings), require
2FA on webmail/admin, and restrict who may relay. The tracker tells you when
those controls are being tested.

## Security

This tool parses data from a host that's under attack, so every parsed field
(SASL user, sender, recipient, HELO, rejection text) is treated as untrusted: no
parsed value is ever `eval`-ed or built into a shell command, parsers do no I/O,
display strings are sanitised before entering the metric line, and alerts are
metadata-only. Secrets stay in the `chmod 600` config (git-ignored). See
[SECURITY.md](SECURITY.md) for the full threat model.

## Repository layout

```
bin/mailu-queue-watch.sh      main watcher (config-driven, testable)
bin/mailu-queue-report.sh     weekly-review summary
bin/mailu-front-ips.sh        real client IPs from the front log (deanonymise XCLIENT)
bin/mailu-queue-drain.sh      delete/hold queued mail for one sender or recipient
lib/parse-queue.awk           postqueue -j / -p parser (mawk-compatible)
lib/parse-front.awk           front-log IP/user correlation (mawk-compatible)
lib/match-queue.awk           exact sender/recipient -> queue_id matcher (mawk-compatible)
etc/mailu-queue-watch.conf.example   documented config template
systemd/                      oneshot service + 5-minute timer
install.sh                    install / update / --uninstall / --purge
docs/install.md               install, usage, update, uninstall & troubleshooting
docs/                         signals, thresholds, incident response
SECURITY.md                   threat model: untrusted-data handling & secrets
tests/                        fixture-driven end-to-end tests (no Docker needed)
```

## Development & tests

The watcher abstracts its data sources behind `QUEUE_SOURCE_CMD` /
`LOG_SOURCE_CMD`, so the test suite feeds it fixtures and asserts on the metrics,
severity, alerting and cooldown — no Mailu required:

```bash
tests/run.sh          # runs shellcheck + end-to-end scenarios
```

Regenerate fixtures with `tests/gen-fixtures.sh`.
