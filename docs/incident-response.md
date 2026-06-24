# Incident response

What to do when the tracker fires a critical alert that looks like a compromised
account. Commands assume you are in your Mailu compose directory
(`cd /opt/mailu`).

## 1. Confirm it's abuse, not a transient hiccup

Look at the alert's `reasons=` and the snapshot the watcher saved under
`/var/lib/mailu-queue-watch/snapshots/<timestamp>/`. Real compromise usually
shows **several** of: a single `top_sasl_sender` spiking, remote
`spam/blacklist/blocked` replies, `rate_limit_seen`, a high
`bounce_defer_rate`, and one sender fanning out across many recipient domains.

A single deferred spike with **no** spam/rate-limit signal and a *normal* top
SASL sender is more likely a flaky remote MX — watch, don't act.

```bash
# who is authenticating and how much, right now
docker compose logs --since=30m smtp | grep -oE 'sasl_username=[^,[:space:]]+' \
  | cut -d= -f2 | sort | uniq -c | sort -nr | head

# what remote servers are saying
docker compose logs --since=30m smtp | grep -Ei 'spam|blacklist|blocked|rate' | tail
```

## 2. Contain the compromised account (do this manually first)

Identify the account from `top_sasl_sender`, then **disable it / rotate its
password** through your normal Mailu admin process:

- **Mailu admin UI:** Users → the account → disable, or set "Enable" off, and
  reset the password. Disabling submission stops further sending immediately.
- **CLI:** `docker compose exec admin flask mailu user ...` per your Mailu
  version, or change the password in the UI.

Rotating the password kills the attacker's authenticated session for that
credential. If several `noreply@…`-style accounts are implicated, treat the
shared origin (leaked list, reused password) as the root cause.

## 3. Drain the bad mail from the queue

Inspect first, then act. **Look before you delete** — make sure you're removing
the abusive sender's mail, not legitimate backlog.

```bash
# what's queued, by sender
docker compose exec -T smtp postqueue -j \
  | grep -oE '"sender": *"[^"]*"' | sort | uniq -c | sort -nr | head

# delete only the compromised sender's queued mail (example sender)
docker compose exec -T smtp sh -c \
  'postqueue -j | grep -F "\"sender\": \"noreply@example.com\"" \
   | grep -oE "\"queue_id\": *\"[^\"]+\"" | cut -d\" -f4 | postsuper -d -'

# flush remaining (legitimate) deferred mail once the abuser is locked out
docker compose exec -T smtp postqueue -f
```

`postsuper -d ALL` deletes the **entire** queue — only use it if you're certain
everything queued is abusive.

## 4. Reputation cleanup

Heavy honeypot sending can get your IP/domain listed. After containment:

- Check your sending IP on the major blocklists it was rejected by (the alert's
  remote replies name them — Spamhaus, Barracuda, etc.) and use their delisting
  forms once you've stopped the abuse.
- Verify SPF/DKIM/DMARC are intact so legitimate mail keeps authenticating.

## 5. Automatic containment — only after a week of clean alerting

Start alert-only. Once thresholds are tuned and you trust them, you can wire
`ALERT_COMMAND` to take action. Bias toward **safe** actions:

**Safe (recommended):**
- Alert (Telegram/Slack/email)
- Snapshot the queue + logs *(done automatically on every alert)*
- Record top senders and sample queue IDs

**Risky (manual, or only with high-confidence rules + a human in the loop):**
- Deleting deferred mail
- Stopping the `smtp` container (takes down *all* mail)
- Firewalling outbound port 25
- Disabling users automatically

A defensible automatic rule, if you want one: **only** when a single SASL user
exceeds the critical send threshold **and** spam/blacklist blocks are present
(i.e. `reasons` contains both `sasl_sender_sent_gt_*` and a spam reason), disable
*that one account* via the Mailu CLI from `ALERT_COMMAND`. Never auto-delete mail
or stop the container.

## 6. Weekly review

```bash
mailu-queue-report.sh                       # summary: alerts, top senders, hits

# or by hand:
grep 'severity=' /var/log/mailu-queue-alerts.log | tail -50
grep '^top_sasl ' /var/log/mailu-queue-watch.log | sort | uniq -c | sort -nr | head -30
grep -E 'spam_blocks_[^ ]*=[1-9]' /var/log/mailu-queue-watch.log | tail -50
grep -E 'rate_limits_[^ ]*=[1-9]' /var/log/mailu-queue-watch.log | tail -50
```

Use the review to retune thresholds (see [thresholds.md](thresholds.md)) and to
spot slow-burn abuse that stays just under the critical levels.
