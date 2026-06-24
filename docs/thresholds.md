# Thresholds & tuning

Each signal has a **warning** and a **critical** level. Crossing `*_WARN` raises
a warning; crossing `*_CRIT` raises a critical. The overall `severity` is the
highest level any signal reached, and `reasons=` lists every level that fired.

Set all of these in `/etc/mailu-queue-watch.conf`.

## Shipped defaults (busy server)

```
QUEUE_WARN=200            QUEUE_CRIT=500          # total queued messages
DEFERRED_WARN=100         DEFERRED_CRIT=300       # deferred queue
SENDER_SENT_WARN=50       SENDER_SENT_CRIT=150    # SASL msgs by one user in WINDOW
BULK_SENDER_MSGS=50                               # a sender >= this in WINDOW is "bulk-like"
MULTI_SENDER_WARN=3       MULTI_SENDER_CRIT=5     # this many bulk-like senders at once
SENDER_QUEUE_WARN=100     SENDER_QUEUE_CRIT=300   # msgs queued by one envelope sender
RCPT_DOMAINS_WARN=25      RCPT_DOMAINS_CRIT=50    # distinct rcpt domains, one sender
BOUNCE_DEFER_RATE_WARN=20 BOUNCE_DEFER_RATE_CRIT=40   # percent over WINDOW
SPAM_BLOCK_WARN=1         SPAM_BLOCK_CRIT=5       # remote spam/blacklist hits in WINDOW
```

Plus two signals with fixed levels:

- **Any** rate-limit rejection (`rate_limits > 0`) ⇒ **critical**. Postfix/Mailu
  only throttles when something is sending abnormally fast.
- `WINDOW` is the sampling window for all log-based rates (default `15m`); the
  timer runs every 5 minutes, so windows overlap — each run is an independent
  point-in-time "in the last 15 minutes" measurement.

## Small / transactional servers

The defaults are **far too high** for a low-volume server. If you normally send
a handful of messages an hour, a compromised account sending 40/15min would slip
under `SENDER_SENT_WARN=50`. Scale the per-sender and queue numbers down to a
small multiple of your real peak. A reasonable starting point:

```
QUEUE_WARN=20             QUEUE_CRIT=50
DEFERRED_WARN=10          DEFERRED_CRIT=30
SENDER_SENT_WARN=10       SENDER_SENT_CRIT=30
BULK_SENDER_MSGS=10       MULTI_SENDER_WARN=2     MULTI_SENDER_CRIT=3
SENDER_QUEUE_WARN=20      SENDER_QUEUE_CRIT=50
RCPT_DOMAINS_WARN=10      RCPT_DOMAINS_CRIT=20
BOUNCE_DEFER_RATE_WARN=20 BOUNCE_DEFER_RATE_CRIT=40
SPAM_BLOCK_WARN=1         SPAM_BLOCK_CRIT=5
```

## How to tune in one week

1. Install and run in **alert-only** mode (the default — no containment).
2. After ~7 days, look at your real baseline:
   ```bash
   mailu-queue-report.sh          # peak per-sender volume, noisiest senders
   grep severity=warning /var/log/mailu-queue-alerts.log | wc -l
   ```
3. Raise any threshold that fires on normal traffic to just above your observed
   peak; lower any that never fires when you *know* volume was high.
4. Keep the two "hard" criticals (rate-limit seen, spam/blacklist ≥ crit) — they
   are reputation events, not volume noise, and rarely false-positive.

## Reason strings

These appear in `reasons=` and in alert bodies, so you can alert/route on them:

| Reason | Signal |
| --- | --- |
| `queue_total_gt_N` | total queue size |
| `deferred_queue_gt_N` | deferred queue size |
| `sasl_sender_sent_gt_N` | one SASL user's send volume in WINDOW |
| `multiple_bulk_senders_gt_N` | N distinct SASL users each sending bulk volume at once |
| `sender_queue_backlog_gt_N` | one envelope sender's queued backlog |
| `rcpt_domain_fanout_gt_N` | one sender's distinct recipient domains |
| `bounce_defer_rate_pct_gt_N` | bounce+defer percentage |
| `rate_limit_seen` | any rate-limit rejection (always critical) |
| `spam_blacklist_terms_seen` / `spam_blacklist_blocks_ge_N` | remote spam/blacklist replies |
