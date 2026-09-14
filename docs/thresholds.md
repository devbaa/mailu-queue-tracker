# Thresholds and tuning

The watcher has warning and critical thresholds for each volume signal. For the configurable `*_WARN` and `*_CRIT` values, the implementation fires when the observed value is **greater than** the configured number. For example, `QUEUE_WARN=200` warns at 201 queued messages, not 200.

The overall `severity` is the highest level reached by any signal. `reasons=` records every signal that fired.

Configure thresholds in `/etc/mailu-queue-watch.conf`.

## Default profile

```bash
QUEUE_WARN=200
QUEUE_CRIT=500

DEFERRED_WARN=100
DEFERRED_CRIT=300

SENDER_SENT_WARN=50
SENDER_SENT_CRIT=150

BULK_SENDER_MSGS=50
MULTI_SENDER_WARN=3
MULTI_SENDER_CRIT=5

SENDER_QUEUE_WARN=100
SENDER_QUEUE_CRIT=300

RCPT_DOMAINS_WARN=25
RCPT_DOMAINS_CRIT=50

BOUNCE_DEFER_RATE_WARN=20
BOUNCE_DEFER_RATE_CRIT=40

SPAM_BLOCK_WARN=1
SPAM_BLOCK_CRIT=5
```

`BULK_SENDER_MSGS` is different from the warning/critical pairs: a sender is considered bulk-like when its volume is **greater than or equal to** this value. `MULTI_SENDER_WARN` and `MULTI_SENDER_CRIT` are then evaluated with the normal strict `>` threshold rule.

Spam-block thresholds are also inclusive: `SPAM_BLOCK_WARN=1` warns on the first matching rejection, and `SPAM_BLOCK_CRIT=5` becomes critical at five matching rejections.

Any detected rate-limit rejection is currently critical regardless of the configurable volume thresholds.

`WINDOW` controls the log sampling window, defaulting to `15m`. The systemd timer runs every five minutes, so adjacent samples normally overlap.

## Small transactional servers

The defaults are intended for a relatively busy server and may be too high for low-volume installations. A smaller starting profile might be:

```bash
QUEUE_WARN=20
QUEUE_CRIT=50
DEFERRED_WARN=10
DEFERRED_CRIT=30
SENDER_SENT_WARN=10
SENDER_SENT_CRIT=30
BULK_SENDER_MSGS=10
MULTI_SENDER_WARN=2
MULTI_SENDER_CRIT=3
SENDER_QUEUE_WARN=20
SENDER_QUEUE_CRIT=50
RCPT_DOMAINS_WARN=10
RCPT_DOMAINS_CRIT=20
BOUNCE_DEFER_RATE_WARN=20
BOUNCE_DEFER_RATE_CRIT=40
SPAM_BLOCK_WARN=1
SPAM_BLOCK_CRIT=5
```

Treat this only as a starting point. Tune from real traffic rather than assuming one profile is correct for every Mailu installation.

## Tuning workflow

Run the watcher without automatic containment and review normal traffic first:

```bash
mailu-queue-report.sh
grep 'severity=warning' /var/log/mailu-queue-alerts.log | wc -l
```

Raise thresholds that repeatedly classify normal traffic as abusive. Lower thresholds that are clearly too permissive for the server's normal volume. Keep reputation-related signals such as spam-block responses and rate-limit events under separate scrutiny because they mean something different from simple queue growth.

## Reason strings

| Reason | Meaning |
| --- | --- |
| `queue_total_gt_N` | total queue size exceeded `N` |
| `deferred_queue_gt_N` | deferred queue size exceeded `N` |
| `sasl_sender_sent_gt_N` | one SASL user's volume exceeded `N` in `WINDOW` |
| `multiple_bulk_senders_gt_N` | count of bulk-like SASL users exceeded `N` |
| `sender_queue_backlog_gt_N` | one envelope sender's backlog exceeded `N` |
| `rcpt_domain_fanout_gt_N` | one sender's distinct recipient-domain count exceeded `N` |
| `bounce_defer_rate_pct_gt_N` | bounce/defer percentage exceeded `N` |
| `rate_limit_seen` | at least one rate-limit rejection was detected |
| `spam_blacklist_terms_seen` | spam/blocklist rejection count reached the warning threshold |
| `spam_blacklist_blocks_ge_N` | spam/blocklist rejection count reached the critical threshold |
