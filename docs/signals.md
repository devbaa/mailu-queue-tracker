# Signals

What `mailu-queue-watch.sh` measures on every run, and how.

## Queue signals (from `postqueue`)

Read via `docker compose exec -T smtp postqueue -j` (JSON, preferred) with a
fallback to `postqueue -p` (text). Parsed by `lib/parse-queue.awk`.

| Metric | Meaning |
| --- | --- |
| `queue_total` | Messages in the whole queue (all queue names). |
| `deferred_queue` | Messages in the `deferred` queue — couldn't be delivered yet. |
| `queue_top_sender` / `queue_top_sender_count` | Envelope sender with the most messages currently queued, and how many. A single account dominating the queue is the clearest compromise tell. |
| `queue_top_domain_sender` / `queue_top_domain_count` | The sender addressing the most *distinct recipient domains*. Spam/honeypot runs fan out across many unrelated domains. |
| `queue_unique_domains` | Distinct recipient domains across the whole queue. |

## Delivery signals (from the `smtp` container log window)

Read via `docker compose logs --since=$WINDOW smtp` (default `15m`). Counted with
`grep`:

| Metric | How it's matched |
| --- | --- |
| `sent` | lines with `status=sent` |
| `bounced` | lines with `status=bounced` |
| `deferred` | lines with `status=deferred` |
| `bounce_defer_rate_pct` | `(bounced + deferred) / (sent + bounced + deferred) × 100` over the window |
| `rate_limits` | lines matching `RATELIMIT_REGEX` (Postfix/Mailu throttling) |
| `spam_blocks` | lines matching `SPAM_REGEX` (remote *spam/blacklist/blocked/reputation* replies) |
| `top_sasl` / `top_sasl_count` | most frequent `sasl_username=` in the window — *which authenticated credential* is sending, and how many messages |

Both regexes are configurable (`RATELIMIT_REGEX`, `SPAM_REGEX`) and matched
case-insensitively.

## Why both queue and log views

They answer different questions and corroborate each other:

- **Logs** tell you the *rate* right now and *which credential* (`sasl_username`)
  is authenticating — the compromised account.
- **The queue** tells you the *standing backlog* and *who it's addressed to*
  (sender + recipient-domain fan-out), which survives even if log retention is
  short.

`sasl_username` appears on the submission (`smtpd`) log line, while
`status=sent|bounced|deferred` appears on the later delivery (`smtp`/`qmgr`)
line — Postfix does not repeat the SASL user on the delivery line. So per-user
*send rate* comes from the logs and per-sender *backlog / fan-out* comes from the
queue; the tracker deliberately uses both rather than trying to stitch queue IDs
together.

## The compromise fingerprint

Any one signal can be benign (a newsletter, a flaky remote MX). The pattern that
specifically indicates a **compromised account or abusive bulk SMTP** is the
combination:

```
top SASL sender volume spikes
  + remote replies saying spam / blacklisted / blocked
  + Postfix/Mailu rate-limit rejections
  + deferred queue rising
  + one sender fanning out to many recipient domains
```

That is exactly the set of `reasons=` the watcher emits together in a critical
alert.
