# Glossary of metrics

Every field the tracker emits, what it means, and where it comes from. These
appear in three places:

- the **metrics log** / `--print` — one space-separated `key=value` line per run;
- the **alert** (Telegram/Slack/log) — the same data, formatted for humans;
- the optional **Prometheus** export (`PROM_TEXTFILE`).

> **The `_15m` suffix.** Keys like `sent_15m`, `rate_limits_15m` carry the sample
> window in their name. `15m` is the configured `WINDOW`; if you change `WINDOW`
> the suffix changes too (e.g. `sent_30m`). Window-based counts come from the
> `smtp` **log**; everything prefixed `queue_` is a point-in-time read of the
> **Postfix queue**.

## Run / status fields

| Field | Source | Meaning |
| --- | --- | --- |
| `time` | — | ISO-8601 timestamp of the run. |
| `severity` | derived | `ok`, `warning`, or `critical` — the highest threshold level any signal crossed this run. |
| `reasons` *(alert only)* | derived | Space-separated list of the specific thresholds that fired (e.g. `rate_limit_seen`). Full vocabulary in [thresholds.md](thresholds.md). |
| `summary` *(alert only)* | derived | One plain-language sentence describing what's happening, shown above the detail. |

## Queue fields (from `postqueue`)

A point-in-time snapshot of the mail queue. Independent of log retention.

| Field | Meaning |
| --- | --- |
| `queue_total` | Total messages in the queue (all queue names: incoming, active, deferred, hold). **Can read `0` during a live incident** if Mailu's rate limiter rejects abuse at `RCPT` before anything is queued. |
| `deferred_queue` | Messages in the **deferred** queue — accepted but not yet delivered because the remote server refused or temporarily failed them. A large deferred count usually means mail is being rejected downstream. |
| `queue_top_sender` | The envelope sender (`MAIL FROM`) with the most messages **currently queued**. `none` if the queue is empty. |
| `queue_top_sender_count` | How many messages that sender has in the queue right now. |
| `queue_top_domain_sender` | The sender addressing the most **distinct recipient domains** in the queue — a spam/honeypot blast fans out across many unrelated domains. |
| `queue_top_domain_count` | That sender's distinct recipient-domain count. |
| `queue_unique_domains` | Distinct recipient domains across the **whole** queue. |

## Delivery fields (from the `smtp` log window)

Counted over the last `WINDOW` (default `15m`) of the `smtp` container log.

| Field | Meaning |
| --- | --- |
| `sent_15m` | Messages logged with `status=sent` in the window. |
| `bounced_15m` | Messages logged with `status=bounced` (hard failure / rejected). |
| `deferred_15m` | Delivery attempts logged with `status=deferred` in the window. *(Distinct from `deferred_queue`, which is the standing backlog right now.)* |
| `bounce_defer_rate_pct` | `(bounced + deferred) / (sent + bounced + deferred) × 100` over the window. `0` when there were no delivery attempts. A high rate means most outbound mail is failing. |
| `rate_limits_15m` | Log lines matching `RATELIMIT_REGEX` — Postfix/Mailu throttling a sender (e.g. *"sending too many emails too fast"*). Any hit is treated as critical. |
| `spam_blocks_15m` | Log lines matching `SPAM_REGEX` — remote servers rejecting mail as *spam / blacklisted / blocked / bad reputation*. |
| `top_sasl` | The authenticated **SASL username** that submitted the most messages in the window — i.e. *which credential* is sending. `none` if no authenticated sends were seen. |
| `top_sasl_count` | That credential's message count in the window. |
| `bulk_senders` | How many **distinct** SASL users each sent ≥ `BULK_SENDER_MSGS` in the window. Several accounts sending bulk at once (none dominating) is the signature of a leaked-credential dump or attacker-provisioned senders. |

> **Why two sender views?** `top_sasl*` comes from the submission log and tells
> you *which login* is authenticating; `queue_top_sender*` comes from the queue
> and tells you *whose mail is backing up*. Postfix doesn't repeat the SASL user
> on the later delivery line, so per-user **send rate** comes from the log and
> per-sender **backlog / fan-out** comes from the queue — the tracker uses both
> rather than trying to stitch them together. See [signals.md](signals.md).

## The `top_sasl` table

Below each metrics line the log also records the busiest authenticated senders:

```
top_sasl   430 noreply@example.com
top_sasl   118 billing@example.com
```

`top_sasl <count> <username>`, up to the 10 highest in the window. `mailu-queue-report.sh` aggregates these across runs.

## Alert field names

The alert reformats the same numbers; a few are renamed for readability:

| Alert field | Same as metric | Notes |
| --- | --- | --- |
| `top_sasl_sender=X (N msgs/15m)` | `top_sasl` / `top_sasl_count` | The authenticating credential and its send volume. |
| `bulk_senders=N (>= M msgs each)` | `bulk_senders` | `M` is `BULK_SENDER_MSGS`. |
| `queue_top_sender=X (N queued)` | `queue_top_sender` / `_count` | Whose mail is backing up. |
| `top_recipient_fanout=X (N domains)` | `queue_top_domain_sender` / `_count` | Sender hitting the most distinct domains. |
| `bounce_defer_rate=R%` | `bounce_defer_rate_pct` | Same value, shown with a `%`. |

## Prometheus metrics (`PROM_TEXTFILE`)

When `PROM_TEXTFILE` is set, the same values are exported for node_exporter's
textfile collector:

| Prometheus metric | Same as |
| --- | --- |
| `mailu_queue_total` | `queue_total` |
| `mailu_queue_deferred` | `deferred_queue` |
| `mailu_queue_unique_recipient_domains` | `queue_unique_domains` |
| `mailu_messages_sent` | `sent_15m` |
| `mailu_messages_bounced` | `bounced_15m` |
| `mailu_messages_deferred` | `deferred_15m` |
| `mailu_bounce_defer_rate_percent` | `bounce_defer_rate_pct` |
| `mailu_rate_limit_rejections` | `rate_limits_15m` |
| `mailu_spam_block_rejections` | `spam_blocks_15m` |
| `mailu_top_sasl_sender_messages` | `top_sasl_count` |
| `mailu_bulk_senders` | `bulk_senders` |
| `mailu_severity{level="ok\|warning\|critical"}` | `severity` (as a label, value `1`) |

Only numeric values and the fixed `severity` label are exported — never
sender/username strings (see [SECURITY.md](../SECURITY.md)).

## Related

- [signals.md](signals.md) — why each signal matters and the compromise fingerprint.
- [thresholds.md](thresholds.md) — warning/critical levels and the `reasons=` vocabulary.
