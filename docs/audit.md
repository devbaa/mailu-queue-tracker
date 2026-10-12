# The audit subsystem

## What it is for

A persistent record of what this server decided about **inbound** mail, so that
questions like these have factual answers weeks later:

- Did our Mailu server ever see this sender?
- Did it reject the SMTP connection?
- Was it greylisted?
- Did Rspamd classify it as spam, and with what score and symbols?
- Did the sender retry?
- Was the message accepted, and was it delivered?
- What happened to mail addressed to this customer?

It is an evidence store, not a mailbox and not an archive.

## Collection is opt-in

Nothing is recorded until a scope exists.

```bash
mailut audit scopes
# No audit scopes configured: nothing is being collected.
```

## Scopes

A scope names a set of **inbound recipients**:

| Type | Meaning | Specificity |
| --- | --- | --- |
| `all` | every local recipient | 0 |
| `domain` | every recipient at one domain | 1 |
| `email` | one exact envelope recipient | 2 |

A scope is never interpreted as the remote *sender*.

```bash
mailut audit add all
mailut audit add domain customer.example
mailut audit add email legal@example.com

mailut audit remove all
mailut audit remove domain private.example.com
mailut audit remove email noisy@example.com
```

`add` means "ensure this is collected". `remove` means "ensure this is not
collected" — it records an explicit exclusion, which is why it keeps working
sensibly while `all` is active.

### Precedence

**The most specific applicable rule wins. At equal specificity, exclusion
wins. When nothing applies, the recipient is not collected.**

```bash
mailut audit add all
mailut audit remove domain internal.example.com
mailut audit add email monitored@internal.example.com
```

gives:

```
all domains collected
except internal.example.com
except that monitored@internal.example.com is collected
```

Check any address against the rules:

```bash
$ mailut audit scopes --test monitored@internal.example.com
monitored@internal.example.com: collected via email monitored@internal.example.com (level metadata, retention 30d)

$ mailut audit scopes --test other@internal.example.com
other@internal.example.com: not collected
```

Domains, and the domain part of addresses, are matched case-insensitively, as
SMTP requires; local parts are matched case-insensitively too. Input is
validated strictly — `mailut audit add domain "not a domain"` is a usage error
(exit 2), not a silently stored rule.

### Local recipients and the `all` scope

Set `local_domains` in `mailut.conf` to the domains this server accepts mail
for. The `all` scope then matches only those, keeping outbound recipients out of
the audit. Left empty, `all` matches every inbound recipient observed.

Authenticated submission (a local account sending outwards) is never audited:
lines carrying `sasl_username=` are skipped, as are deliveries over the outbound
`postfix/smtp` transport. Local delivery over `postfix/lmtp` is inbound and is
recorded.

### Rejections with no recipient

A connection refused during `CONNECT`, `HELO` or `MAIL FROM` has no recipient
yet, so no domain or email scope could be shown to apply. Such events are
collected only when the `all` scope is including.

## What is collected

For every matching inbound event, as much of this as actually exists:

```
occurred_at, received_at, source (rspamd|postfix)
stage        connect | helo | mail | rcpt | data | queue | delivery | unknown
action       accept | deliver | junk | greylist | soft_reject | reject |
             discard | policy_reject | virus_reject | unknown
envelope_from, envelope_to (+ their domains)
message_id
queue_id, session_id
remote_ip, helo
smtp_code, smtp_enhanced_code, reason
rspamd_score, rspamd_required, rspamd_action
spf, dkim, dmarc
message_size
```

plus every Rspamd symbol in a normalised table (`symbol`, `score`, `options`),
so you can ask "which mail did Spamhaus hit this month?".

The Subject and the header From/To are **not** in that list: the Mailu logs do
not record them, so they are never collected. (The schema keeps the columns,
which simply stay empty.)

**Accepted mail is collected too** (`store_accepted = true`). Without it you
could not tell "this server never saw it" from "this server accepted it", which
is most of the point.

Both the Rspamd **score** and the Rspamd **action** are stored, because the
action is authoritative: `force_actions`, settings and modules can change it
independently of the raw score. The classification above is derived from the
action, never from the score alone.

### A sequence, not a verdict

Events are per observation, so a greylisted message that comes back produces
several rows:

```
12:41:03Z  greylist    (rspamd)   reason: greylisting
12:46:09Z  accept      (rspamd)   score 0.42 / 6.00
12:46:10Z  deliver     (postfix)  stage: delivery
```

Nothing correlates them into a single verdict, because in general they cannot be
correlated with certainty. What is shown is what was observed.

## Collection level

Everything recorded is **metadata**: the fields listed above, and no body, no
attachments, no complete message and no header set. That is not a setting;
it is what the sources contain. `mailut` reads the Mailu container logs, and
neither Rspamd's per-message line nor Postfix's log carries message content.

The database can still represent the `headers` and `message` levels, but no
scope can be created at them, and asking says why rather than quietly
collecting less:

```bash
$ mailut audit add domain example.com --level headers
mailut: collection level 'headers' is not available: mailut collects from the
Mailu container logs, which carry no message headers or bodies; only 'metadata'
can be collected
$ echo $?
2
```

Per-scope retention still applies:

```bash
mailut audit add domain customer.example --retention 365
```

## Retention

Every record stores its **own** `expires_at`, computed when it is created from
the retention in force at that moment. Consequences:

- changing a scope from 30 to 365 days affects **future** records only;
- history is never re-evaluated against today's settings, and a nightly purge
  never has to recompute anything;
- there is no command that rewrites historical expiry — if that is ever needed,
  it will be an explicit one.

Default retention is 30 days (`audit.default_retention_days`).

## Querying

```bash
mailut audit show --since 24h
mailut audit show --domain example.com --since 7d
mailut audit show --recipient user@example.com --since 30d
mailut audit show --sender sender@example.net --since 7d
mailut audit show --recipient user@example.com --sender sender@example.net --since 7d
mailut audit show --symbol RBL_SPAMHAUS_SBL --since 30d
mailut audit show --action reject --action greylist --since 7d
mailut audit show --stage rcpt --since 7d
mailut audit show --queue-id 4AbCd67890
mailut audit show --message-id '<abc123@example.net>'
mailut audit show --ip 203.0.113.42 --since 7d
mailut audit show --since 24h --json
```

`--since` takes a duration (`30m`, `6h`, `7d`, `2w`) or an absolute timestamp;
`--after`/`--before` take timestamps. `--limit` caps output (0 means no cap) and
results are streamed in batches, never loaded whole.

`--json` emits **JSON Lines**: one complete object per line. Each object carries
a stable set of keys, its `symbols`, which `payloads` exist, and
`subject_available` so a consumer can distinguish "no subject was transmitted"
from "no subject was recorded".

Human output labels what cannot exist rather than leaving it blank:

```
2026-09-17T12:41:03Z  greylist
  stage:    data
  from:     sender@example.net
  to:       user@example.com
  ip:       203.0.113.42
  subject:  not recorded (not in the Mailu logs)
  msg-id:   abc123@example.net
  rspamd:   5.43 / 15.00 (greylist)
  reason:   greylisting
  spf:      pass
  dkim:     pass
  dmarc:    pass
  expires:  2026-10-17T12:41:03Z
```

## Mail rejected before DATA

An SMTP session can be refused during the connection, after `HELO`, after
`MAIL FROM` or after `RCPT TO` — all before the `DATA` command. At that point
the sending server has transmitted no headers and no body, so **there is no
Subject, no Message-ID, no header From/To and no message content**. They do not
exist; they were not "lost".

```
2026-09-17T13:02:51Z  reject
  stage:    rcpt
  from:     sender@example.net
  to:       user@example.com
  ip:       203.0.113.4
  smtp:     550 5.7.1
  subject:  unavailable (rejected before DATA)
  reason:   Recipient address rejected: Access denied
```

`mailut` enforces this: a pre-DATA event cannot carry a subject, message id,
header addresses or a payload, whatever an ingested record claims.

Rspamd never sees these sessions, which is why the collector also reads the
Postfix log.

## "They definitely sent it"

```bash
$ mailut audit show --sender supplier@example.net --recipient john@example.com --since 30d
No matching SMTP activity was recorded during the retained period.
This means this server holds no matching retained observation; it does not
establish what the sending system did.
```

That wording is deliberate. Absence from this server's records does not show
the sender did not send the message: their system may have failed before ever
contacting this MX, may have used a different MX, or the observation may have
expired. Report what was observed, not what was not done.

## Statistics

```bash
mailut audit stats
mailut audit stats --domain example.com --since 30d
mailut audit stats --since 30d --json
```

Counts by action and stage, pre-DATA rejections, oldest and newest record, the
next expiration, database and payload storage sizes, and the most common Rspamd
symbols. The categories are per event, not mutually exclusive per message: one
message can produce a greylist, an accept and a deliver.

## Purging

Purging is the **only** thing that deletes audit history.

```bash
mailut audit purge --expired --dry-run
mailut audit purge --expired --yes

mailut audit purge --domain example.com --dry-run
mailut audit purge --domain example.com

mailut audit purge --email john@example.com
mailut audit purge --before 2026-08-01

mailut audit purge --all --dry-run
mailut audit purge --all --yes
```

Exactly one selector is required. `--dry-run` reports event and payload-file
counts and changes nothing. `--all` requires typing `purge` at the prompt, or
`--yes`. Without a terminal and without `--yes`, a destructive purge aborts
(exit 3) rather than assuming consent.

Payload files are unlinked before the rows referencing them are deleted; a file
that cannot be removed is reported and its event is kept for the next run, so
the database never disagrees with the disk. `--expired` is idempotent and is
what `mailut-purge.timer` runs daily.

## Remove is not purge

```
mailut audit remove ...   stops future collection
mailut audit purge  ...   deletes retained evidence
```

After `mailut audit remove domain example.com`, everything already recorded for
that domain stays readable until its own expiry, or until you purge it
explicitly. This is the single most important distinction in the subsystem.

## Idempotent ingestion

Each event gets a deterministic fingerprint over its source, timestamp, stage,
action, envelope addresses, queue id, message id, remote IP, SMTP code, session
id and reason, with a uniqueness constraint behind it. So:

- reading the same log lines twice stores nothing new;
- restarting `mailut-audit.service` does not re-ingest history — the log cursor
  lives in SQLite and the fingerprints catch the deliberate one-second overlap;
- but a genuine retry five minutes after a greylist has a different timestamp
  and stays a distinct event, which is exactly what you need to see.
