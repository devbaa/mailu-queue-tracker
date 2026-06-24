# Security notes

This tool reads logs and the mail queue of a server that is, by assumption,
under attack (compromised-account abuse). The inputs it parses are therefore
**attacker-influenced**: SASL usernames, envelope senders, recipient addresses,
HELO names and remote rejection text can all contain content an attacker chose.
The design treats every parsed field as untrusted.

## How untrusted log/queue data is handled

- **Never `eval`-ed.** The only `eval` calls act on `*_SOURCE_CMD` values, which
  come from the config file (admin-controlled) or the test harness — never from
  log or queue content. Parser output is consumed with `read`, not `eval`.
- **No shell construction from data.** Attacker-controlled fields are never
  interpolated into a command line. `ALERT_COMMAND` is an admin-set command and
  the alert text reaches it on **stdin**, so log content cannot inject shell.
- **Parsers do no I/O.** `lib/*.awk` use only text functions — no `system()`,
  `getline`, or pipes to a shell.
- **Field values are bounded.** `jval()` stops at the first quote and log tokens
  stop at whitespace/comma, so a single crafted field cannot smuggle a newline
  and forge an extra metric or log line.
- **Display strings are sanitised.** Sender / SASL-user strings have whitespace,
  `=` and `"` stripped before entering the space-delimited `key=value` metric
  line, so a crafted address can't confuse a downstream log parser.
- **No data in Prometheus labels.** The textfile export uses numeric values and
  the fixed `severity` label only — never sender/username strings (which could
  otherwise break the exposition format).

## Secrets

- Notification secrets (Telegram token, Slack webhook) live only in
  `/etc/mailu-queue-watch.conf`, installed `chmod 600`, and are git-ignored
  (`*.conf`; only `*.conf.example` is committed).
- Alerts are **metadata-only**: counts, severities, and sender/recipient-domain
  *aggregates* — never message contents or full recipient lists.

## Evidence snapshots

On an alert the watcher writes the raw queue and recent `smtp`/`front` logs to
`STATE_DIR/snapshots/<timestamp>/` (default `0750`, root-owned). This is raw mail
metadata kept **locally on your host** as incident evidence — it is never
transmitted. Rotate or purge it per your retention policy.

## Test fixtures contain no real data

Every fixture under `tests/fixtures/` is synthetic and uses only reserved
identifiers: domains under `.example` / `example.com` / `example.org`
(RFC 2606), and IPs from `203.0.113.0/24` & `198.51.100.0/24` (RFC 5737) or
RFC 1918 private ranges. No real customer domains, usernames, or routable IPs
are committed. The test suite enforces this (a fixture-hygiene check fails CI if
a non-reserved domain or a routable IP appears under `tests/fixtures/`).

## Reporting an issue

Open a private security advisory on the repository, or contact the maintainer
directly rather than filing a public issue.
