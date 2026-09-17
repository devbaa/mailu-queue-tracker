# Security notes

Mailu Tools reads the logs and mail queue of a server that is, by assumption,
under attack, and it stores mail metadata — which is sensitive in itself. Both
facts shape the design.

## Reporting a vulnerability

Open a GitHub issue for anything already public. For something exploitable,
please use GitHub's private vulnerability reporting on the repository rather
than a public issue.

## Untrusted input

Everything ingested is chosen by a remote party: envelope senders and
recipients, HELO names, subjects, Message-IDs, Rspamd symbol options and
Postfix rejection text.

- **Never in a shell.** Every external program — `docker compose`, `postqueue`,
  `postsuper` — is run as an argument vector through `subprocess`, with no
  shell, no string interpolation and no `eval`. `postsuper` receives queue ids
  on stdin. The configuration file is parsed as INI and is never sourced or
  executed.
- **Never in a path.** Stored messages are written to generated filenames under
  a date hierarchy; nothing derived from a subject, sender or header ever forms
  a path component, and every write and delete is checked to stay inside the
  configured message directory.
- **Never in SQL.** Every statement is parameterised. No query is assembled from
  a value; the only interpolation is a placeholder count.
- **Escaped before printing.** Human output passes untrusted strings through a
  sanitiser that escapes C0/C1 control characters and collapses newlines, so a
  crafted subject cannot rewrite a terminal or forge a line of output.
- **Bounded.** The HTTP collector enforces a `Content-Length` limit, a record
  count per request and a stored-message size limit. Malformed JSON and bad
  base64 are 400s; an unparseable log line is counted and skipped, never fatal.

## The collector

The collector is **unauthenticated** and binds to `127.0.0.1` by default. It is
meant to be reachable only by the Rspamd container on the same host.

Binding it anywhere else requires `--allow-remote` and is reported as a warning
by `mailut doctor`. Do not expose it; there is no authentication to configure,
by design — access control is the host's firewall and the Docker network.

## Stored data

- The database is mode 0600, the state and message directories 0700, owned by
  root. `mailut doctor` warns if anything is looser.
- Complete message retention is **disabled by default** and must be enabled
  deliberately in `/etc/mailut/mailut.conf`. A scope cannot ask for a level the
  host forbids, and a request for one fails rather than being downgraded.
- Retained bodies are never printed by ordinary output; `mailut audit show` only
  reports that a payload exists.
- Every record carries an expiry, and the daily purge enforces it. Retention is
  a deletion guarantee, not a suggestion.
- `/etc/mailut/mailut.conf` is installed 0640. It holds no secrets by design:
  there are no tokens, webhooks or credentials anywhere in this application.

## Privileges

`mailut-audit.service` and `mailut-watch.service` run as root because reading
the Mailu queue and container logs requires the Docker socket — which is
effectively root anyway. A dedicated unprivileged user, `PrivateNetwork=yes` or
`ProtectSystem=strict` would break that access, so the units apply the hardening
that is compatible with it (`NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=full`, `ProtectHome`, kernel/cgroup protections,
`MemoryDenyWriteExecute`, a restricted address-family set) rather than
directives that would silently stop collection. `mailut-purge.service` touches
no network and adds `PrivateNetwork=yes`.

Commands that modify the system (`upgrade`, `uninstall`) check for root up
front, before downloading or deleting anything.

## Upgrades

- Release metadata and artifacts come from the project's public GitHub releases
  over HTTPS. No token, account, `gh` CLI or SSH key is involved.
- The tarball's SHA-256 is checked against the release's own `SHA256SUMS`. A
  mismatch aborts the upgrade, and there is deliberately no flag to ignore it.
  A release with no `SHA256SUMS` is refused.
- Nothing from the network is executed before verification, and nothing is ever
  piped from a download into a shell.
- Archives are validated member by member before extraction: absolute paths,
  `..` traversal, links escaping the extraction directory and device/fifo
  entries are all refused, and the tree is only inspected in a private
  temporary directory.
- `--version` takes a version, never a URL, so it cannot be pointed at an
  arbitrary remote location.
- `/run/mailut/lifecycle.lock` (an `flock`, not a PID file) prevents concurrent
  upgrade, uninstall or migration.

## Destructive operations

- Queue drain/hold and every purge selector support `--dry-run`.
- On a terminal, destructive commands confirm; with no terminal and no `--yes`
  they abort (exit 3) rather than assume consent.
- `audit purge --all` and `uninstall --remove-data` require a typed word
  (`purge`, `remove`) rather than a `[y/N]`, and print what is about to be
  destroyed first.
- Uninstall removes only files listed in the install manifest. It never
  recursively deletes `/usr/local/bin`, `/usr/local/lib`, `/usr/local/share` or
  `/etc/systemd/system`, never touches Mailu's containers, units or
  configuration, and preserves configuration and audit data unless explicitly
  told otherwise.

## Reporting what was observed

Where absence of evidence could be mistaken for evidence of absence, the output
says what the records show and nothing more:

> No matching SMTP activity was recorded during the retained period.
> This means this server holds no matching retained observation; it does not
> establish what the sending system did.

Similarly, a message rejected before the SMTP `DATA` command has no Subject,
Message-ID or body, because the sending server never transmitted them. Those
fields are reported as unavailable and are never fabricated — the code enforces
this regardless of what an ingested record claims.
