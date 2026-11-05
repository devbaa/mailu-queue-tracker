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
recipients, HELO names, Message-IDs, Rspamd symbol options and Postfix
rejection text.

- **Never in a shell.** Every external program — `docker compose`, `postqueue`,
  `postsuper` — is run as an argument vector through `subprocess`, with no
  shell, no string interpolation and no `eval`. `postsuper` receives queue ids
  on stdin. The configuration file is parsed as INI and is never sourced or
  executed.
- **Never in a path.** Nothing derived from ingested text ever forms a path
  component. Message content is never stored at all.
- **Never in SQL.** Every statement is parameterised. No query is assembled from
  a value; the only interpolation is a placeholder count.
- **Escaped before printing.** Human output passes untrusted strings through a
  sanitiser that escapes C0/C1 control characters and collapses newlines, so a
  crafted value cannot rewrite a terminal or forge a line of output.
- **Never fatal.** An unparseable log line is counted and skipped; the parsers
  return nothing rather than raise.

## The collector

The collector opens no network socket. It reads the Mailu antispam and smtp
container logs through the Docker socket, as `docker compose logs` does, so
there is no endpoint to expose, authenticate or firewall, and nothing another
process could post fabricated evidence to. It changes no Mailu or Rspamd
configuration.

## Stored data

- The database is mode 0600 and the state directory 0700, owned by root.
  Copies taken before a schema migration have the same modes. `mailut doctor`
  warns if anything is looser.
- Only metadata is collected. No body or header set is ever stored, because
  the logs that are read contain none, and a scope asking for more is refused
  rather than accepted and downgraded.
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

`mailut uninstall` checks for root up front, before deleting anything.

## Upgrades

There is no self-upgrade. Upgrading is `git pull && sudo make install` from a
checkout you control, so `mailut` never downloads, unpacks or runs anything
from the network, and never contacts GitHub at all.

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
