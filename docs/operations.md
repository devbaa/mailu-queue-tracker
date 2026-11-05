# Operations

## Daily use

```bash
mailut status          # is everything where it should be?
mailut doctor          # read-only diagnostics, exits 4 on a critical failure
mailut report          # what the watcher has seen lately
journalctl -u mailut-audit.service -f
systemctl list-timers 'mailut-*'
```

`mailut status` shows the configuration file, Mailu compose location, database
path, size and schema version, scope and event counts, the latest event and
purge, message-storage size, the collector state and the state of each owned
unit. `--json` for scripts.

## Responding to a compromised account

```bash
# 1. See the damage.
mailut queue list
mailut watch --print

# 2. Find where it is coming from (the smtp log only sees the front proxy).
mailut ips --since 6h
mailut ips --since 6h --user compromised@example.com

# 3. Check before deleting anything.
mailut queue drain --sender compromised@example.com --dry-run

# 4. Stop the bleeding.
mailut queue drain --sender compromised@example.com
#    ...or keep the evidence and release later:
mailut queue hold --sender compromised@example.com
mailut queue release --sender compromised@example.com
```

Draining the queue does **not** disable the account or stop new submissions.
Change the password and revoke sessions in Mailu separately.

`--dry-run` and `--yes` work on all three; on a terminal without `--yes` you are
asked to confirm, and with no terminal and no `--yes` the command aborts with
exit 3 rather than assuming consent.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | operational or runtime failure |
| 2 | invalid command line or argument |
| 3 | a destructive action was not confirmed |
| 4 | a verification or doctor check failed |

Useful in cron and monitoring: `mailut doctor || alert`.

## Retention and purging

`mailut-purge.timer` runs `mailut audit purge --expired --yes` daily. To check
or run it by hand:

```bash
systemctl list-timers mailut-purge.timer
mailut audit purge --expired --dry-run
sudo systemctl start mailut-purge.service
```

Ad-hoc purges (a customer leaves, a legal request, a mistake):

```bash
mailut audit purge --domain example.com --dry-run
mailut audit purge --domain example.com
mailut audit purge --email john@example.com
mailut audit purge --before 2026-08-01
```

Remember: **`mailut audit remove` stops collecting; `mailut audit purge`
deletes.** Removing a scope never deletes history.

## Database maintenance

```bash
mailut db migrate          # create/migrate (also happens automatically)
mailut db optimize         # PRAGMA optimize + ANALYZE + WAL checkpoint
mailut db optimize --vacuum  # full rewrite; needs free disk, do it deliberately
```

A `VACUUM` is never run on a schedule. Run one after a large purge if you want
the space back.

## Upgrading

Upgrade from the checkout you installed from:

```bash
cd /path/to/mailu-queue-tracker
git pull
make test
sudo make install
sudo systemctl restart mailut-audit.service
```

`make install` replaces the program, library, man pages and units, reloads
systemd, and never touches `/etc/mailut/mailut.conf` or anything under
`/var/lib/mailut`. Enabled units stay enabled; nothing is enabled for you.

If the new version changes the database schema, the first command to open the
database migrates it — normally the restarted collector. Before changing the
schema of a database that already holds data, it copies it into
`/var/lib/mailut/backups/mailut-schema<N>-<time>.sqlite3` using SQLite's backup
API. If a migration fails, that copy is what you go back to. A schema the
installed version does not know (from a newer checkout) is refused rather
than guessed at.

There is no `mailut upgrade` and no automatic update check: `mailut` never
contacts GitHub.

## Uninstalling

```bash
sudo mailut uninstall                        # keeps config and data
sudo mailut uninstall --remove-config        # also removes /etc/mailut
sudo mailut uninstall --remove-data          # also removes /var/lib/mailut
sudo mailut uninstall --purge                # == --remove-config --remove-data
sudo mailut uninstall --dry-run
sudo make uninstall                          # same implementation
```

`--purge` means exactly those two flags and nothing more.

Uninstall is entirely local: no network, no GitHub, no checkout, no Makefile. It
reads the install manifest, stops and disables the units it owns, removes only
the files listed there, prunes the directories it created if they are empty, and
runs `systemctl daemon-reload`. It never touches Mailu's containers, Mailu's
units, Docker itself, or unrelated files under `/usr/local`.

Before a destructive removal it prints what is about to be destroyed and
requires the word `remove` to be typed:

```
Retained Mailu Tools data:
  audit events:      183421
  audit scopes:      17
  stored messages:   411
  database size:     91.4 MB
  payload storage:   264.2 MB
  database backups:  3

This will permanently delete Mailu Tools data:

  audit scopes
  retained SMTP/Rspamd events
  SQLite database
  stored message payloads
  database backups

Type "remove" to continue:
```

An empty line is not consent. `--yes` skips the prompt for automation.

Installed files that differ from the manifest are reported before removal; they
are still removed, because they are application-owned. This never applies to
`mailut.conf`, the database or the message archive.

Nothing in Mailu needs undoing: `mailut` only ever read its logs.

Re-running uninstall is harmless.

## Backups

Worth backing up:

- `/etc/mailut/mailut.conf`
- `/var/lib/mailut/mailut.sqlite3` — take it with SQLite's backup API or
  `sqlite3 ... ".backup"`, not `cp`, while the collector is running

`/var/lib/mailut/backups/` holds the copies taken before each schema migration;
prune old ones yourself.

## Migrating from mailu-queue-tracker

Mailu Tools replaces the earlier shell scripts in this repository and is
**intentionally not backward compatible**. Nothing is migrated automatically.

| Old | New |
| --- | --- |
| `mailu-queue-watch.sh` | `mailut watch` |
| `mailu-queue-watch.sh --print` | `mailut watch --print` |
| `mailu-queue-drain.sh ADDR` | `mailut queue drain --sender ADDR` |
| `mailu-queue-drain.sh -r ADDR` | `mailut queue drain --recipient ADDR` |
| `mailu-queue-drain.sh --hold ADDR` | `mailut queue hold --sender ADDR` |
| `mailu-front-ips.sh` | `mailut ips` |
| `mailu-queue-report.sh` | `mailut report` |
| `mailu-alert-test.sh` | removed (no notification integrations) |
| `install.sh` | `make install` |
| `/etc/mailu-queue-watch.conf` | `/etc/mailut/mailut.conf` (INI, new keys) |
| `/var/log/mailu-queue-watch.log` | journald + `watch_samples` in SQLite |
| `/var/lib/mailu-queue-watch/` | `/var/lib/mailut/` |
| `mailu-queue-watch.service/.timer` | `mailut-watch.service/.timer` |

To remove the old installation:

```bash
sudo systemctl disable --now mailu-queue-watch.timer
sudo rm -f /usr/local/sbin/mailu-queue-*.sh /usr/local/sbin/mailu-front-ips.sh \
           /usr/local/sbin/mailu-alert-test.sh
sudo rm -rf /usr/local/lib/mailu-queue-watch
sudo rm -f /etc/systemd/system/mailu-queue-watch.service \
           /etc/systemd/system/mailu-queue-watch.timer
sudo systemctl daemon-reload
# then, when you no longer want the old data:
sudo rm -f /etc/mailu-queue-watch.conf /var/log/mailu-queue-*.log
sudo rm -rf /var/lib/mailu-queue-watch
```

Thresholds carry over conceptually — the `[watch]` section of `mailut.conf` has
the same knobs in lower case — but copy the values across by hand. Telegram,
Slack and custom alert commands have no equivalent: notification integrations
are out of scope, and `mailut watch` writes to the journal and the database
instead.
