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
| 5 | another lifecycle operation holds the lock |

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

### From public releases

```bash
mailut upgrade --check          # no root, no changes
sudo mailut upgrade
sudo mailut upgrade --dry-run
sudo mailut upgrade --version 1.1.0
sudo mailut upgrade --verbose
```

What happens:

1. take the lifecycle lock (`/run/mailut/lifecycle.lock`);
2. ask GitHub for the release — public HTTPS, no account or token, one metadata
   request in the normal case;
3. download the tarball and `SHA256SUMS` into a private temporary directory;
4. **verify the SHA-256** — a mismatch aborts, and there is no option to ignore
   it;
5. unpack and validate the tree in temporary storage (path traversal, absolute
   paths, escaping links and device entries are all refused);
6. if the release changes the database schema: stop `mailut-audit.service` and
   take a SQLite backup using SQLite's own backup API (not `cp`, which can tear
   a live WAL database) into `/var/lib/mailut/backups/`;
7. install by running the new release's `make install`;
8. migrate the schema, verify it opened at the expected version;
9. `systemctl daemon-reload`, restart what was running before, leave disabled
   units disabled;
10. verify `mailut --version`, that the configuration still parses, that the
    manifest matches and that the collector is running if it was;
11. release the lock.

```
mailut 1.0.0 -> 1.1.0

Downloading release...
Checksum verified.
Installing...
Database schema: 1 -> 2
Restarting mailut-audit.service...
Upgrade complete.
```

Notes:

- Prereleases (alpha/beta/rc/draft) are never installed by an ordinary upgrade;
  `--prerelease` opts in.
- Downgrades are refused unless `--allow-downgrade` is given. Application files
  can be replaced; a database schema generally cannot be moved backwards, so if
  that is not explicitly supported the downgrade is refused rather than risked.
- `--version` accepts a version, never a URL. Arbitrary remote code locations
  are not reachable through it.
- If installed application files have local modifications, upgrade lists them
  and asks before replacing them (`--yes` for automation).
- `/etc/mailut/mailut.conf` and everything under `/var/lib/mailut` are always
  preserved. `/var/lib/mailut` is never deleted and rebuilt.
- If migration fails, the collector is left stopped (running new code against
  an old schema is worse than downtime), the backup path and schema version are
  printed, and the command exits non-zero. No rollback is claimed, because none
  was performed.
- `mailut upgrade` needs `make` on the host. It never pipes a download into a
  shell.
- Normal commands (`status`, `audit show`, `queue list`, …) never contact
  GitHub. There is no automatic update check.
- `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` are honoured; proxy credentials are
  never stored.

### From source

```bash
git pull
make test
sudo make install
```

Equivalent, and it goes through the same install and migration path. Remote
upgrade is a convenience, not the only safe way to install a release.

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

Afterwards you are reminded that your Mailu/Rspamd configuration may still
contain a metadata exporter pointing at the collector: `mailut` does not edit
Mailu configuration, so remove that snippet yourself.

Re-running uninstall is harmless.

## Backups

Worth backing up:

- `/etc/mailut/mailut.conf`
- `/var/lib/mailut/mailut.sqlite3` — take it with SQLite's backup API or
  `sqlite3 ... ".backup"`, not `cp`, while the collector is running
- `/var/lib/mailut/messages/` if you retain complete messages

`/var/lib/mailut/backups/` holds the pre-migration copies upgrade takes; prune
old ones yourself.

## Making a release (maintainers)

```bash
# 1. Update the version.
echo 1.1.0 > VERSION
$EDITOR man/mailut.8 man/mailut.conf.5     # .TH version strings

# 2. Check.
make test
make check

# 3. Verify a staged install.
rm -rf /tmp/mailut-root
make install DESTDIR=/tmp/mailut-root
find /tmp/mailut-root -type f

# 4. Build deterministic artifacts.
make dist
#    -> dist/mailut-1.1.0.tar.gz
#    -> dist/SHA256SUMS

# 5. Tag and publish.
git commit -am "Release 1.1.0"
git tag -a v1.1.0 -m "Mailu Tools 1.1.0"
git push --follow-tags

# 6. Create the GitHub release for tag v1.1.0 and upload BOTH
#    dist/mailut-1.1.0.tar.gz and dist/SHA256SUMS.
```

`make dist` builds from `git ls-files`, so `.git/`, test scratch files, local
configuration, databases and mail payloads cannot end up in the artifact. The
archive is built with fixed ownership and timestamps, so the same commit
produces the same bytes. It also writes `SCHEMA_VERSION` into the tree, which is
how `mailut upgrade` knows whether a schema change is coming before it installs
anything.

Both assets are required: `mailut upgrade` refuses a release with no
`SHA256SUMS` rather than installing something it cannot verify. The names must
be `mailut-<version>.tar.gz` and `SHA256SUMS`.

If release signing is added later, it layers on top of the existing
metadata/checksum step; nothing about the upgrade flow needs redesigning.

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
