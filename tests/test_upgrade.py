"""`mailut upgrade`: discovery, verification, safety and post-conditions.

Nothing here touches the network or GitHub: a local server stands in for the
public release API, and every install is staged under a temporary root.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from fakehub import FakeHub
from helpers import ROOT

from mailut import release as release_mod
from mailut.lifecycle import archive, upgrade, upstream
from mailut.lifecycle.lock import LifecycleLock
from mailut.util import MailutError

MAKE = shutil.which("make")
BASE_VERSION = (ROOT / "VERSION").read_text().strip()


class VersionTests(unittest.TestCase):
    def test_parses_and_orders_versions(self):
        self.assertLess(upstream.parse_version("1.0.0"), upstream.parse_version("1.0.1"))
        self.assertLess(upstream.parse_version("1.9.0"), upstream.parse_version("1.10.0"))
        self.assertLess(upstream.parse_version("v1.0.0"), upstream.parse_version("2.0.0"))
        self.assertLess(upstream.parse_version("1.4.0-rc.1"), upstream.parse_version("1.4.0"))

    def test_rejects_non_versions(self):
        for value in ("latest", "1.0", "", "1.0.0.0", "../../etc/passwd",
                      "https://example.com/x.tar.gz"):
            with self.assertRaises(upstream.UpstreamError, msg=value):
                upstream.parse_version(value)

    def test_prerelease_detection(self):
        self.assertTrue(upstream.is_prerelease({"tag_name": "v1.4.0-rc.1"}))
        self.assertTrue(upstream.is_prerelease({"tag_name": "v1.4.0", "prerelease": True}))
        self.assertTrue(upstream.is_prerelease({"tag_name": "v1.4.0-beta"}))
        self.assertFalse(upstream.is_prerelease({"tag_name": "v1.4.0"}))

    def test_checksum_file_parsing(self):
        sums = upstream.parse_checksums(
            "  \n"
            + ("0" * 64) + "  mailut-1.0.0.tar.gz\n"
            + "not-a-digest  ignored.tar.gz\n"
            + ("f" * 64) + " *SHA256SUMS\n"
        )
        self.assertEqual(sums["mailut-1.0.0.tar.gz"], "0" * 64)
        self.assertNotIn("ignored.tar.gz", sums)
        self.assertEqual(sums["SHA256SUMS"], "f" * 64)


class ArchiveSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mailut-archive-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def make_tar(self, build):
        tarball = self.tmp / "evil.tar.gz"
        with tarfile.open(tarball, "w:gz") as handle:
            build(handle)
        return tarball

    def test_absolute_path_member_is_refused(self):
        def build(handle):
            info = tarfile.TarInfo("/etc/passwd")
            info.size = 0
            handle.addfile(info, io.BytesIO(b""))

        with self.assertRaises(archive.ArchiveError):
            archive.extract(self.make_tar(build), self.tmp / "out")

    def test_traversal_member_is_refused(self):
        payload = self.tmp / "payload"
        payload.write_text("x")

        def build(handle):
            handle.add(payload, arcname="mailut-1.0.0/../../escape")

        with self.assertRaises(archive.ArchiveError):
            archive.extract(self.make_tar(build), self.tmp / "out")

    def test_escaping_symlink_is_refused(self):
        def build(handle):
            info = tarfile.TarInfo("mailut-1.0.0/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../../etc/passwd"
            handle.addfile(info)

        with self.assertRaises(archive.ArchiveError):
            archive.extract(self.make_tar(build), self.tmp / "out")

    def test_device_member_is_refused(self):
        def build(handle):
            info = tarfile.TarInfo("mailut-1.0.0/dev")
            info.type = tarfile.CHRTYPE
            handle.addfile(info)

        with self.assertRaises(archive.ArchiveError):
            archive.extract(self.make_tar(build), self.tmp / "out")

    def test_multiple_top_level_directories_are_refused(self):
        payload = self.tmp / "payload"
        payload.write_text("x")

        def build(handle):
            handle.add(payload, arcname="one/file")
            handle.add(payload, arcname="two/file")

        with self.assertRaises(archive.ArchiveError):
            archive.extract(self.make_tar(build), self.tmp / "out")

    def test_checksum_mismatch_is_fatal(self):
        payload = self.tmp / "artifact.tar.gz"
        payload.write_bytes(b"content")
        with self.assertRaises(archive.ArchiveError) as caught:
            archive.verify_checksum(payload, "0" * 64)
        self.assertIn("checksum mismatch", str(caught.exception))
        archive.verify_checksum(payload, archive.sha256(payload))

    def test_tree_validation_requires_the_expected_files(self):
        root = self.tmp / "mailut-1.0.0"
        (root / "bin").mkdir(parents=True)
        (root / "VERSION").write_text("1.0.0\n")
        with self.assertRaises(archive.ArchiveError):
            archive.validate_tree(root)


@unittest.skipUnless(MAKE, "make is not available")
class UpgradeFlowTests(unittest.TestCase):
    """Install 1.0.0 into a staging root, then upgrade it from a fake upstream.

    Every upgrade runs the *staged* command as a subprocess, from a working
    directory outside the checkout, with only the staging root and the fake
    upstream in its environment. That is exactly the situation an administrator
    is in after deleting their clone.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mailut-upgrade-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        self.hub = FakeHub(self.tmp / "hub")
        self.addCleanup(self.hub.close)
        self._install()
        self.conf = self.root / "etc/mailut/mailut.conf"

    # -- helpers ------------------------------------------------------------
    def _install(self):
        proc = subprocess.run(
            [MAKE, "-C", str(ROOT), "install", f"DESTDIR={self.root}"],
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def config(self):
        from mailut.config import Config

        os.environ["MAILUT_ROOT"] = str(self.root)
        self.addCleanup(os.environ.pop, "MAILUT_ROOT", None)
        release_mod._cache = None
        self.addCleanup(setattr, release_mod, "_cache", None)
        return Config.load(self.conf)

    def staged(self, *args, expect=None):
        """Run the installed command, from outside the source checkout."""
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.tmp),
            "MAILUT_ROOT": str(self.root),
            "MAILUT_UPSTREAM_API": self.hub.api,
            "MAILUT_NO_SYSTEMD": "1",
        }
        proc = subprocess.run(
            [sys.executable, str(self.root / "usr/local/sbin/mailut"), *args],
            capture_output=True, text=True, timeout=300, env=env, check=False, cwd="/",
        )
        if expect is not None and proc.returncode != expect:
            self.fail(
                f"`mailut {' '.join(args)}` exited {proc.returncode}, expected {expect}\n"
                f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            )
        return proc

    def upgrade(self, *args, expect=0):
        return self.staged("--config", str(self.conf), "upgrade", *args, expect=expect)

    def installed_version(self):
        return self.staged("version", expect=0).stdout.strip()

    def publish(self, version, **kwargs):
        return self.hub.publish_tree(ROOT, version, **kwargs)

    # -- discovery ----------------------------------------------------------
    def test_check_reports_an_available_update(self):
        self.publish("1.1.0")
        proc = self.upgrade("--check")
        self.assertIn(f"Installed: {BASE_VERSION}", proc.stdout)
        self.assertIn("Latest:    1.1.0", proc.stdout)
        self.assertIn("Update available.", proc.stdout)

    def test_check_when_already_current_is_not_an_error(self):
        self.publish(BASE_VERSION)
        proc = self.upgrade("--check", expect=0)
        self.assertIn("up to date", proc.stdout)

    def test_check_changes_nothing(self):
        self.publish("1.1.0")
        before = self.installed_version()
        self.upgrade("--check")
        self.assertEqual(self.installed_version(), before)

    def test_prereleases_are_ignored_by_default(self):
        self.publish("1.1.0")
        self.publish("2.0.0-rc.1", prerelease=True)
        self.assertIn("Latest:    1.1.0", self.upgrade("--check").stdout)

    def test_prerelease_flag_opts_in(self):
        self.publish("1.1.0")
        self.publish("2.0.0-rc.1", prerelease=True)
        self.assertIn("2.0.0-rc.1", self.upgrade("--check", "--prerelease").stdout)

    def test_explicit_version_selection(self):
        self.publish("1.1.0")
        self.publish("1.2.0")
        self.assertIn("Latest:    1.1.0", self.upgrade("--check", "--version", "1.1.0").stdout)

    def test_unknown_version_is_an_error(self):
        self.publish("1.1.0")
        proc = self.upgrade("--check", "--version", "9.9.9", expect=1)
        self.assertIn("not published", proc.stderr)

    def test_version_option_cannot_be_a_url(self):
        self.publish("1.1.0")
        proc = self.upgrade("--check", "--version", "https://example.net/evil.tar.gz", expect=1)
        self.assertIn("not a semantic version", proc.stderr)

    def test_malformed_release_metadata_is_reported(self):
        self.hub.raw_bodies["/releases/latest"] = b"{not json"
        proc = self.upgrade("--check", expect=1)
        self.assertIn("malformed", proc.stderr)

    def test_release_without_a_tag_is_reported(self):
        self.hub.raw_bodies["/releases/latest"] = json.dumps({"assets": []}).encode()
        proc = self.upgrade("--check", expect=1)
        self.assertIn("malformed", proc.stderr)

    def test_unreachable_upstream_is_reported(self):
        self.hub.close()
        proc = self.upgrade("--check", expect=1)
        self.assertIn("cannot reach", proc.stderr)

    def test_metadata_requests_are_not_repeated(self):
        self.publish("1.1.0")
        self.hub.requests.clear()
        self.upgrade("--check")
        self.assertEqual(self.hub.requests.count("/releases/latest"), 1)

    def test_ordinary_commands_never_contact_upstream(self):
        self.publish("1.1.0")
        self.hub.requests.clear()
        self.staged("--config", str(self.conf), "status", expect=0)
        self.staged("--config", str(self.conf), "audit", "scopes", expect=0)
        self.staged("version", expect=0)
        self.assertEqual(self.hub.requests, [])

    def test_no_authentication_is_used(self):
        """The request path carries no credentials of any kind."""
        self.publish("1.1.0")
        self.upgrade("--check")
        self.assertNotIn("Authorization", upstream.USER_AGENT)
        self.assertNotIn("token", upstream.USER_AGENT.lower())

    # -- dry run ------------------------------------------------------------
    def test_dry_run_changes_nothing(self):
        self.publish("1.1.0")
        before = self.installed_version()
        proc = self.upgrade("--dry-run")
        self.assertIn("Would:", proc.stdout)
        self.assertIn("dry run", proc.stdout)
        self.assertEqual(self.installed_version(), before)

    def test_dry_run_does_not_create_a_database(self):
        self.publish("1.1.0")
        self.upgrade("--dry-run")
        self.assertFalse((self.root / "var/lib/mailut/mailut.sqlite3").exists())

    # -- real upgrades ------------------------------------------------------
    def test_upgrade_installs_the_new_release(self):
        self.publish("1.1.0")
        proc = self.upgrade()
        self.assertIn("Checksum verified.", proc.stdout)
        self.assertIn("Upgrade complete.", proc.stdout)
        self.assertIn("1.1.0", self.installed_version())

    def test_upgrade_updates_the_manifest(self):
        self.publish("1.1.0")
        self.upgrade()
        manifest = json.loads(
            (self.root / "usr/local/share/mailut/install-manifest.json").read_text()
        )
        self.assertEqual(manifest["version"], "1.1.0")

    def test_upgrade_preserves_configuration(self):
        self.conf.write_text("[mailu]\ncompose_dir = /srv/custom-mailu\n", encoding="utf-8")
        self.publish("1.1.0")
        self.upgrade()
        self.assertIn("/srv/custom-mailu", self.conf.read_text(encoding="utf-8"))

    def test_upgrade_preserves_the_database_and_messages(self):
        state = self.root / "var/lib/mailut"
        self.staged("--config", str(self.conf), "audit", "add", "domain", "example.com", expect=0)
        (state / "messages" / "keepme").write_bytes(b"payload")

        self.publish("1.1.0")
        self.upgrade()

        self.assertTrue((state / "mailut.sqlite3").exists())
        self.assertEqual((state / "messages" / "keepme").read_bytes(), b"payload")
        scopes = self.staged("--config", str(self.conf), "audit", "scopes", expect=0)
        self.assertIn("example.com", scopes.stdout)

    def test_upgrade_needs_no_source_checkout(self):
        """Nothing in the staged environment points at the clone."""
        self.publish("1.1.0")
        proc = self.upgrade()
        self.assertIn("Upgrade complete.", proc.stdout)
        self.assertIn("1.1.0", self.installed_version())
        self.assertFalse((self.root / "usr/local/lib/mailut/.git").exists())
        self.assertFalse((self.root / "usr/local/lib/mailut/mailut/.git").exists())

    def test_schema_change_backs_up_the_database(self):
        self.staged("--config", str(self.conf), "audit", "add", "all", expect=0)
        self.publish("1.1.0", schema_version=2)
        proc = self.upgrade()
        backups = list((self.root / "var/lib/mailut/backups").glob("*.sqlite3"))
        self.assertEqual(len(backups), 1, proc.stdout)
        self.assertIn(f"mailut-db-{BASE_VERSION}-schema1-", backups[0].name)
        self.assertIn("Database schema: 1 -> 2", proc.stdout)

    def test_backup_is_a_readable_database(self):
        import sqlite3

        self.staged("--config", str(self.conf), "audit", "add", "domain", "example.com", expect=0)
        self.publish("1.1.0", schema_version=2)
        self.upgrade()
        backup = next((self.root / "var/lib/mailut/backups").glob("*.sqlite3"))
        self.assertEqual(oct(backup.stat().st_mode & 0o777), "0o600")
        conn = sqlite3.connect(str(backup))
        try:
            rows = conn.execute("SELECT scope_value FROM audit_scopes").fetchall()
        finally:
            conn.close()
        self.assertEqual(rows, [("example.com",)])

    def test_a_real_migration_is_accepted_by_verification(self):
        """The upgrader must judge the DB by the NEW release's schema, not its own.

        The pre-existing schema test only rewrote the SCHEMA_VERSION marker, so
        the installed code still migrated to schema 1 and verification compared
        1 against 1 -- it passed while the real path was broken. This publishes
        a release that genuinely migrates the database to 2, which the old
        process's own constants would reject.
        """
        def add_migration(tree):
            path = tree / "lib" / "mailut" / "migrations.py"
            text = path.read_text(encoding="utf-8")
            text = text.replace(
                "LATEST = max(version for version, _desc, _sql in MIGRATIONS)",
                'MIGRATIONS.append((2, "test migration", '
                '("CREATE TABLE later_addition (id INTEGER PRIMARY KEY)",)))\n'
                "LATEST = max(version for version, _desc, _sql in MIGRATIONS)",
            )
            path.write_text(text, encoding="utf-8")
            release = tree / "lib" / "mailut" / "release.py"
            release.write_text(
                release.read_text(encoding="utf-8").replace(
                    "SCHEMA_VERSION = 1", "SCHEMA_VERSION = 2"
                ),
                encoding="utf-8",
            )

        self.staged("--config", str(self.conf), "audit", "add", "domain", "example.com", expect=0)
        self.publish("1.1.0", schema_version=2, mutate=add_migration)

        proc = self.upgrade()
        self.assertIn("Database schema: 1 -> 2", proc.stdout)
        self.assertIn("Upgrade complete.", proc.stdout)
        self.assertNotIn("post-upgrade check failed", proc.stderr)

        # The database really did migrate, and the scope survived.
        version = self.staged("version", "--json", expect=0)
        self.assertEqual(json.loads(version.stdout)["schema_version"], 2)
        scopes = self.staged("--config", str(self.conf), "audit", "scopes", expect=0)
        self.assertIn("example.com", scopes.stdout)

    def test_a_failed_migration_is_reported_and_leaves_a_backup(self):
        def broken_migration(tree):
            path = tree / "lib" / "mailut" / "migrations.py"
            text = path.read_text(encoding="utf-8").replace(
                "LATEST = max(version for version, _desc, _sql in MIGRATIONS)",
                'MIGRATIONS.append((2, "broken", ("THIS IS NOT SQL",)))\n'
                "LATEST = max(version for version, _desc, _sql in MIGRATIONS)",
            )
            path.write_text(text, encoding="utf-8")

        self.staged("--config", str(self.conf), "audit", "add", "all", expect=0)
        self.publish("1.1.0", schema_version=2, mutate=broken_migration)

        proc = self.upgrade(expect=1)
        self.assertIn("Database migration FAILED", proc.stderr)
        self.assertIn("pre-migration backup", proc.stderr)
        backups = list((self.root / "var/lib/mailut/backups").glob("*.sqlite3"))
        self.assertEqual(len(backups), 1)

    def test_dry_run_does_not_assert_an_unknown_schema_outcome(self):
        """A dry run has not downloaded the artifact, so it cannot know."""
        self.staged("--config", str(self.conf), "audit", "add", "all", expect=0)
        self.publish("1.1.0")
        proc = self.upgrade("--dry-run")
        self.assertNotIn("leave the database schema unchanged", proc.stdout)
        self.assertIn("if they differ", proc.stdout)

    def test_no_backup_when_the_schema_is_unchanged(self):
        self.staged("--config", str(self.conf), "audit", "add", "all", expect=0)
        self.publish("1.1.0", schema_version=1)
        self.upgrade()
        self.assertEqual(list((self.root / "var/lib/mailut/backups").glob("*.sqlite3")), [])

    def test_already_current_does_nothing(self):
        self.publish(BASE_VERSION)
        proc = self.upgrade()
        self.assertIn("up to date", proc.stdout)

    def test_downgrade_is_refused_by_default(self):
        self.publish("0.9.0")
        proc = self.upgrade("--version", "0.9.0", expect=1)
        self.assertIn("refusing to downgrade", proc.stderr)
        self.assertIn(BASE_VERSION, self.installed_version())

    def test_downgrade_with_the_explicit_flag(self):
        self.publish("0.9.0")
        self.upgrade("--version", "0.9.0", "--allow-downgrade")
        self.assertIn("0.9.0", self.installed_version())

    # -- failure handling ---------------------------------------------------
    def test_checksum_mismatch_aborts_and_keeps_the_old_version(self):
        self.publish("1.1.0", checksum_override="0" * 64)
        proc = self.upgrade(expect=1)
        self.assertIn("checksum mismatch", proc.stderr)
        self.assertIn(BASE_VERSION, self.installed_version())

    def test_there_is_no_flag_to_skip_checksum_verification(self):
        help_text = self.staged("upgrade", "--help", expect=0).stdout.lower()
        for phrase in ("--no-verify", "--skip-checksum", "--insecure", "--force"):
            self.assertNotIn(phrase, help_text)

    def test_missing_checksum_asset_is_refused(self):
        self.publish("1.1.0", with_checksums=False)
        proc = self.upgrade(expect=1)
        self.assertIn("SHA256SUMS", proc.stderr)
        self.assertIn(BASE_VERSION, self.installed_version())

    def test_missing_tarball_asset_is_refused(self):
        self.hub.add_release("1.1.0", assets=["SHA256SUMS"])
        proc = self.upgrade(expect=1)
        self.assertIn("mailut-1.1.0.tar.gz", proc.stderr)

    def test_download_failure_keeps_the_installation_usable(self):
        self.publish("1.1.0")
        self.hub.fail_paths.add("/assets/mailut-1.1.0.tar.gz")
        self.upgrade(expect=1)
        self.assertIn(BASE_VERSION, self.installed_version())
        self.staged("--config", str(self.conf), "status", expect=0)

    def test_invalid_release_tree_is_refused(self):
        def remove_makefile(tree):
            (tree / "Makefile").unlink()

        self.publish("1.1.0", mutate=remove_makefile)
        proc = self.upgrade(expect=1)
        self.assertIn("Makefile", proc.stderr)
        self.assertIn(BASE_VERSION, self.installed_version())

    def test_version_is_only_updated_after_a_successful_install(self):
        def break_install(tree):
            (tree / "Makefile").write_text(
                "install:\n\t@echo deliberate failure >&2; exit 1\n", encoding="utf-8"
            )

        self.publish("1.1.0", mutate=break_install)
        proc = self.upgrade(expect=1)
        self.assertIn("failed", proc.stderr)
        self.assertIn(BASE_VERSION, self.installed_version())

    def test_temporary_files_are_cleaned_up(self):
        self.publish("1.1.0")
        before = set(Path(tempfile.gettempdir()).glob("mailut-upgrade-*"))
        self.upgrade()
        after = set(Path(tempfile.gettempdir()).glob("mailut-upgrade-*"))
        self.assertEqual(after - before, set())

    # -- lock ---------------------------------------------------------------
    def test_lifecycle_lock_blocks_a_concurrent_operation(self):
        self.publish("1.1.0")
        run_dir = self.root / "run/mailut"
        with LifecycleLock(run_dir):
            proc = self.upgrade(expect=5)
            self.assertIn("lifecycle operation", proc.stderr)
        self.assertIn(BASE_VERSION, self.installed_version())

    def test_lock_is_released_afterwards(self):
        run_dir = self.root / "run/mailut"
        with LifecycleLock(run_dir):
            pass
        with LifecycleLock(run_dir):
            pass

    def test_lock_file_lives_under_the_run_directory(self):
        run_dir = self.root / "run/mailut"
        with LifecycleLock(run_dir) as lock:
            self.assertEqual(lock.path, run_dir / "lifecycle.lock")
            self.assertTrue(lock.path.exists())

    # -- modified installed files ------------------------------------------
    def test_modified_application_file_is_reported_and_confirmed(self):
        target = self.root / "usr/local/lib/mailut/mailut/util.py"
        target.write_text(target.read_text() + "\n# local edit\n", encoding="utf-8")
        self.publish("1.1.0")

        # Without a terminal and without --yes the upgrade stops rather than
        # silently discarding a deliberate local change.
        proc = self.upgrade(expect=3)
        self.assertIn("Modified installed application files detected.", proc.stdout)
        self.assertIn("util.py", proc.stdout)
        self.assertIn(BASE_VERSION, self.installed_version())

        proc = self.upgrade("--yes")
        self.assertIn("Modified installed application files detected.", proc.stdout)
        self.assertIn("1.1.0", self.installed_version())
        self.assertNotIn("# local edit", target.read_text(encoding="utf-8"))

    # -- systemd ------------------------------------------------------------
    def test_units_are_never_enabled_by_an_upgrade(self):
        self.publish("1.1.0")
        proc = self.upgrade()
        self.assertNotIn("systemctl enable", proc.stdout)
        self.assertNotIn("enable --now", proc.stdout)


class PrivilegeCheckTests(unittest.TestCase):
    """The root check must fire for a real install and only for a real one.

    os.geteuid is patched so this behaves identically whoever runs the suite.
    """

    def setUp(self):
        self._geteuid = os.geteuid
        os.geteuid = lambda: 1000
        self.addCleanup(setattr, os, "geteuid", self._geteuid)
        os.environ.pop("MAILUT_ROOT", None)
        self.addCleanup(os.environ.pop, "MAILUT_ROOT", None)

    def test_upgrade_requires_root_on_a_real_installation(self):
        with self.assertRaises(MailutError) as caught:
            upgrade._require_root()
        self.assertIn("requires root", str(caught.exception))
        self.assertIn("sudo", str(caught.exception))

    def test_uninstall_requires_root_on_a_real_installation(self):
        from mailut.lifecycle import uninstall

        with self.assertRaises(MailutError) as caught:
            uninstall._require_root(dry_run=False)
        self.assertIn("requires root", str(caught.exception))

    def test_uninstall_dry_run_never_requires_root(self):
        from mailut.lifecycle import uninstall

        uninstall._require_root(dry_run=True)

    def test_a_staging_root_needs_no_privileges(self):
        from mailut.lifecycle import uninstall

        os.environ["MAILUT_ROOT"] = "/tmp/not-a-real-install"
        upgrade._require_root()
        uninstall._require_root(dry_run=False)

    def test_upgrade_check_never_requires_root(self):
        """--check is read-only, so it must work for an unprivileged operator."""
        import inspect

        source = inspect.getsource(upgrade.cmd_upgrade)
        check_return = source.index("return cmd_check(args, config)")
        require_root = source.index("_require_root()")
        self.assertLess(check_return, require_root)
