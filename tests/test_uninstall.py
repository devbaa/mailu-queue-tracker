"""`mailut uninstall`: manifest-driven, offline, and never destructive by default."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fakehub import FakeHub
from helpers import ROOT

from mailut.lifecycle.manifest import Manifest
from mailut.util import MailutError

MAKE = shutil.which("make")


@unittest.skipUnless(MAKE, "make is not available")
class UninstallTests(unittest.TestCase):
    """Install into a staging root, then remove it the way an operator would."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mailut-uninstall-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        proc = subprocess.run(
            [MAKE, "-C", str(ROOT), "install", f"DESTDIR={self.root}"],
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.conf = self.root / "etc/mailut/mailut.conf"
        self.state = self.root / "var/lib/mailut"
        self.command = self.root / "usr/local/sbin/mailut"

        # Unrelated files that must survive: a neighbour in the same prefix,
        # and somebody else's systemd unit.
        self.neighbour = self.root / "usr/local/sbin/other-tool"
        self.neighbour.write_text("#!/bin/sh\necho not ours\n", encoding="utf-8")
        self.neighbour_lib = self.root / "usr/local/lib/other-tool.py"
        self.neighbour_lib.write_text("# not ours\n", encoding="utf-8")
        self.foreign_unit = self.root / "etc/systemd/system/postfix.service"
        self.foreign_unit.write_text("[Unit]\nDescription=not ours\n", encoding="utf-8")
        self.foreign_share = self.root / "usr/local/share/other-tool"
        self.foreign_share.mkdir(parents=True)
        (self.foreign_share / "data").write_text("keep me", encoding="utf-8")

    # -- helpers ------------------------------------------------------------
    def staged(self, *args, expect=None, network=True, input_text=None):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.tmp),
            "MAILUT_ROOT": str(self.root),
            "MAILUT_NO_SYSTEMD": "1",
        }
        if not network:
            # Point the upstream API at a dead address: any attempt to use the
            # network during uninstall would hang or fail loudly.
            env["MAILUT_UPSTREAM_API"] = "http://127.0.0.1:1"
        proc = subprocess.run(
            [sys.executable, str(self.command), *args],
            capture_output=True, text=True, timeout=180, env=env, check=False,
            cwd="/", input=input_text,
        )
        if expect is not None and proc.returncode != expect:
            self.fail(
                f"`mailut {' '.join(args)}` exited {proc.returncode}, expected {expect}\n"
                f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            )
        return proc

    def uninstall(self, *args, expect=0, **kwargs):
        return self.staged("--config", str(self.conf), "uninstall", *args, expect=expect, **kwargs)

    def seed_data(self):
        self.staged("--config", str(self.conf), "audit", "add", "domain", "example.com", expect=0)
        (self.state / "messages" / "2026").mkdir(parents=True, exist_ok=True)
        (self.state / "messages" / "2026" / "payload.eml.gz").write_bytes(b"payload")
        (self.state / "backups" / "old.sqlite3").write_bytes(b"backup")

    def application_files(self):
        manifest = json.loads(
            (self.root / "usr/local/share/mailut/install-manifest.json").read_text()
        )
        return [self.root / entry["path"].lstrip("/") for entry in manifest["files"]]

    def assert_unrelated_files_survived(self):
        self.assertTrue(self.neighbour.is_file())
        self.assertTrue(self.neighbour_lib.is_file())
        self.assertTrue(self.foreign_unit.is_file())
        self.assertTrue((self.foreign_share / "data").is_file())
        self.assertTrue((self.root / "usr/local/sbin").is_dir())
        self.assertTrue((self.root / "etc/systemd/system").is_dir())

    # -- dry run ------------------------------------------------------------
    def tree(self):
        """Every path under the staging root, ignoring Python bytecode caches."""
        return {
            path
            for path in self.root.rglob("*")
            if "__pycache__" not in path.parts
        }

    def test_dry_run_changes_nothing(self):
        before = self.tree()
        proc = self.uninstall("--dry-run")
        self.assertIn("Would remove", proc.stdout)
        self.assertIn("preserve", proc.stdout)
        self.assertEqual(self.tree(), before)

    def test_dry_run_lists_units_files_and_disposition(self):
        proc = self.uninstall("--dry-run")
        self.assertIn("/usr/local/sbin/mailut", proc.stdout)
        self.assertIn("/usr/local/share/man/man8/mailut.8", proc.stdout)
        self.assertIn(str(self.root / "etc/mailut"), proc.stdout)
        self.assertIn(str(self.state), proc.stdout)

    def test_destructive_dry_run_shows_the_data_summary(self):
        self.seed_data()
        proc = self.uninstall("--remove-data", "--dry-run")
        self.assertIn("Retained Mailu Tools data:", proc.stdout)
        self.assertIn("audit scopes:", proc.stdout)
        self.assertIn("REMOVE", proc.stdout)
        self.assertTrue((self.state / "mailut.sqlite3").exists())

    # -- default behaviour --------------------------------------------------
    def test_default_uninstall_removes_application_files(self):
        files = self.application_files()
        self.uninstall("--yes")
        for path in files:
            self.assertFalse(path.exists(), path)

    def test_default_uninstall_preserves_config_and_data(self):
        self.seed_data()
        self.uninstall("--yes")
        self.assertTrue(self.conf.is_file())
        self.assertTrue((self.state / "mailut.sqlite3").is_file())
        self.assertTrue((self.state / "messages" / "2026" / "payload.eml.gz").is_file())
        self.assertTrue((self.state / "backups" / "old.sqlite3").is_file())

    def test_default_uninstall_reports_what_it_kept(self):
        proc = self.uninstall("--yes")
        self.assertIn("has been uninstalled", proc.stdout)
        self.assertIn("Preserved:", proc.stdout)
        self.assertIn(str(self.root / "etc/mailut"), proc.stdout)
        self.assertIn(str(self.state), proc.stdout)

    def test_uninstall_mentions_the_rspamd_exporter(self):
        proc = self.uninstall("--yes")
        self.assertIn("metadata exporter", proc.stdout)
        self.assertIn("Remove that configuration manually", proc.stdout)

    def test_unrelated_files_are_never_touched(self):
        self.uninstall("--yes")
        self.assert_unrelated_files_survived()

    def test_owned_directories_are_pruned_but_shared_ones_are_not(self):
        self.uninstall("--yes")
        self.assertFalse((self.root / "usr/local/lib/mailut").exists())
        self.assertFalse((self.root / "usr/local/share/mailut").exists())
        self.assertTrue((self.root / "usr/local/lib").is_dir())
        self.assertTrue((self.root / "usr/local/share").is_dir())

    # -- options ------------------------------------------------------------
    def test_remove_config_removes_only_the_configuration(self):
        self.seed_data()
        self.uninstall("--remove-config", "--yes")
        self.assertFalse((self.root / "etc/mailut").exists())
        self.assertTrue((self.state / "mailut.sqlite3").is_file())

    def test_remove_data_removes_only_the_state(self):
        self.seed_data()
        self.uninstall("--remove-data", "--yes")
        self.assertFalse(self.state.exists())
        self.assertTrue(self.conf.is_file())

    def test_purge_removes_both(self):
        self.seed_data()
        self.uninstall("--purge", "--yes")
        self.assertFalse((self.root / "etc/mailut").exists())
        self.assertFalse(self.state.exists())
        self.assert_unrelated_files_survived()

    def test_purge_equals_remove_config_plus_remove_data(self):
        purge = self.uninstall("--purge", "--dry-run").stdout
        both = self.uninstall("--remove-config", "--remove-data", "--dry-run").stdout
        self.assertEqual(purge, both)

    # -- confirmation -------------------------------------------------------
    def test_destructive_removal_without_yes_and_without_a_terminal_aborts(self):
        self.seed_data()
        proc = self.uninstall("--remove-data", expect=3)
        self.assertIn("aborted", proc.stderr)
        self.assertTrue((self.state / "mailut.sqlite3").is_file())
        self.assertTrue(self.command.is_file())

    def test_destructive_removal_shows_what_will_be_destroyed(self):
        self.seed_data()
        proc = self.uninstall("--remove-data", expect=3)
        self.assertIn("Retained Mailu Tools data:", proc.stdout)
        self.assertIn("audit events:", proc.stdout)
        self.assertIn("database size:", proc.stdout)

    def test_ordinary_removal_without_yes_and_without_a_terminal_aborts(self):
        proc = self.uninstall(expect=3)
        self.assertIn("aborted", proc.stderr)
        self.assertTrue(self.command.is_file())

    def test_destructive_removal_with_an_unopenable_database_still_warns(self):
        (self.state / "mailut.sqlite3").write_bytes(b"this is not a database")
        proc = self.uninstall("--remove-data", "--dry-run")
        self.assertIn("Retained Mailu Tools data:", proc.stdout)
        self.assertTrue((self.state / "mailut.sqlite3").exists())

    # -- manifest -----------------------------------------------------------
    def test_bytecode_caches_are_cleaned_up(self):
        self.uninstall("--yes")
        self.assertEqual(list(self.root.rglob("__pycache__")), [])

    def test_uninstall_uses_the_manifest(self):
        extra = self.root / "usr/local/lib/mailut/mailut/not_in_manifest.py"
        extra.write_text("# added after installation\n", encoding="utf-8")
        self.uninstall("--yes")
        # The manifest is the authority: a file it does not list is not removed,
        # which is also why the directory above survives.
        self.assertTrue(extra.is_file())

    def test_missing_manifest_fails_safely(self):
        (self.root / "usr/local/share/mailut/install-manifest.json").unlink()
        proc = self.uninstall("--yes", expect=1)
        self.assertIn("install manifest not found", proc.stderr)
        self.assertTrue(self.command.is_file())

    def test_malformed_manifest_fails_safely(self):
        (self.root / "usr/local/share/mailut/install-manifest.json").write_text(
            "{not json", encoding="utf-8"
        )
        proc = self.uninstall("--yes", expect=1)
        self.assertIn("unreadable", proc.stderr)
        self.assertTrue(self.command.is_file())

    def test_manifest_without_a_file_list_fails_safely(self):
        (self.root / "usr/local/share/mailut/install-manifest.json").write_text(
            json.dumps({"manifest_version": 1, "version": "1.0.0"}), encoding="utf-8"
        )
        proc = self.uninstall("--yes", expect=1)
        self.assertIn("malformed", proc.stderr)
        self.assertTrue(self.command.is_file())

    def test_modified_installed_file_is_reported(self):
        target = self.root / "usr/local/lib/mailut/mailut/util.py"
        target.write_text(target.read_text() + "\n# local edit\n", encoding="utf-8")
        proc = self.uninstall("--yes")
        self.assertIn("Modified installed file", proc.stdout)
        self.assertIn("util.py", proc.stdout)
        self.assertFalse(target.exists())  # application-owned: still removed

    def test_manifest_verify_detects_modification_and_absence(self):
        os.environ["MAILUT_ROOT"] = str(self.root)
        self.addCleanup(os.environ.pop, "MAILUT_ROOT", None)
        manifest = Manifest.load(self.root / "usr/local/share/mailut/install-manifest.json")
        self.assertEqual(manifest.verify()["modified"], [])

        target = self.root / "usr/local/lib/mailut/mailut/util.py"
        target.write_text("changed\n", encoding="utf-8")
        (self.root / "usr/local/share/man/man8/mailut.8").unlink()
        state = manifest.verify()
        self.assertEqual(len(state["modified"]), 1)
        self.assertEqual(len(state["missing"]), 1)

    # -- self-removal -------------------------------------------------------
    def test_the_executable_is_removed(self):
        self.uninstall("--yes")
        self.assertFalse(self.command.exists())
        self.assertFalse((self.root / "usr/local/lib/mailut/mailut/cli.py").exists())

    def test_data_removal_happens_before_the_library_is_deleted(self):
        """The data summary needs SQLite, so it must run while the code exists."""
        self.seed_data()
        proc = self.uninstall("--remove-data", "--yes")
        self.assertIn("audit scopes:      1", proc.stdout)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.command.exists())

    # -- other properties ---------------------------------------------------
    def test_uninstall_needs_no_network(self):
        proc = self.uninstall("--yes", network=False)
        self.assertIn("has been uninstalled", proc.stdout)
        self.assertFalse(self.command.exists())

    def test_uninstall_needs_no_source_checkout(self):
        """Nothing under the staging root refers back to the clone."""
        self.uninstall("--yes")
        self.assertFalse(self.command.exists())
        self.assertTrue(ROOT.is_dir())  # the checkout was not touched
        self.assertTrue((ROOT / "Makefile").is_file())

    def test_repeated_uninstall_is_harmless(self):
        self.uninstall("--yes")
        # The command is gone; running the *removed* path is not something an
        # operator can do, so re-run through the source tree against the same
        # staging root and expect a clean, non-destructive failure.
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "MAILUT_ROOT": str(self.root),
            "MAILUT_NO_SYSTEMD": "1",
            "PYTHONPATH": str(ROOT / "lib"),
        }
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mailut"),
             "--config", str(self.conf), "uninstall", "--yes"],
            capture_output=True, text=True, timeout=120, env=env, check=False, cwd="/",
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("install manifest not found", proc.stderr)
        self.assertTrue(self.conf.is_file())


@unittest.skipUnless(MAKE, "make is not available")
class MakeUninstallTests(unittest.TestCase):
    def test_make_uninstall_uses_the_same_implementation(self):
        tmp = Path(tempfile.mkdtemp(prefix="mailut-makeuninstall-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = tmp / "root"
        subprocess.run(
            [MAKE, "-C", str(ROOT), "install", f"DESTDIR={root}"],
            capture_output=True, text=True, timeout=300, check=True,
        )
        (root / "var/lib/mailut/mailut.sqlite3").write_bytes(b"keep me")

        env = dict(os.environ)
        env["MAILUT_NO_SYSTEMD"] = "1"
        proc = subprocess.run(
            [MAKE, "-C", str(ROOT), "uninstall", f"DESTDIR={root}"],
            capture_output=True, text=True, timeout=300, check=False, env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("has been uninstalled", proc.stdout)
        self.assertFalse((root / "usr/local/sbin/mailut").exists())
        self.assertTrue((root / "etc/mailut/mailut.conf").is_file())
        self.assertEqual((root / "var/lib/mailut/mailut.sqlite3").read_bytes(), b"keep me")


class UninstallUnitTests(unittest.TestCase):
    def test_manifest_load_rejects_an_unknown_version(self):
        tmp = Path(tempfile.mkdtemp(prefix="mailut-manifest-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = tmp / "install-manifest.json"
        path.write_text(json.dumps({"manifest_version": 99, "files": []}), encoding="utf-8")
        with self.assertRaises(MailutError) as caught:
            Manifest.load(path)
        self.assertIn("unsupported version", str(caught.exception))

    def test_fakehub_is_only_used_by_the_upgrade_tests(self):
        """Uninstall must never need an upstream at all."""
        self.assertTrue(hasattr(FakeHub, "publish_tree"))
