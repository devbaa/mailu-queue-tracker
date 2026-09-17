"""Staged `make install`: layout, modes, manifest, man pages and config safety."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

MAKE = shutil.which("make")


def staged_install(destdir: Path, *extra):
    return subprocess.run(
        [MAKE, "-C", str(ROOT), "install", f"DESTDIR={destdir}", *extra],
        capture_output=True, text=True, timeout=300, check=False,
    )


@unittest.skipUnless(MAKE, "make is not available")
class StagedInstallTests(unittest.TestCase):
    """One staged install shared by the whole class: it is not cheap."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="mailut-install-"))
        cls.root = cls.tmp / "root"
        proc = staged_install(cls.root)
        if proc.returncode != 0:
            raise AssertionError(f"make install failed:\n{proc.stdout}\n{proc.stderr}")
        cls.output = proc.stdout

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def path(self, relative):
        return self.root / relative.lstrip("/")

    # -- layout -------------------------------------------------------------
    def test_command_is_installed_executable(self):
        command = self.path("usr/local/sbin/mailut")
        self.assertTrue(command.is_file())
        self.assertEqual(stat.S_IMODE(command.stat().st_mode), 0o755)

    def test_library_is_installed_not_executable(self):
        package = self.path("usr/local/lib/mailut/mailut")
        self.assertTrue((package / "cli.py").is_file())
        self.assertTrue((package / "ingest" / "postfix.py").is_file())
        self.assertTrue((package / "lifecycle" / "upgrade.py").is_file())
        self.assertEqual(stat.S_IMODE((package / "cli.py").stat().st_mode), 0o644)

    def test_man_pages_are_installed(self):
        for page in ("usr/local/share/man/man8/mailut.8",
                     "usr/local/share/man/man5/mailut.conf.5"):
            path = self.path(page)
            self.assertTrue(path.is_file(), page)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith(".\\\""))
            self.assertIn(".TH ", text)

    def test_man_page_documents_the_required_sections(self):
        text = self.path("usr/local/share/man/man8/mailut.8").read_text(encoding="utf-8")
        for section in ("SYNOPSIS", "GLOBAL OPTIONS", "COMMAND HIERARCHY", "AUDIT COMMANDS",
                        "QUEUE COMMANDS", "IP INVESTIGATION", "LIFECYCLE COMMANDS",
                        "FILES", "ENVIRONMENT", "EXIT STATUS", "SECURITY CONSIDERATIONS",
                        "EXAMPLES"):
            self.assertIn(f".SH {section}", text, section)

    def test_conf_man_page_documents_every_setting(self):
        sys.path.insert(0, str(ROOT / "lib"))
        from mailut.config import DEFAULTS

        text = self.path("usr/local/share/man/man5/mailut.conf.5").read_text(encoding="utf-8")
        for section, keys in DEFAULTS.items():
            self.assertIn(f"SECTION [{section}]", text, section)
            for key in keys:
                self.assertIn(key, text, f"{section}.{key} is not documented")

    def test_systemd_units_are_installed(self):
        for unit in ("mailut-audit.service", "mailut-purge.service", "mailut-purge.timer",
                     "mailut-watch.service", "mailut-watch.timer"):
            path = self.path(f"etc/systemd/system/{unit}")
            self.assertTrue(path.is_file(), unit)
            text = path.read_text(encoding="utf-8")
            self.assertIn("Description=", text)
            if unit.endswith(".service"):
                # Services must use the absolute installed command path.
                self.assertIn("ExecStart=/usr/local/sbin/mailut", text)
            else:
                self.assertIn("Unit=mailut-", text)

    def test_no_timer_for_the_long_running_collector(self):
        self.assertFalse(self.path("etc/systemd/system/mailut-audit.timer").exists())
        audit = self.path("etc/systemd/system/mailut-audit.service").read_text()
        self.assertIn("Restart=on-failure", audit)

    def test_state_directories_are_owner_only(self):
        for directory in ("var/lib/mailut", "var/lib/mailut/messages", "var/lib/mailut/backups"):
            mode = stat.S_IMODE(self.path(directory).stat().st_mode)
            self.assertEqual(mode, 0o700, directory)

    def test_config_is_installed_restricted(self):
        config = self.path("etc/mailut/mailut.conf")
        self.assertTrue(config.is_file())
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.path("etc/mailut").stat().st_mode), 0o750)

    def test_example_config_and_rspamd_snippet_are_data(self):
        self.assertTrue(self.path("usr/local/share/mailut/mailut.conf.example").is_file())
        snippet = self.path("usr/local/share/mailut/rspamd/mailut-exporter.conf")
        self.assertTrue(snippet.is_file())
        self.assertIn("metadata_exporter", snippet.read_text(encoding="utf-8"))

    def test_no_old_command_names_are_installed(self):
        for path in self.root.rglob("*"):
            self.assertNotIn("mailu-queue", path.name)
            self.assertNotIn("mailu-front", path.name)

    # -- manifest -----------------------------------------------------------
    def test_manifest_lists_everything_installed(self):
        manifest = json.loads(
            self.path("usr/local/share/mailut/install-manifest.json").read_text()
        )
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual(manifest["version"], (ROOT / "VERSION").read_text().strip())

        listed = {entry["path"] for entry in manifest["files"]}
        for expected in (
            "/usr/local/sbin/mailut",
            "/usr/local/lib/mailut/mailut/cli.py",
            "/usr/local/lib/mailut/mailut/buildinfo.json",
            "/usr/local/share/man/man8/mailut.8",
            "/usr/local/share/man/man5/mailut.conf.5",
            "/etc/systemd/system/mailut-audit.service",
            "/etc/systemd/system/mailut-purge.timer",
            "/usr/local/share/mailut/install-manifest.json",
        ):
            self.assertIn(expected, listed, expected)

    def test_manifest_excludes_mutable_operator_data(self):
        manifest = json.loads(
            self.path("usr/local/share/mailut/install-manifest.json").read_text()
        )
        listed = {entry["path"] for entry in manifest["files"]}
        for mutable in ("/etc/mailut/mailut.conf", "/var/lib/mailut/mailut.sqlite3"):
            self.assertNotIn(mutable, listed)
        self.assertIn("/etc/mailut", manifest["preserved"])
        self.assertIn("/var/lib/mailut", manifest["preserved"])

    def test_manifest_hashes_match_the_installed_files(self):
        import hashlib

        manifest = json.loads(
            self.path("usr/local/share/mailut/install-manifest.json").read_text()
        )
        checked = 0
        for entry in manifest["files"]:
            if not entry.get("sha256"):
                continue
            path = self.path(entry["path"])
            self.assertTrue(path.is_file(), entry["path"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, entry["sha256"], entry["path"])
            checked += 1
        self.assertGreater(checked, 20)

    def test_buildinfo_records_version_and_layout(self):
        info = json.loads(
            self.path("usr/local/lib/mailut/mailut/buildinfo.json").read_text()
        )
        self.assertEqual(info["version"], (ROOT / "VERSION").read_text().strip())
        self.assertEqual(info["layout"]["sbindir"], "/usr/local/sbin")
        self.assertEqual(info["layout"]["statedir"], "/var/lib/mailut")

    # -- behaviour of the staged application --------------------------------
    def run_staged(self, *args):
        env = dict(os.environ)
        env["MAILUT_ROOT"] = str(self.root)
        env.pop("MAILUT_CONF", None)
        return subprocess.run(
            [sys.executable, str(self.path("usr/local/sbin/mailut")), *args],
            capture_output=True, text=True, timeout=60, env=env, check=False,
        )

    def test_installed_command_reports_its_version_without_git(self):
        proc = self.run_staged("version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.startswith("mailut "))
        self.assertIn((ROOT / "VERSION").read_text().strip(), proc.stdout)

    def test_installed_command_has_help(self):
        proc = self.run_staged("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("audit", proc.stdout)
        self.assertIn("Exit status:", proc.stdout)

    def test_installed_command_runs_status(self):
        proc = self.run_staged("--config", str(self.path("etc/mailut/mailut.conf")), "status")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Mailu Tools", proc.stdout)


@unittest.skipUnless(MAKE, "make is not available")
class ReinstallTests(unittest.TestCase):
    def test_reinstall_keeps_an_edited_config(self):
        tmp = Path(tempfile.mkdtemp(prefix="mailut-reinstall-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = tmp / "root"

        self.assertEqual(staged_install(root).returncode, 0)
        config = root / "etc/mailut/mailut.conf"
        config.write_text("[mailu]\ncompose_dir = /srv/mailu\n", encoding="utf-8")

        proc = staged_install(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(config.read_text(encoding="utf-8"), "[mailu]\ncompose_dir = /srv/mailu\n")
        self.assertIn("keeping existing", proc.stdout)

    def test_reinstall_keeps_state(self):
        tmp = Path(tempfile.mkdtemp(prefix="mailut-reinstall-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = tmp / "root"

        self.assertEqual(staged_install(root).returncode, 0)
        database = root / "var/lib/mailut/mailut.sqlite3"
        database.write_bytes(b"pretend database")

        self.assertEqual(staged_install(root).returncode, 0)
        self.assertEqual(database.read_bytes(), b"pretend database")
