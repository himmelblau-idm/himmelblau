#!/usr/bin/env python3
"""Exercise the himmelblau-sso-policies maintainer scripts in a temporary root.

Run with: python3 scripts/test_sso_policies_scripts.py -v
"""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "src/sso-policies/scripts"
RELEASES = "https://github.com/siemens/linux-entra-sso/releases/download"
FIREFOX_ID = "linux-entra-sso@example.com"
FIREFOX_OLD = f"{RELEASES}/v1.9.1/linux_entra_sso-1.9.1.xpi"
THUNDERBIRD_OLD = f"{RELEASES}/v1.9.1/linux_entra_sso-1.9.1.thunderbird.xpi"
ADMIN_FIREFOX = f"{RELEASES}/v1.10.2/linux_entra_sso-1.10.2.xpi"
ADMIN_THUNDERBIRD = f"{RELEASES}/v1.10.2/linux_entra_sso-1.10.2.thunderbird.xpi"
MIRROR = "https://mirror.example.org/linux_entra_sso-1.9.1.xpi"
# Tools the scripts call, besides jq
TOOLS = ("cat", "chmod", "dirname", "grep", "mkdir", "mktemp", "mv", "rm")


def script_value(name, variable):
    """Read a VAR="..." assignment from a maintainer script."""
    for line in (SCRIPTS / name).read_text().splitlines():
        if line.startswith(f'{variable}="'):
            return line.split('"')[1]
    raise AssertionError(f"{variable} not found in {name}")


FIREFOX_URL = script_value("postinst", "FIREFOX_EXTENSION_URL")
THUNDERBIRD_URL = script_value("postinst", "THUNDERBIRD_EXTENSION_URL")


@unittest.skipUnless(shutil.which("jq"), "jq is required")
class SsoPoliciesScripts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.firefox = self.root / "etc/firefox/policies/policies.json"
        self.thunderbird = self.root / "etc/thunderbird/policies/policies.json"
        self.betterbird = self.root / "etc/betterbird/policies/policies.json"
        # PATH without jq, for the no-jq paths
        self.nojq = self.root / "nojq-bin"
        self.nojq.mkdir()
        for tool in TOOLS:
            (self.nojq / tool).symlink_to(shutil.which(tool))

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, name, *arguments, jq=True, umask=0o022, fail_mv=False):
        # Point the absolute policy paths into the temporary root
        script = self.root / name
        text = (SCRIPTS / name).read_text()
        text = text.replace('"/etc/', f'"{self.root}/etc/')
        text = text.replace("/opt/betterbird", f"{self.root}/opt/betterbird")
        script.write_text(text)
        env = dict(os.environ)
        if not jq:
            env["PATH"] = str(self.nojq)
        if fail_mv:
            # Simulate a policy that cannot be replaced, e.g. a bind mount
            stub = self.root / "failmv-bin"
            stub.mkdir(exist_ok=True)
            (stub / "mv").write_text("#!/bin/sh\necho 'mv: Device or resource busy' >&2\nexit 1\n")
            (stub / "mv").chmod(0o755)
            env["PATH"] = f"{stub}:{env['PATH']}"
        result = subprocess.run(["/bin/sh", str(script), *arguments], env=env,
                                capture_output=True, text=True, timeout=30,
                                preexec_fn=lambda: os.umask(umask))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout + result.stderr

    def write(self, path, policies, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"policies": policies}))
        path.chmod(mode)

    def policies(self, path):
        return json.loads(path.read_text())["policies"]

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def test_fresh_install_is_readable_under_restrictive_umask(self):
        self.run_script("postinst", "configure", umask=0o077)
        self.assertEqual(self.policies(self.firefox), {"ExtensionSettings": {FIREFOX_ID: {
            "installation_mode": "force_installed", "install_url": FIREFOX_URL}}})
        self.assertEqual(self.policies(self.thunderbird),
                         {"Extensions": {"Install": [THUNDERBIRD_URL]}})
        for path in (self.firefox, self.thunderbird, self.betterbird):
            self.assertEqual(self.mode(path), 0o644, path)
            # The browser must be able to reach the file through new directories
            self.assertEqual(self.mode(path.parent), 0o755, path.parent)
            self.assertEqual(self.mode(path.parent.parent), 0o755, path.parent.parent)

    def test_rerun_leaves_files_unchanged_and_fixes_mode(self):
        self.run_script("postinst", "configure")
        before = self.firefox.read_bytes()
        self.firefox.chmod(0o600)
        output = self.run_script("postinst", "configure")
        self.assertIn("Firefox SSO extension already configured", output)
        self.assertEqual(self.firefox.read_bytes(), before)
        self.assertEqual(self.mode(self.firefox), 0o644)

    def test_upgrade_converts_firefox_and_keeps_admin_entries(self):
        self.write(self.firefox, {
            "DisableTelemetry": True,
            "Extensions": {"Install": [FIREFOX_OLD, ADMIN_FIREFOX, MIRROR]},
            "ExtensionSettings": {FIREFOX_ID: {"private_browsing": True}},
        }, mode=0o600)
        self.write(self.thunderbird, {"Extensions": {"Install": [THUNDERBIRD_OLD, ADMIN_THUNDERBIRD]}})
        self.run_script("postinst", "configure")
        firefox = self.policies(self.firefox)
        self.assertTrue(firefox["DisableTelemetry"])
        self.assertEqual(firefox["Extensions"]["Install"], [ADMIN_FIREFOX, MIRROR])
        self.assertEqual(firefox["ExtensionSettings"][FIREFOX_ID], {
            "private_browsing": True, "installation_mode": "force_installed",
            "install_url": FIREFOX_URL})
        self.assertEqual(self.mode(self.firefox), 0o644)
        self.assertEqual(sorted(self.policies(self.thunderbird)["Extensions"]["Install"]),
                         sorted([ADMIN_THUNDERBIRD, THUNDERBIRD_URL]))

    def test_remove_keeps_admin_entries_and_deletes_empty_files(self):
        self.run_script("postinst", "configure")
        self.run_script("postrm", "remove")
        for path in (self.firefox, self.thunderbird, self.betterbird):
            self.assertFalse(path.exists(), path)

        self.write(self.firefox, {"Extensions": {"Install": [ADMIN_FIREFOX]}})
        self.run_script("postinst", "configure")
        settings = self.policies(self.firefox)["ExtensionSettings"]
        settings[FIREFOX_ID]["private_browsing"] = True
        self.write(self.firefox, {"Extensions": {"Install": [ADMIN_FIREFOX]},
                                  "ExtensionSettings": settings})
        self.run_script("postrm", "remove")
        self.assertEqual(self.policies(self.firefox), {
            "Extensions": {"Install": [ADMIN_FIREFOX]},
            "ExtensionSettings": {FIREFOX_ID: {"private_browsing": True}}})
        self.assertEqual(self.mode(self.firefox), 0o644)

    def test_remove_leaves_admin_install_url_alone(self):
        admin = {"ExtensionSettings": {FIREFOX_ID: {
            "installation_mode": "force_installed", "install_url": ADMIN_FIREFOX}}}
        self.write(self.firefox, admin)
        self.run_script("postrm", "remove")
        self.assertEqual(self.policies(self.firefox), admin)

    def test_upgrade_ignores_rpm_upgrade_argument_in_postrm(self):
        self.run_script("postinst", "configure")
        before = self.firefox.read_bytes()
        self.run_script("postrm", "1")
        self.run_script("postrm", "upgrade")
        self.assertEqual(self.firefox.read_bytes(), before)

    def test_without_jq_only_an_identical_file_counts_as_configured(self):
        output = self.run_script("postinst", "configure", jq=False)
        self.assertIn("Created Firefox SSO policy", output)
        output = self.run_script("postinst", "configure", jq=False)
        self.assertIn("Firefox SSO extension already configured", output)

        legacy = {"ExtensionSettings": {FIREFOX_ID: {"installation_mode": "blocked"}},
                  "Extensions": {"Install": [FIREFOX_URL]}}
        self.write(self.firefox, legacy)
        output = self.run_script("postinst", "configure", jq=False)
        self.assertIn("jq not found", output)
        self.assertNotIn("Firefox SSO extension already configured", output)
        self.assertEqual(self.policies(self.firefox), legacy)

    def test_invalid_json_is_left_unchanged_without_temp_files(self):
        for path in (self.firefox, self.thunderbird):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{not json")
        for script, argument in (("postinst", "configure"), ("postrm", "remove")):
            with self.subTest(script=script):
                output = self.run_script(script, argument)
                self.assertIn("could not update", output)
                self.assertNotIn("Merged Firefox", output)
                for path in (self.firefox, self.thunderbird):
                    self.assertEqual(path.read_text(), "{not json")
                    self.assertEqual(sorted(p.name for p in path.parent.iterdir()),
                                     ["policies.json"])

    def test_failed_rename_leaves_policy_unchanged_without_temp_files(self):
        self.write(self.firefox, {"Extensions": {"Install": [FIREFOX_OLD]}})
        before = self.firefox.read_bytes()
        output = self.run_script("postinst", "configure", fail_mv=True)
        self.assertIn("could not replace", output)
        self.assertNotIn("Merged Firefox", output)
        self.assertEqual(self.firefox.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.firefox.parent.iterdir()), ["policies.json"])

        self.run_script("postinst", "configure")
        before = self.firefox.read_bytes()
        output = self.run_script("postrm", "remove", fail_mv=True)
        self.assertIn("could not replace", output)
        self.assertNotIn("Removed Firefox", output)
        self.assertEqual(self.firefox.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.firefox.parent.iterdir()), ["policies.json"])

    def test_empty_policy_file_is_left_unchanged(self):
        for path in (self.firefox, self.thunderbird):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        for script, argument in (("postinst", "configure"), ("postrm", "remove")):
            with self.subTest(script=script):
                output = self.run_script(script, argument)
                self.assertIn("could not update", output)
                self.assertNotIn("Merged", output)
                for path in (self.firefox, self.thunderbird):
                    self.assertEqual(path.read_text(), "")
                    self.assertEqual(sorted(p.name for p in path.parent.iterdir()),
                                     ["policies.json"])

    def test_remove_without_jq_lists_managed_firefox_urls(self):
        self.write(self.firefox, {"Extensions": {"Install": [FIREFOX_OLD]}})
        output = self.run_script("postrm", "remove", jq=False)
        self.assertIn(FIREFOX_ID, output)
        # Only the package fields, not the whole entry an admin may have extended
        self.assertIn('"installation_mode" and "install_url"', output)
        self.assertIn("keep any other keys", output)
        self.assertIn(FIREFOX_OLD, output)
        self.assertIn(FIREFOX_URL, output)

    def test_remove_with_jq_cleans_url_left_by_upgrade_without_jq(self):
        for path in (self.thunderbird, self.betterbird):
            self.write(path, {"Extensions": {"Install": [THUNDERBIRD_OLD, ADMIN_THUNDERBIRD]}})
        self.run_script("postinst", "configure", jq=False)
        self.assertIn(THUNDERBIRD_OLD, self.thunderbird.read_text())
        self.run_script("postrm", "remove")
        for path in (self.thunderbird, self.betterbird):
            self.assertEqual(self.policies(path), {"Extensions": {"Install": [ADMIN_THUNDERBIRD]}})


if __name__ == "__main__":
    unittest.main()
