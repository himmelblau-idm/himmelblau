#!/usr/bin/env python3
"""Check packaged PAM cancellation controls without changing installed PAM files.

Run with: python3 scripts/test_pam_cancellation.py -v
"""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AUTH_CONTROL = "[success=done new_authtok_reqd=done abort=die default=ignore]"
ARCH_CONTROL = "[success=ok ignore=2 default=2 abort=die]"
ARCH_SCRIPT = ROOT / "platform/arch/himmelblau.install"


class PamCancellationTests(unittest.TestCase):
    def test_debian_auth_preserves_end_and_unknown_user_fallback(self):
        text = (ROOT / "platform/debian/pam-config").read_text()
        auth = text.split("\nAuth:\n", 1)[1].splitlines()[0]
        self.assertEqual(
            auth.strip(),
            "[success=end abort=die default=ignore]    "
            "pam_himmelblau.so ignore_unknown_user set_authtok",
        )

    def test_opensuse_auth_preserves_sufficient_behavior_except_abort(self):
        text = (ROOT / "platform/opensuse/pam-config").read_text()
        auth = next(line for line in text.splitlines() if line.startswith("Auth:"))
        self.assertIn(AUTH_CONTROL, auth)
        self.assertIn("pam_himmelblau.so    ignore_unknown_user set_authtok", auth)

    def test_nixos_auth_preserves_sufficient_behavior_except_abort(self):
        text = (ROOT / "nix/modules/himmelblau.nix").read_text()
        auth = text.split("auth.himmelblau = {", 1)[1].split("};", 1)[0]
        self.assertIn(f'control = "{AUTH_CONTROL}";', auth)

    def repair_rpm_pam_config(self, directory):
        manifest = (ROOT / "src/pam/Cargo.toml").read_text()
        helper = "fix_pam_config_lines() {" + manifest.split(
            "fix_pam_config_lines() {", 1
        )[1].split("\n}\n", 1)[0] + "\n}\n"
        helper = helper.replace('"/etc/pam.d/', f'"{directory}/')
        subprocess.run(
            ["bash", "-c", helper + "\nfix_pam_config_lines\n"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_rpm_repairs_legacy_builtin_pam_config_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            auth = "auth sufficient pam_himmelblau.so ignore_unknown_user debug\n"
            account = "account required pam_himmelblau.so ignore_unknown_user\n"
            (root / "common-auth-pc").write_text(auth)
            (root / "common-account-pc").write_text(account)
            (root / "common-auth").symlink_to("common-auth-pc")
            (root / "common-account").symlink_to("common-account-pc")
            self.repair_rpm_pam_config(root)
            expected = auth.replace("sufficient", AUTH_CONTROL)
            self.assertEqual((root / "common-auth").read_text(), expected)
            self.assertEqual(
                (root / "common-account").read_text(),
                account.replace("required", "[success=ok auth_err=die default=ignore]"),
            )
            self.assertEqual((root / "common-auth-pc").read_text(), auth)
            self.repair_rpm_pam_config(root)
            self.assertEqual((root / "common-auth").read_text(), expected)

    def test_rpm_preserves_secure_and_custom_auth_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "common-account-pc").write_text(
                "account [success=ok auth_err=die default=ignore] "
                "pam_himmelblau.so ignore_unknown_user\n"
            )
            for control in [AUTH_CONTROL, "required"]:
                with self.subTest(control=control):
                    auth = f"auth {control} pam_himmelblau.so ignore_unknown_user\n"
                    (root / "common-auth-pc").write_text(auth)
                    (root / "common-auth").write_text(auth)
                    self.repair_rpm_pam_config(root)
                    self.assertEqual((root / "common-auth").read_text(), auth)

    def configure_arch_keyring(self, path):
        script = ARCH_SCRIPT.read_text().replace(
            "local conf=/etc/pam.d/gdm-password", f"local conf='{path}'"
        )
        subprocess.run(
            ["bash", "-c", script + "\n_configure_keyring\n"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return path.read_text()

    def test_arch_keyring_fresh_install_stops_abort_and_preserves_jumps(self):
        original = (
            "auth include system-local-login\n"
            "auth optional pam_gnome_keyring.so\n"
            "account include system-local-login\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gdm-password"
            path.write_text(original)
            content = self.configure_arch_keyring(path)
            self.assertIn(
                f"auth       {ARCH_CONTROL} pam_himmelblau.so "
                "ignore_unknown_user set_authtok\n",
                content,
            )
            self.assertIn("auth optional pam_gnome_keyring.so use_authtok\n", content)
            self.assertEqual(self.configure_arch_keyring(path), content)

    def test_arch_keyring_upgrade_migrates_only_the_shipped_legacy_control(self):
        original = (
            "# himmelblau-keyring-prelude\n"
            "auth       [success=ok ignore=2 default=2] pam_himmelblau.so "
            "ignore_unknown_user set_authtok\n"
            "auth optional pam_gnome_keyring.so use_authtok\n"
            "auth [default=done] pam_permit.so\n"
            "auth include system-local-login\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gdm-password"
            path.write_text(original)
            expected = original.replace(
                "[success=ok ignore=2 default=2]", ARCH_CONTROL
            )
            self.assertEqual(self.configure_arch_keyring(path), expected)
            self.assertEqual(self.configure_arch_keyring(path), expected)

            custom = original.replace("ignore=2 default=2", "ignore=3 default=3")
            path.write_text(custom)
            self.assertEqual(self.configure_arch_keyring(path), custom)


if __name__ == "__main__":
    unittest.main()
