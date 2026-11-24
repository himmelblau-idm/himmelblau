"""Exercise the unix-chkpwd post-install branch without modifying host policy."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


POSTINST = Path(__file__).with_name("postinst")


class UnixChkpwdReloadTests(unittest.TestCase):
    def run_case(self, profile, patch_status=0, parser_status=0):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "unix-chkpwd"
            if profile is not None:
                path.write_text(profile)
            bindir = root / "bin"
            bindir.mkdir()
            for name, status in (("patch", patch_status), ("apparmor_parser", parser_status)):
                command = bindir / name
                command.write_text(f'#!/bin/sh\nprintf "%s\\n" "{name} $*" >> "$CALLS"\nexit {status}\n')
                command.chmod(0o755)
            source = POSTINST.read_text()
            block = source.split("# Check if the file /etc/apparmor.d/unix-chkpwd exists", 1)[1]
            block = block.split("# Check if the file /etc/apparmor.d/usr.lib.libreoffice", 1)[0]
            block = block.replace("/etc/apparmor.d/unix-chkpwd", str(path))
            env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "CALLS": str(root / "calls")}
            result = subprocess.run(["bash", "-ec", 'UNIX_CHKPWD_PATCH=fixture\n' + block],
                                    env=env, capture_output=True, text=True, check=True)
            calls = (root / "calls").read_text().splitlines() if (root / "calls").exists() else []
            return calls, result.stdout, result.stderr

    def test_reload_when_flag_already_exists(self):
        calls, _, _ = self.run_case("profile unix-chkpwd flags=(attach_disconnected) {}")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("apparmor_parser -r "))

    def test_reload_after_patch_success_or_failure(self):
        for status in (0, 1):
            with self.subTest(patch_status=status):
                calls, _, err = self.run_case("profile unix-chkpwd {}", patch_status=status)
                self.assertEqual([line.split()[0] for line in calls], ["patch", "apparmor_parser"])
                self.assertEqual("patch failed" in err, status != 0)

    def test_absent_profile_and_reload_failure(self):
        self.assertEqual(self.run_case(None)[0], [])
        calls, out, _ = self.run_case("flags=(attach_disconnected)", parser_status=1)
        self.assertEqual(len(calls), 1)
        self.assertIn("apparmor reload failed", out)


if __name__ == "__main__":
    unittest.main()
