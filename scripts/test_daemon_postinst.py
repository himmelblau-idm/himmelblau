"""Run the daemon post-install script with isolated systemctl helpers."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "src/daemon/scripts/postinst"


class DaemonPostinstTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls"

        self.helper("grep", "#!/bin/sh\nexec /usr/bin/grep \"$@\"\n")
        self.helper("systemd-detect-virt", "#!/bin/sh\nexit 1\n")
        self.helper("systemd-tmpfiles", "#!/bin/sh\nexit 0\n")
        self.helper(
            "systemctl",
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$POSTINST_TEST_LOG\"\n",
        )

    def helper(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def run_postinst(self, systemd_creds):
        if systemd_creds:
            self.helper("systemd-creds", "#!/bin/sh\nexit 0\n")
        else:
            (self.bin / "systemd-creds").unlink(missing_ok=True)

        self.log.unlink(missing_ok=True)
        result = subprocess.run(
            ["/bin/sh", str(SCRIPT)],
            env={
                "PATH": str(self.bin),
                "POSTINST_TEST_LOG": str(self.log),
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.log.read_text().splitlines()

    def test_legacy_systemd_disables_encrypted_pin_initializer(self):
        calls = self.run_postinst(systemd_creds=False)
        self.assertIn("disable himmelblau-hsm-pin-init.service", calls)
        self.assertNotIn("enable himmelblau-hsm-pin-init.service", calls)
        self.assertLess(
            calls.index("disable himmelblau-hsm-pin-init.service"),
            calls.index("restart himmelblaud.service himmelblaud-tasks.service"),
        )

    def test_systemd_creds_enables_encrypted_pin_initializer(self):
        calls = self.run_postinst(systemd_creds=True)
        self.assertIn("enable himmelblau-hsm-pin-init.service", calls)
        self.assertNotIn("disable himmelblau-hsm-pin-init.service", calls)


if __name__ == "__main__":
    unittest.main()
