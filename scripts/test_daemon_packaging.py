#!/usr/bin/env python3
"""Exercise daemon RPM maintainer-script upgrade ordering in isolation."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "src/daemon/scripts"
MOCK = r'''
import json
import os
from pathlib import Path
import sys

command = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ["FIXTURE"])
with (root / "calls").open("a") as output:
    output.write(json.dumps([command, *args]) + "\n")
if command == "systemd-detect-virt":
    sys.exit(1)
if command == "systemctl" and args[:2] == ["is-enabled", "--quiet"]:
    sys.exit(int(os.environ.get("SERVICE_DISABLED", "0")))
'''


class DaemonPackagingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="daemon-packaging-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.systemd = self.root / "run/systemd/system"
        self.systemd.mkdir(parents=True)
        self.marker = self.root / "run/himmelblau-rpm-upgrade-restart"
        self.config = self.root / "etc/himmelblau/himmelblau.conf"
        self.config.parent.mkdir(parents=True)
        for command in ("systemctl", "systemd-detect-virt", "systemd-tmpfiles"):
            path = self.bin / command
            path.write_text("#!/usr/bin/python3\n" + MOCK)
            path.chmod(0o755)
        for command in ("awk", "grep", "md5sum", "mv", "rm"):
            (self.bin / command).symlink_to(Path("/usr/bin") / command)
        self.env = dict(
            os.environ,
            PATH=str(self.bin),
            FIXTURE=str(self.root),
        )

    def run_script(self, name, argument, **environment):
        text = (SCRIPTS / name).read_text()
        text = text.replace("/run/systemd/system", str(self.systemd))
        text = text.replace("/run/himmelblau-rpm-upgrade-restart", str(self.marker))
        text = text.replace("/etc/himmelblau/himmelblau.conf", str(self.config))
        script = self.root / name
        script.write_text(text)
        env = dict(self.env, **environment)
        return subprocess.run(
            ["/bin/sh", str(script), argument],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def calls(self):
        path = self.root / "calls"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_rpm_preun_stops_only_on_final_erase(self):
        result = self.run_script("prerm", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("stop", [arg for call in self.calls() for arg in call])

        result = self.run_script("prerm", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            [
                "systemctl",
                "stop",
                "himmelblaud.service",
                "himmelblaud-tasks.service",
                "himmelblau-hsm-pin-init.service",
            ],
            self.calls(),
        )

    def test_rpm_post_marks_only_live_upgrades_for_recovery(self):
        result = self.run_script("postinst", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())

        result = self.run_script("postinst", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())

    def test_posttrans_recovers_enabled_upgrade_once(self):
        self.marker.touch()
        result = self.run_script("posttrans", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertIn(
            [
                "systemctl",
                "start",
                "himmelblaud.service",
                "himmelblaud-tasks.service",
            ],
            self.calls(),
        )

    def test_posttrans_does_not_start_disabled_service(self):
        self.marker.touch()
        result = self.run_script("posttrans", "1", SERVICE_DISABLED="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertNotIn("start", [arg for call in self.calls() for arg in call])

    def test_config_recovery_keeps_existing_try_restart(self):
        saved = Path(str(self.config) + ".rpmsave")
        saved.write_text("[global]\n")
        result = self.run_script("posttrans", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_text(), "[global]\n")
        self.assertIn(
            [
                "systemctl",
                "try-restart",
                "himmelblaud.service",
                "himmelblaud-tasks.service",
            ],
            self.calls(),
        )


if __name__ == "__main__":
    unittest.main()
