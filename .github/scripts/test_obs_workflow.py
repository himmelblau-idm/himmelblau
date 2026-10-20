#!/usr/bin/env python3
"""Offline regression checks for the OBS workflow's credential lifecycle."""

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).parents[1] / "workflows" / "obs-update.yml"


class ObsWorkflowTests(unittest.TestCase):
    def setUp(self):
        # These steps use literal run blocks; keep this test standard-library only.
        self.steps = dict(re.findall(
            r"^      - name: ([^\n]+)\n(.*?)(?=^      - name: |\Z)",
            WORKFLOW.read_text(), re.MULTILINE | re.DOTALL,
        ))

    def script(self, name):
        block = self.steps[name].split("        run: ", 1)[1]
        if block.startswith("|\n"):
            return textwrap.dedent(block[2:])
        return block.strip()

    def test_credentials_precede_every_initial_osc_invocation(self):
        names = list(self.steps)
        configured = names.index("Configure osc credentials")
        removed = names.index("Remove osc credentials before generating sources")
        self.assertLess(names.index("Install osc and service dependencies"), configured)
        self.assertLess(configured, names.index("Install OBS cargo service"))
        for index, body in enumerate(self.steps.values()):
            if index < removed and re.search(r"^          osc\s", body, re.MULTILINE):
                self.assertLess(configured, index)

    def test_credentials_are_absent_during_source_generation(self):
        names = list(self.steps)
        self.assertLess(names.index("Remove osc credentials before generating sources"),
                        names.index("Update OBS package sources"))
        self.assertLess(names.index("Update OBS package sources"),
                        names.index("Restore osc credentials for submission and cleanup"))
        self.assertIn("if: always()", self.steps["Cleanup temporary OBS branch project"])
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home, "OBS_API_URL": "https://api.example.invalid",
                   "OBS_TARGET_PROJECT": "test:project", "OBS_USER": "test-user",
                   "OBS_PASSWORD": "test-password"}
            subprocess.run(["bash", "-e", "-c", self.script("Configure osc credentials")],
                           env=env, check=True)
            config = Path(home) / ".config/osc/oscrc"
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            self.assertIn("user=test-user", config.read_text())
            subprocess.run(["bash", "-e", "-c", self.script(
                "Remove osc credentials before generating sources")], env=env, check=True)
            self.assertFalse(config.exists())

    def test_missing_secrets_fail_without_prompt_or_config(self):
        for missing in ("OBS_USER", "OBS_PASSWORD"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as home:
                env = {**os.environ, "HOME": home, "OBS_USER": "test-user",
                       "OBS_PASSWORD": "test-password", missing: ""}
                result = subprocess.run(
                    ["bash", "-e", "-c", self.script("Configure osc credentials")],
                    env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{missing} secret is not configured", result.stdout)
                self.assertFalse((Path(home) / ".config/osc/oscrc").exists())


if __name__ == "__main__":
    unittest.main()
