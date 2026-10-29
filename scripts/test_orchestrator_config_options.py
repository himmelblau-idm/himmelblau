#!/usr/bin/env python3
"""Isolated regressions for opt-in orchestrator configuration generation."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "src/common/scripts/gen_param_code.py"
ORCHESTRATOR_NAMES = (
    "experimental_orchestrator_enabled",
    "orchestrator_socket",
    "orchestrator_provider",
    "orchestrator_timeout_secs",
    "orchestrator_poll_secs",
)


class OrchestratorConfigTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("rustc"), "rustc is not installed")
    def test_daemon_build_script_preserves_package_example_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "src/daemon"
            manifest.mkdir(parents=True)
            script = root / "src/common/scripts/gen_param_code.py"
            script.parent.mkdir(parents=True)
            shutil.copyfile(GENERATOR, script)
            xml = root / "src/common/docs-xml/himmelblauconf/base"
            xml.mkdir(parents=True)
            for name in (*ORCHESTRATOR_NAMES, "fixture_regular_option"):
                (xml / f"{name}.xml").write_text(
                    f'<parameter name="{name}" type="string" section="global">'
                    '<description>Fixture option.</description>'
                    '<default>fixture</default></parameter>', encoding="utf-8",
                )
            binary = root / "build-config-fixture"
            subprocess.run(
                ["rustc", "--edition=2021", str(ROOT / "src/daemon/build.rs"),
                 "-o", str(binary)],
                check=True, capture_output=True, text=True,
            )
            environment = dict(os.environ, CARGO_MANIFEST_DIR=str(manifest),
                               CARGO_TARGET_DIR=str(root / "output"))
            for value in (None, "1", "1", "0", "1", "0", "false"):
                with self.subTest(value=value):
                    if value is None:
                        environment.pop("WITH_ORCHESTRATOR", None)
                    else:
                        environment["WITH_ORCHESTRATOR"] = value
                    result = subprocess.run(
                        [str(binary)], env=environment, check=True,
                        capture_output=True, text=True,
                    )
                    self.assertIn("cargo:rerun-if-env-changed=WITH_ORCHESTRATOR", result.stdout)
                    for kind in ("config", "debian"):
                        text = (root / "output" / kind / "himmelblau.conf.example").read_text()
                        self.assertIn("fixture_regular_option", text)
                        for name in ORCHESTRATOR_NAMES:
                            self.assertEqual(name in text, value == "1", (kind, name))

    def test_documentation_opt_in_preserves_runtime_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xml = root / "xml" / "base"
            xml.mkdir(parents=True)
            for name in (*ORCHESTRATOR_NAMES, "fixture_regular_option"):
                (xml / f"{name}.xml").write_text(
                    f'<parameter name="{name}" type="string" section="global">'
                    '<description>Fixture option.</description>'
                    '<default>fixture</default><example>example</example>'
                    '</parameter>', encoding="utf-8",
                )
            rust_outputs = []
            for enabled in (False, True):
                with self.subTest(enabled=enabled):
                    output = root / str(enabled)
                    output.mkdir()
                    command = [sys.executable, str(GENERATOR), "--xml-dir", str(xml.parent)]
                    for kind in ("man", "nix", "conf-example", "debian-conf-example", "rust"):
                        command.extend([f"--gen-{kind}", f"--{kind}-output", str(output / kind)])
                    if enabled:
                        command.append("--with-orchestrator")
                    subprocess.run(command, check=True, capture_output=True, text=True)
                    for kind in ("man", "nix", "conf-example", "debian-conf-example"):
                        text = (output / kind).read_text(encoding="utf-8")
                        self.assertIn("fixture_regular_option", text)
                        for name in ORCHESTRATOR_NAMES:
                            self.assertEqual(name in text, enabled, (kind, name))
                    rust_outputs.append((output / "rust").read_text(encoding="utf-8"))
            self.assertEqual(rust_outputs[0], rust_outputs[1])
            for name in ORCHESTRATOR_NAMES:
                self.assertIn(name, rust_outputs[0])

    @unittest.skipUnless(shutil.which("make"), "make is not installed")
    def test_make_passes_opt_in_flag_once(self):
        local_library = str(ROOT / "fixture-local-libhimmelblau")
        cases = (("0", 0, None), ("1", 1, None),
                 ("0", 0, local_library), ("1", 1, local_library))
        for value, expected, library in cases:
            with self.subTest(value=value, local_library=library):
                environment = dict(os.environ)
                if library is None:
                    environment.pop("LIBHIMMELBLAU_LOCAL", None)
                else:
                    environment["LIBHIMMELBLAU_LOCAL"] = library
                result = subprocess.run(
                    ["make", "--no-print-directory", "-n", "conf-examples",
                     f"WITH_ORCHESTRATOR={value}"],
                    cwd=ROOT, env=environment, check=True, capture_output=True, text=True,
                )
                self.assertEqual(result.stdout.count("--with-orchestrator"), expected)
                self.assertIn("--gen-conf-example", result.stdout)
                self.assertIn("--gen-debian-conf-example", result.stdout)
                exported = subprocess.run(
                    ["make", "--no-print-directory", "--eval="
                     '__orchestrator_env_probe: ; @printf "%s" "$$WITH_ORCHESTRATOR"',
                     "__orchestrator_env_probe", f"WITH_ORCHESTRATOR={value}"],
                    cwd=ROOT, env=environment, check=True, capture_output=True, text=True,
                )
                # Makefile informational messages may precede the probe value.
                self.assertEqual(exported.stdout.splitlines()[-1], value)


if __name__ == "__main__":
    unittest.main()
