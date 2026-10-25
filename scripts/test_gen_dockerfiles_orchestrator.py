"""Regressions for per-invocation optional orchestrator generation."""

import contextlib
import importlib.util
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("gen_dockerfiles.py")
SPEC = importlib.util.spec_from_file_location("gen_dockerfiles_orchestrator", MODULE_PATH)
gen_dockerfiles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen_dockerfiles)


class OptionalOrchestratorTests(unittest.TestCase):
    def assert_selection(self, name, dockerfile, enabled):
        config = gen_dockerfiles.DISTS[name]
        family = config["family"]
        selection_env = [
            line for line in dockerfile.splitlines() if line.startswith("ENV WITH_ORCHESTRATOR=")
        ]
        self.assertEqual(
            selection_env,
            [] if family == "ebuild" else [f"ENV WITH_ORCHESTRATOR={int(enabled)}"],
        )
        if name == "test":
            command = next(line for line in dockerfile.splitlines() if line.startswith("CMD "))
            # --workspace adds orchestrator to the baseline, unlike -p, which
            # would select only orchestrator and omit the default members.
            self.assertEqual(
                command,
                "CMD python3 scripts/test_hsm_pin_init.py && cargo test"
                + (" --workspace" if enabled else ""),
            )
            return

        if family == "arch":
            self.assertIn("python3 scripts/package_arch.py --out ./packaging/", dockerfile)
            self.assertNotIn("--with-orchestrator", dockerfile)
            return

        self.assertEqual(dockerfile.count("--with-orchestrator"), int(enabled))
        if family == "ebuild":
            self.assertIn("python3 scripts/gen_ebuild.py --out ./packaging/", dockerfile)
            return

        packages = list(gen_dockerfiles.PACKAGES)
        if enabled:
            packages.append(("himmelblau-orchestrator", "src/orchestrator", False))
        if family == "deb":
            actual = re.findall(r"cargo deb [^&\n]* -p ([\w-]+)", dockerfile)
            expected = [pkg for pkg, _, _ in packages if pkg != "selinux"]
        else:
            actual = re.findall(r"cargo generate-rpm -p ([\w/-]+)", dockerfile)
            expected = [
                source for pkg, source, _ in packages
                if (pkg != "selinux" or config.get("selinux", False))
                and (pkg != "apparmor" or config.get("apparmor", False))
            ]
            self.assertEqual(
                dockerfile.count("--exclude himmelblau-orchestrator"), int(not enabled),
            )
            self.assertEqual(
                dockerfile.count("strip -s target/release/himmelblaud-orchestrator"),
                int(enabled),
            )
        self.assertEqual(actual, expected)

    def generate(self, enabled, arch, only=""):
        with tempfile.TemporaryDirectory() as directory:
            argv = [str(MODULE_PATH), "--out", directory, "--arch", arch]
            if only:
                argv.extend(["--only", only])
            if enabled:
                argv.append("--with-orchestrator")
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                gen_dockerfiles.main()
            return {path.name: path.read_text() for path in Path(directory).iterdir()}

    def test_test_target_retains_default_tests_and_opts_in_to_workspace(self):
        for enabled in (False, True):
            for arch in gen_dockerfiles.ARCH_MAP:
                with self.subTest(enabled=enabled, arch=arch):
                    suffix = f".{arch}" if arch != "amd64" else ""
                    dockerfile = self.generate(enabled, arch, only="test")[f"Dockerfile.test{suffix}"]
                    self.assert_selection("test", dockerfile, enabled)

    def test_render_selects_packages_and_docs_per_call_for_every_distro(self):
        for name, config in gen_dockerfiles.DISTS.items():
            for arch in gen_dockerfiles.ARCH_MAP:
                for enabled in (True, False, True):
                    with self.subTest(distro=name, arch=arch, enabled=enabled):
                        dockerfile = gen_dockerfiles.render(
                            name, config, patch_libhimmelblau=False,
                            arch=arch, with_orchestrator=enabled,
                        )
                        self.assert_selection(name, dockerfile, enabled)
                        if not enabled:
                            self.assertEqual(
                                dockerfile,
                                gen_dockerfiles.render(name, config, False, arch=arch),
                            )

    def test_repeated_main_invocations_do_not_leak_or_duplicate_state(self):
        packages = list(gen_dockerfiles.PACKAGES)
        manpage = gen_dockerfiles.GEN_MANPAGE
        for arch in gen_dockerfiles.ARCH_MAP:
            snapshots = {}
            for enabled in (False, True, True, False, True, False):
                with self.subTest(arch=arch, enabled=enabled):
                    files = self.generate(enabled, arch)
                    self.assertEqual(gen_dockerfiles.PACKAGES, packages)
                    self.assertEqual(gen_dockerfiles.GEN_MANPAGE, manpage)
                    suffix = f".{arch}" if arch != "amd64" else ""
                    expected_names = {
                        f"Dockerfile.{name}{suffix}" for name, config in gen_dockerfiles.DISTS.items()
                        if arch == "amd64" or config.get(arch, True)
                    }
                    self.assertEqual(set(files), expected_names)
                    for name, config in gen_dockerfiles.DISTS.items():
                        if arch != "amd64" and not config.get(arch, True):
                            continue
                        self.assert_selection(name, files[f"Dockerfile.{name}{suffix}"], enabled)
                    if enabled in snapshots:
                        self.assertEqual(files, snapshots[enabled])
                    else:
                        snapshots[enabled] = files


if __name__ == "__main__":
    unittest.main()
