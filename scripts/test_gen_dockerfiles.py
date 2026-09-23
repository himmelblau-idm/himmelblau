import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("gen_dockerfiles.py")
SPEC = importlib.util.spec_from_file_location("gen_dockerfiles", MODULE_PATH)
gen_dockerfiles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen_dockerfiles)


class Arm64RpmDockerfileTests(unittest.TestCase):
    def test_arm64_rpm_installs_packaging_tools_in_target_image(self):
        dockerfile = gen_dockerfiles.render(
            "fedora44",
            gen_dockerfiles.DISTS["fedora44"],
            patch_libhimmelblau=False,
            arch="arm64",
        )

        self.assertNotIn("FROM --platform=linux/amd64 rust:latest AS tooling", dockerfile)
        self.assertNotIn("COPY --from=tooling", dockerfile)
        self.assertIn("FROM fedora:44", dockerfile)
        self.assertIn("cargo install cargo-generate-rpm", dockerfile)
        self.assertNotIn("cargo-deb", dockerfile)


class PackagingToolTests(unittest.TestCase):
    def test_packaging_tools_match_distro_family_on_each_architecture(self):
        for name, config in gen_dockerfiles.DISTS.items():
            for arch in gen_dockerfiles.ARCH_MAP:
                with self.subTest(distro=name, arch=arch):
                    dockerfile = gen_dockerfiles.render(
                        name, config, patch_libhimmelblau=False, arch=arch
                    )
                    family = config["family"]
                    if family == "deb":
                        self.assertIn("cargo install cargo-deb", dockerfile)
                        self.assertNotIn("cargo-generate-rpm", dockerfile)
                    elif family in ("rpm", "zypper"):
                        self.assertIn("cargo install cargo-generate-rpm", dockerfile)
                        self.assertNotIn("cargo-deb", dockerfile)
                    else:
                        self.assertNotIn("cargo install", dockerfile)


if __name__ == "__main__":
    unittest.main()
