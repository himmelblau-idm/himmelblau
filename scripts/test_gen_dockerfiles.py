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
        self.assertIn("FROM --platform=linux/arm64 fedora:44", dockerfile)
        self.assertIn("cargo install cargo-deb cargo-generate-rpm", dockerfile)

    def test_amd64_rpm_pins_amd64_base(self):
        dockerfile = gen_dockerfiles.render(
            "rawhide",
            gen_dockerfiles.DISTS["rawhide"],
            patch_libhimmelblau=False,
            arch="amd64",
        )

        self.assertIn(
            "FROM --platform=linux/amd64 fedora:rawhide", dockerfile
        )

    def test_arm64_deb_cross_compile_uses_amd64_base(self):
        dockerfile = gen_dockerfiles.render(
            "ubuntu24.04",
            gen_dockerfiles.DISTS["ubuntu24.04"],
            patch_libhimmelblau=False,
            arch="arm64",
        )

        self.assertIn(
            "FROM --platform=linux/amd64 ubuntu:24.04", dockerfile
        )


if __name__ == "__main__":
    unittest.main()
