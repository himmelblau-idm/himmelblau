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

    def test_rpm_release_can_be_overridden_without_changing_the_default(self):
        dockerfile = gen_dockerfiles.render(
            "rocky9",
            gen_dockerfiles.DISTS["rocky9"],
            patch_libhimmelblau=False,
            arch="amd64",
        )

        self.assertIn('if [ -n \\"${RPM_PACKAGE_RELEASE:-}\\" ]', dockerfile)
        self.assertIn(r'''--set-metadata \"release = '${RPM_PACKAGE_RELEASE}'\"''', dockerfile)
        self.assertIn("else cargo generate-rpm", dockerfile)


class SleRepositoryTests(unittest.TestCase):
    def test_sle_uses_public_repositories_without_registration(self):
        expected = {
            "sle15sp7": (
                "registry.suse.com/bci/ruby:2.5",
                "https://download.opensuse.org/repositories/openSUSE:/Backports:/SLE-15-SP7/standard/",
            ),
            "sle16": (
                "registry.suse.com/bci/bci-base:16.0",
                "https://download.opensuse.org/distribution/leap/16.0/repo/oss",
            ),
        }

        self.assertNotIn("sle15sp6", gen_dockerfiles.DISTS)

        for name, (image, repository) in expected.items():
            with self.subTest(distro=name):
                config = gen_dockerfiles.DISTS[name]
                dockerfile = gen_dockerfiles.render(
                    name, config, patch_libhimmelblau=False, arch="amd64"
                )
                self.assertNotIn("scc", config)
                self.assertIn(f"FROM {image}", dockerfile)
                if repository:
                    self.assertIn(repository, dockerfile)
                if name == "sle15sp7":
                    self.assertIn("openSUSE:/Backports:/SLE-15-SP7:/Update", dockerfile)
                    self.assertIn("clang14", dockerfile)
                    self.assertNotIn("opensuse/leap:15.6", dockerfile)
                self.assertNotIn("SUSEConnect", dockerfile)
                self.assertNotIn("scc_regcode", dockerfile)


if __name__ == "__main__":
    unittest.main()
