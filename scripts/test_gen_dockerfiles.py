import importlib.util
import shlex
import tomllib
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("gen_dockerfiles.py")
SPEC = importlib.util.spec_from_file_location("gen_dockerfiles", MODULE_PATH)
gen_dockerfiles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen_dockerfiles)


class DebianPamProfileTests(unittest.TestCase):
    def test_profiles_differ_only_in_debian_auth_workaround(self):
        root = MODULE_PATH.parent.parent
        ubuntu = (root / "platform/ubuntu/pam-config").read_text()
        debian = (root / "platform/debian/pam-config").read_text()
        auth = "pam_himmelblau.so ignore_unknown_user set_authtok"
        self.assertNotIn("mfa_poll_prompt", ubuntu)
        self.assertEqual(debian.count("mfa_poll_prompt"), 1)
        self.assertEqual(debian, ubuntu.replace(auth + "\n", auth + " mfa_poll_prompt\n", 1))

    def test_generated_packages_select_only_debian_profile(self):
        root = MODULE_PATH.parent.parent
        metadata = tomllib.loads((root / "src/pam/Cargo.toml").read_text())["package"]["metadata"]["deb"]
        destination = "usr/share/pam-configs/himmelblau"
        default_assets = {asset[1]: asset for asset in metadata["assets"]}
        self.assertEqual(default_assets[destination],
                         ["../../platform/ubuntu/pam-config", destination, "644"])
        variant = metadata["variants"]["debian"]
        self.assertEqual(variant["name"], metadata["name"])
        self.assertEqual(variant["merge-assets"]["by"]["dest"],
                         [["../../platform/debian/pam-config", destination, "644"]])
        for distro, config in gen_dockerfiles.DISTS.items():
            if config["family"] != "deb" or distro == "test":
                continue
            for arch in gen_dockerfiles.ARCH_MAP:
                with self.subTest(distro=distro, arch=arch):
                    rendered = gen_dockerfiles.render(distro, config, False, arch=arch)
                    commands = [line for line in rendered.splitlines() if "cargo deb " in line]
                    self.assertTrue(commands)
                    pam = next(line for line in commands if "-p pam_himmelblau" in line)
                    expected = distro.startswith("debian")
                    self.assertEqual("--variant=debian" in pam, expected)
                    for command in commands:
                        if command != pam:
                            self.assertNotIn("--variant", command)
                    assets = dict(default_assets)
                    if "--variant=debian" in shlex.split(pam):
                        assets.update({asset[1]: asset for asset in variant["merge-assets"]["by"]["dest"]})
                    profile = (root / "src/pam" / assets[destination][0]).read_text()
                    self.assertEqual("mfa_poll_prompt" in profile, expected)
                    self.assertEqual(set(assets), set(default_assets))
                    for dest, asset in default_assets.items():
                        if dest != destination:
                            self.assertEqual(assets[dest], asset)

    def test_unknown_deb_derivative_does_not_inherit_debian_workaround(self):
        command = gen_dockerfiles.build_deb_final_cmd([], "derivative1")
        self.assertNotIn("--variant", command)


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
    def test_rpm_images_install_native_dependency_scanner(self):
        for name, config in gen_dockerfiles.DISTS.items():
            if config["family"] not in ("rpm", "zypper"):
                continue
            for arch in gen_dockerfiles.ARCH_MAP:
                with self.subTest(distro=name, arch=arch):
                    dockerfile = gen_dockerfiles.render(
                        name, config, patch_libhimmelblau=False, arch=arch
                    )
                    self.assertIn("rpm-build", dockerfile.split())

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

    def test_rpm_release_defaults_to_one_and_can_be_overridden(self):
        dockerfile = gen_dockerfiles.render(
            "rocky9",
            gen_dockerfiles.DISTS["rocky9"],
            patch_libhimmelblau=False,
            arch="amd64",
        )

        self.assertIn(r'''RPM_INTERNAL_RELEASE=\"${RPM_PACKAGE_RELEASE:-1}\"''', dockerfile)
        self.assertIn(
            r'''--set-metadata \"release = '${RPM_INTERNAL_RELEASE}'\"''',
            dockerfile,
        )

    def test_interdependent_rpms_require_matching_versions(self):
        dockerfile = gen_dockerfiles.render(
            "rocky9",
            gen_dockerfiles.DISTS["rocky9"],
            patch_libhimmelblau=False,
            arch="amd64",
        )

        expected = {
            "src/nss": "himmelblau",
            "src/pam": "himmelblau",
            "src/broker": "himmelblau",
            "src/sso": "himmelblau-broker",
            "src/o365": "himmelblau",
        }
        self.assertIn("RPM_INTERNAL_VERSION=$(cargo metadata --no-deps", dockerfile)
        for crate, dependency in expected.items():
            with self.subTest(crate=crate):
                self.assertIn(
                    f"cargo generate-rpm -p {crate} "
                    + r'''--set-metadata \"release = '${RPM_INTERNAL_RELEASE}'\" '''
                    + r'''--set-metadata \"requires = { '''
                    + f"{dependency} = '= ${{RPM_INTERNAL_VERSION}}-${{RPM_INTERNAL_RELEASE}}'"
                    + r''' }\"''',
                    dockerfile,
                )


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
