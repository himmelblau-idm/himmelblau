#!/usr/bin/env python3
"""Exercise Collabora's Arch/Gentoo/Nix packaging without a Rust toolchain.

Run with: python3 scripts/test_collabora_distribution_packaging.py -v
These fixtures check package selection and installed assets, not native package
builds, Nix evaluation, or live login/removal behavior on the target distros.
"""

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen_ebuild = load_script("gen_ebuild")
package_arch = load_script("package_arch")


class DistributionPackagingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="collabora-distributions-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        shutil.copy2(REPO / "Cargo.toml", self.repo / "Cargo.toml")
        shutil.copytree(REPO / "src/collabora/platform", self.repo / "src/collabora/platform")
        shutil.copytree(REPO / "src/broker/platform", self.repo / "src/broker/platform")
        (self.repo / "target/release/locale").mkdir(parents=True)
        (self.repo / "target/release/himmelblau-collabora").write_text("bridge fixture\n")
        (self.repo / "target/release/broker").write_text("broker fixture\n")

    def shell(self, script, **env):
        return subprocess.run(
            ["bash", "-e", "-c", script],
            cwd=self.repo,
            env={**os.environ, **{key: str(value) for key, value in env.items()}},
            text=True, capture_output=True, check=True,
        ).stdout

    def test_arch_build_selects_bridge_and_defines_optional_package(self):
        output = self.shell(
            'source "$PKGBUILD"\n'
            'printf "packages: %s\\n" "${pkgname[*]}"\n'
            'python3() { :; }\n'
            'cargo() { printf "cargo: %s\\n" "$*"; }\n'
            'build\n',
            PKGBUILD=REPO / "platform/arch/PKGBUILD", HIMMELBLAU_SRC=self.repo,
        )
        self.assertIn("packages: himmelblau himmelblau-collabora\n", output)
        self.assertIn("-p himmelblau-collabora", output)

    def test_arch_bridge_installs_only_its_assets(self):
        dest = self.root / "pkg"
        output = self.shell(
            'source "$PKGBUILD"\n'
            'package_himmelblau-collabora\n'
            'printf "depends: %s\\ninstall: %s\\nprovides: %s\\n" '
            '"${depends[*]}" "$install" "${provides[*]}"\n',
            PKGBUILD=REPO / "platform/arch/PKGBUILD", HIMMELBLAU_SRC=self.repo,
            pkgdir=dest,
        )
        paths = {
            str(path.relative_to(dest)): path.stat().st_mode & 0o777
            for path in dest.rglob("*") if path.is_file()
        }
        self.assertEqual(paths, {
            "usr/bin/himmelblau-collabora": 0o755,
            "usr/lib/systemd/user/himmelblau-collabora.service": 0o644,
            "etc/xdg/autostart/himmelblau-collabora.desktop": 0o644,
        })
        self.assertRegex(output, r"depends: himmelblau=[^\n]+-1\n")
        self.assertIn("install: \nprovides: \n", output)

    def test_arch_core_does_not_install_bridge_assets(self):
        output = self.shell(
            'source "$PKGBUILD"\n'
            'install() { printf "%s\\n" "$*"; }\n'
            'package_himmelblau\n',
            PKGBUILD=REPO / "platform/arch/PKGBUILD", HIMMELBLAU_SRC=self.repo,
            pkgdir=self.root / "core",
        )
        self.assertNotIn("himmelblau-collabora", output)
        self.assertNotIn("src/collabora/", output)

    def test_arch_runner_copies_both_split_packages(self):
        arch = self.repo / "platform/arch"
        arch.mkdir(parents=True)
        (arch / "PKGBUILD").touch()
        out = self.root / "packaging"
        names = [
            "himmelblau-5.0.0-1-x86_64.pkg.tar.zst",
            "himmelblau-collabora-5.0.0-1-x86_64.pkg.tar.zst",
        ]

        def fake_makepkg(command, **kwargs):
            self.assertEqual(command[0], "makepkg")
            for name in names:
                (Path(kwargs["env"]["PKGDEST"]) / name).write_text(name)

        with patch.object(package_arch, "BUILD_ROOT", self.root / "build"), \
                patch.object(package_arch.os, "geteuid", return_value=1000), \
                patch.object(package_arch, "run", side_effect=fake_makepkg), \
                patch.object(sys, "argv", [
                    "package_arch.py", "--repo-root", str(self.repo), "--out", str(out),
                ]):
            self.assertEqual(package_arch.main(), 0)
        self.assertEqual(sorted(path.name for path in out.iterdir()), sorted(names))

    def run_make_recipe(self, target, manager="pacman", installed="installed",
                        os_id="arch", cleanup_status=0, query_status=0):
        recipe = (REPO / "Makefile").read_text().split(f"\n{target}:", 1)[1]
        recipe = recipe.split("\n", 1)[1].split("\n\n", 1)[0]
        recipe = "\n".join(line.removeprefix("\t").removeprefix("@") for line in recipe.splitlines())
        recipe = recipe.replace("$$", "$").replace("$(DESTDIR)", "")
        recipe = recipe.replace(". /etc/os-release", '. "$TEST_OS_RELEASE"')
        os_release = self.root / "os-release"
        os_release.write_text(f"ID={os_id}\n")
        calls_path = self.root / "package-manager-calls"
        calls_path.write_text("")
        bins = self.root / "bin"
        bins.mkdir(exist_ok=True)
        stub = f"#!{sys.executable}\n" + '''
import json
import os
from pathlib import Path
import subprocess
import sys
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TEST_CALLS"], "a") as stream:
    stream.write(json.dumps([name, *args]) + "\\n")
if name == "sudo":
    if args == ["env", "-u", "DPKG_ROOT", "sh", "src/collabora/platform/prerm", "remove"]:
        assert Path(args[-2]).is_file()
        sys.exit(int(os.environ["CLEANUP_STATUS"]))
    assert args[0] in ("pacman", "apt-get", "dnf", "yum", "zypper")
    sys.exit(subprocess.call(args))
if (name == "pacman" and args == ["-Qq"]) or name in ("dpkg-query", "rpm"):
    status = int(os.environ["QUERY_STATUS"])
    if status:
        sys.exit(status)
    installed = os.environ["INSTALLED"]
    if name == "dpkg-query":
        print("himmelblau installed")
        if installed != "none":
            print("himmelblau-collabora " + installed)
    else:
        print("himmelblau")
        if installed == "installed":
            print("himmelblau-collabora")
'''
        for name in ("sudo", "pacman", "apt-get", "dnf", "yum", "zypper", "dpkg-query", "rpm"):
            command = bins / name
            command.write_text(stub)
            command.chmod(0o755)
        # Force each distro branch without depending on the test host's package
        # manager. Every package command remains a fixture executable.
        prefix = '''
command() {
    if [ "$1" = -v ] && [ "$#" = 2 ]; then
        [ "$2" = "$TEST_MANAGER" ]
    else
        builtin command "$@"
    fi
}
'''
        result = subprocess.run(
            ["bash", "-e", "-c", prefix + recipe], cwd=self.repo,
            env={**os.environ, "PATH": f"{bins}:/usr/bin:/bin", "TEST_MANAGER": manager,
                 "TEST_OS_RELEASE": str(os_release), "TEST_CALLS": str(calls_path),
                 "INSTALLED": installed, "CLEANUP_STATUS": str(cleanup_status),
                 "QUERY_STATUS": str(query_status), "DPKG_ROOT": "/must-not-skip-host-cleanup"},
            capture_output=True, text=True,
        )
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
        return result, calls

    def test_arch_make_install_keeps_bridge_optional(self):
        packaging = self.repo / "packaging"
        packaging.mkdir()
        core = "himmelblau-5.0.0-1-x86_64.pkg.tar.zst"
        bridge = "himmelblau-collabora-5.0.0-1-x86_64.pkg.tar.zst"
        (packaging / core).touch()
        (packaging / bridge).touch()
        for os_id in ("arch", "unknown-arch-derivative"):
            with self.subTest(os_id=os_id):
                result, calls = self.run_make_recipe("install", os_id=os_id)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [["pacman", "-U", "--noconfirm", f"./packaging/{core}"]])
        (packaging / core).unlink()
        result, calls = self.run_make_recipe("install")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_arch_uninstall_cleans_bridge_before_removing_packages(self):
        for installed in ("none", "installed"):
            with self.subTest(installed=installed):
                result, calls = self.run_make_recipe("uninstall", installed=installed)
                self.assertEqual(result.returncode, 0, result.stderr)
                removal = calls[-1]
                self.assertEqual(removal[:3], ["pacman", "-Rns", "--noconfirm"])
                if installed == "installed":
                    self.assertEqual(calls[1], [
                        "sudo", "env", "-u", "DPKG_ROOT", "sh",
                        "src/collabora/platform/prerm", "remove",
                    ])
                    self.assertEqual(removal[3:], ["himmelblau", "himmelblau-collabora"])
                else:
                    self.assertEqual(removal[3:], ["himmelblau"])
                    self.assertFalse(any("prerm" in " ".join(call) for call in calls))

    def test_arch_cleanup_failure_blocks_package_removal(self):
        result, calls = self.run_make_recipe("uninstall", cleanup_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], ["pacman", "-Qq"])
        self.assertEqual(calls[1][-2:], ["src/collabora/platform/prerm", "remove"])

    def test_deb_rpm_uninstall_includes_installed_bridge(self):
        for manager in ("apt-get", "dnf", "yum", "zypper"):
            for installed in ("none", "installed"):
                with self.subTest(manager=manager, installed=installed):
                    result, calls = self.run_make_recipe("uninstall", manager=manager, installed=installed)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(calls[-1][0], manager)
                    self.assertEqual("himmelblau-collabora" in calls[-1], installed == "installed")
                    self.assertFalse(any("prerm" in " ".join(call) for call in calls))
        for installed in ("config-files", "not-installed", "half-configured"):
            with self.subTest(debian_status=installed):
                result, calls = self.run_make_recipe("uninstall", manager="apt-get", installed=installed)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("himmelblau-collabora" in calls[-1], installed == "half-configured")

    def test_uninstall_package_query_failure_blocks_removal(self):
        for manager in ("pacman", "apt-get", "dnf"):
            with self.subTest(manager=manager):
                result, calls = self.run_make_recipe("uninstall", manager=manager, query_status=1)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)

    def check_gentoo_install(self, ebuild):
        ebuild_path = self.root / "himmelblau.ebuild"
        ebuild_path.write_text(ebuild)
        self.assertIn('IUSE="+tpm collabora"', ebuild)
        script = '''
inherit() { :; }
use() { [ "$1" = collabora ] && [ "$COLLABORA" = 1 ]; }
for command in dobin newbin dosbin newsbin into dolib.so dosym dopammod systemd_dounit \
    systemd_douserunit insinto doins newins doman dodoc; do
    eval "$command() { printf '%s %s\\\\n' '$command' \\"\\$*\\"; }"
done
source "$EBUILD"
S="$FIXTURE_S"
# Stage the actual available fixture assets as the corresponding eclass helpers
# would. Missing unrelated core artifacts remain outside this fixture's scope.
stage_asset() {
    if [ -f "$2" ]; then
        install -Dm"$1" "$2" "$DEST$3"
    fi
}
dobin() {
    printf 'dobin %s\\n' "$*"
    stage_asset 755 "$1" "/usr/bin/${1##*/}"
}
newsbin() {
    printf 'newsbin %s\\n' "$*"
    stage_asset 755 "$1" "/usr/sbin/$2"
}
systemd_douserunit() {
    printf 'systemd_douserunit %s\\n' "$*"
    stage_asset 644 "$1" "/usr/lib/systemd/user/${1##*/}"
}
insinto() { printf 'insinto %s\\n' "$*"; INSDEST="$1"; }
doins() {
    printf 'doins %s\\n' "$*"
    stage_asset 644 "$1" "$INSDEST/${1##*/}"
}
src_install
'''
        for enabled in (0, 1):
            with self.subTest(collabora=enabled):
                dest = self.root / f"gentoo-{enabled}"
                output = self.shell(
                    script, EBUILD=ebuild_path, COLLABORA=enabled,
                    FIXTURE_S=self.repo, DEST=dest,
                )
                bridge = [line for line in output.splitlines() if "himmelblau-collabora" in line]
                if enabled:
                    self.assertEqual(len(bridge), 3)
                    self.assertIn(f"dobin {self.repo}/target/release/himmelblau-collabora", bridge)
                    self.assertIn(
                        f"systemd_douserunit {self.repo}/src/collabora/platform/himmelblau-collabora.service",
                        bridge,
                    )
                    self.assertIn("insinto /etc/xdg/autostart", output)
                    self.assertIn(f"newsbin {self.repo}/target/release/broker himmelblau_broker", output)
                    self.assertIn(
                        f"systemd_douserunit {self.repo}/src/broker/platform/himmelblau-broker.service",
                        output,
                    )
                    self.assertIn(
                        f"doins {self.repo}/src/broker/platform/com.microsoft.identity.broker1.service",
                        output,
                    )
                    for path, mode in {
                        "usr/bin/himmelblau-collabora": 0o755,
                        "usr/lib/systemd/user/himmelblau-collabora.service": 0o644,
                        "etc/xdg/autostart/himmelblau-collabora.desktop": 0o644,
                        "usr/sbin/himmelblau_broker": 0o755,
                        "usr/lib/systemd/user/himmelblau-broker.service": 0o644,
                        "usr/share/dbus-1/services/com.microsoft.identity.broker1.service": 0o644,
                    }.items():
                        self.assertEqual((dest / path).stat().st_mode & 0o777, mode)
                else:
                    self.assertEqual(bridge, [])
                    self.assertFalse(list(dest.rglob("*himmelblau-collabora*")))

    def test_gentoo_optional_assets_from_cargo_metadata(self):
        self.check_gentoo_install(gen_ebuild.generate_ebuild(REPO))

    def test_gentoo_optional_assets_in_asset_fallback(self):
        with patch.object(gen_ebuild, "collect_all_assets", return_value=[]):
            self.check_gentoo_install(gen_ebuild.generate_ebuild(REPO))

    def test_gentoo_generation_without_toml_parser(self):
        with patch.object(gen_ebuild, "tomllib", None):
            ebuild = gen_ebuild.generate_ebuild(REPO)
            self.assertIn('HOMEPAGE="https://github.com/himmelblau-idm/himmelblau"', ebuild)
            self.check_gentoo_install(ebuild)

    def test_nix_package_exports_and_relocates_desktop_assets(self):
        default_nix = (REPO / "default.nix").read_text()
        self.assertIn('collabora = cargo_nix.workspaceMembers."himmelblau-collabora".build;', default_nix)
        self.assertIn('"himmelblau-collabora" = rec {', (REPO / "Cargo.nix").read_text())
        self.assertIn(".#collabora", (REPO / ".github/workflows/nixosbuild-ci.yml").read_text())
        match = re.search(
            r"himmelblau-collabora = attrs: \{\s*postInstall = .*?\+ ''(.*?)'';",
            default_nix, re.S,
        )
        self.assertIsNotNone(match)
        out = self.root / "nix-output"
        systemd = self.root / "systemd"
        # Execute the packaging shell fragment with a store-path fixture and the
        # same fail-if-missing replacement behavior as substituteInPlace.
        substitute = '''
substituteInPlace() {
    python3 - "$@" <<'PY'
from pathlib import Path
import sys
path, option, old, new = sys.argv[1:]
assert option == "--replace-fail"
text = Path(path).read_text()
assert old in text
Path(path).write_text(text.replace(old, new))
PY
}
'''
        self.shell(
            substitute + '\ncd src/collabora\n' + match.group(1).replace("${pkgs.systemd}", str(systemd)),
            out=out,
        )
        unit = (out / "lib/systemd/user/himmelblau-collabora.service").read_text()
        desktop = (out / "etc/xdg/autostart/himmelblau-collabora.desktop").read_text()
        self.assertIn(f"ExecStart={out}/bin/himmelblau-collabora serve", unit)
        self.assertIn(f"Exec={systemd}/bin/systemctl --user start himmelblau-collabora.service", desktop)
        self.assertNotIn("/usr/bin/himmelblau-collabora", unit)
        for path in out.rglob("*"):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
