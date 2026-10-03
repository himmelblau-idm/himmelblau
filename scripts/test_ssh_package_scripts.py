"""Exercise SSH package scripts against isolated paths and fake services."""

import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

from scripts import gen_ebuild


SCRIPTS = Path(__file__).parents[1] / "src/sshd-config/scripts"


class PackageScriptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "run").mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.dropin = self.root / "etc/ssh/sshd_config.d/30-himmelblau.conf"
        self.template = self.root / "usr/lib/himmelblau/ssh/30-himmelblau.conf"
        self.template.parent.mkdir(parents=True)
        self.template.write_text("# test configuration\n")
        self.calls = self.root / "calls"
        for name in ["systemd-sysusers", "sshd", "systemctl"]:
            self.helper(name, f'#!/bin/sh\necho "{name} $*" >>"$CALLS"\n')
        self.refresh = self.bin / "himmelblau-ssh-ca-refresh"
        self.helper("himmelblau-ssh-ca-refresh", '''#!/bin/sh
[ "$1" = --allow-unconfigured ] || exit 1
mkdir -p "$(dirname "$TRUST")"
echo "refresh $*" >>"$CALLS"
printf '# empty trust before domain configuration\n' >"$TRUST"
''')

    def helper(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def run_script(self, name, *args, expected_status=0):
        script = self.root / name
        script.write_text(SCRIPTS.joinpath(name).read_text()
            .replace("/var/lib/himmelblau", str(self.root / "var/lib/himmelblau"))
            .replace("/run/himmelblau", str(self.root / "run/himmelblau"))
            .replace("/etc/ssh", str(self.root / "etc/ssh"))
            .replace("/usr/lib/himmelblau", str(self.root / "usr/lib/himmelblau"))
            .replace("/usr/libexec/himmelblau-ssh-ca-refresh", str(self.refresh)))
        result = subprocess.run(["/bin/sh", str(script), *args], capture_output=True,
            env={**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin", "CALLS": str(self.calls),
                 "TRUST": str(self.root / "var/lib/himmelblau/ssh-ca/trusted_user_ca_keys")})
        self.assertEqual(result.returncode, expected_status, result.stderr)

    def test_fresh_install_creates_backup_parent_and_enables_deferred_refresh(self):
        self.assertFalse((self.root / "var/lib/himmelblau").exists())
        self.run_script("postinst", "configure")
        self.assertEqual(self.dropin.read_text(), self.template.read_text())
        calls = self.calls.read_text()
        self.assertIn("refresh --allow-unconfigured", calls)
        self.assertIn("enable --now himmelblau-ssh-ca-refresh.timer", calls)
        self.assertEqual(list((self.root / "run").glob("himmelblau-ssh-ca-install.*")), [])

    def test_postinst_leaves_state_tree_creation_to_refresh_helper(self):
        script = SCRIPTS.joinpath("postinst").read_text()
        self.assertNotIn("mkdir -p /etc/ssh/sshd_config.d /var/lib/himmelblau/ssh-ca", script)

    def test_toml_fallback_installs_complete_ssh_integration(self):
        fallback = gen_ebuild._fallback_install()
        for asset in [
            "target/release/himmelblau-ssh-prepare",
            "target/release/himmelblau-ssh-authorize",
            "target/release/himmelblau-ssh-ca-refresh",
            "src/sshd-config/scripts/himmelblau-ssh-ca-update",
            "platform/common/himmelblau-ssh-authorizer.sysusers",
            "platform/common/himmelblau-ssh-ca-refresh.service",
            "platform/common/himmelblau-ssh-ca-refresh.timer",
            "platform/el/ssh_config",
            "platform/el/sshd_config",
        ]:
            with self.subTest(asset=asset):
                self.assertIn(asset, fallback)

    def test_ssh_package_requires_protocol_compatible_daemon(self):
        metadata = tomllib.loads(
            (Path(__file__).parents[1] / "src/sshd-config/Cargo.toml").read_text()
        )["package"]["metadata"]
        self.assertIn("himmelblau (>= 4.0.0)", metadata["deb"]["depends"])
        self.assertEqual(metadata["generate-rpm"]["requires"]["himmelblau"], ">= 4.0.0")

    def test_main_config_pam_migration_and_validation_rollback(self):
        main = self.root / "etc/ssh/sshd_config"
        main.parent.mkdir(parents=True)
        original = "KbdInteractiveAuthentication no\nInclude sshd_config.d/*.conf\n"
        main.write_text(original)
        self.run_script("postinst", "configure")
        self.assertIn("KbdInteractiveAuthentication yes", main.read_text())
        main.write_text(original)
        old_dropin = self.dropin.read_text()
        self.helper("sshd", "#!/bin/sh\nexit 1\n")
        self.run_script("postinst", "configure", expected_status=1)
        self.assertEqual(main.read_text(), original)
        self.assertEqual(self.dropin.read_text(), old_dropin)

    def test_validation_rollback_never_follows_provenance_symlink(self):
        provenance = self.root / "var/lib/himmelblau/ssh-ca/provenance.json"
        provenance.parent.mkdir(parents=True)
        target = self.root / "outside-provenance-target"
        target.write_text("must remain unchanged\n")
        provenance.symlink_to(target)
        self.helper("sshd", "#!/bin/sh\nexit 1\n")

        self.run_script("postinst", "configure", expected_status=1)

        self.assertEqual(target.read_text(), "must remain unchanged\n")
        self.assertTrue(provenance.is_symlink())

    def test_discovery_outage_installs_timer_and_preserves_fresh_trust(self):
        trust = self.root / "var/lib/himmelblau/ssh-ca/trusted_user_ca_keys"
        trust.parent.mkdir(parents=True)
        trust.write_text("existing fresh CA\n")
        self.helper("himmelblau-ssh-ca-refresh", '''#!/bin/sh
echo "refresh $*" >>"$CALLS"
if [ "$1" = --disable-if-stale ]; then exit 2; fi
exit 1
''')
        self.run_script("postinst", "configure")
        self.assertEqual(trust.read_text(), "existing fresh CA\n")
        self.assertEqual(self.dropin.read_text(), self.template.read_text())
        self.assertIn("refresh --disable-if-stale", self.calls.read_text())
        self.assertIn("enable --now himmelblau-ssh-ca-refresh.timer", self.calls.read_text())

    def test_discovery_outage_first_install_has_disabled_trust(self):
        self.helper("himmelblau-ssh-ca-refresh", '''#!/bin/sh
mkdir -p "$(dirname "$TRUST")"
[ "$1" = --disable-if-stale ]
''')
        self.run_script("postinst", "configure")
        trust = self.root / "var/lib/himmelblau/ssh-ca/trusted_user_ca_keys"
        self.assertEqual(trust.read_text(), "# Entra trust disabled pending successful discovery\n")
        self.assertIn("enable --now himmelblau-ssh-ca-refresh.timer", self.calls.read_text())

    def test_discovery_outage_with_trust_check_failure_aborts(self):
        self.helper("himmelblau-ssh-ca-refresh", "#!/bin/sh\nexit 1\n")
        self.run_script("postinst", "configure", expected_status=1)
        self.assertFalse(self.dropin.exists())

    def test_discovery_outage_disables_stale_trust_before_install(self):
        trust = self.root / "var/lib/himmelblau/ssh-ca/trusted_user_ca_keys"
        trust.parent.mkdir(parents=True)
        trust.write_text("expired CA\n")
        self.helper("himmelblau-ssh-ca-refresh", '''#!/bin/sh
if [ "$1" = --disable-if-stale ]; then
    printf '# disabled stale trust\\n' >"$TRUST"
    exit 0
fi
exit 1
''')
        self.run_script("postinst", "configure")
        self.assertEqual(trust.read_text(), "# disabled stale trust\n")
        self.assertIn("enable --now himmelblau-ssh-ca-refresh.timer", self.calls.read_text())

    def test_rpm_and_debian_upgrades_preserve_dropin_and_timer(self):
        self.dropin.parent.mkdir(parents=True)
        self.dropin.write_text("new package configuration")
        for argument in ["1", "upgrade", "deconfigure"]:
            with self.subTest(argument=argument):
                self.run_script("prerm", argument)
                self.assertEqual(self.dropin.read_text(), "new package configuration")
                self.assertFalse(self.calls.exists())

    def test_rpm_and_debian_removal_clean_up(self):
        self.dropin.parent.mkdir(parents=True)
        for argument in ["0", "remove", "purge"]:
            with self.subTest(argument=argument):
                self.dropin.write_text("configuration")
                self.run_script("prerm", argument)
                self.assertFalse(self.dropin.exists())
        self.assertIn("disable --now himmelblau-ssh-ca-refresh.timer", self.calls.read_text())


if __name__ == "__main__":
    unittest.main()
