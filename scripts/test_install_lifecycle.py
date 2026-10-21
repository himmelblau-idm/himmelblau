#!/usr/bin/env python3
"""Exercise package scripts without touching host configuration or services."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallLifecycleTests(unittest.TestCase):
    def run_script(self, relative, active=False, selinux=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / 'bin'
            bindir.mkdir()
            log = root / 'commands'
            # Keep distro helpers out of PATH: finding the real Debian helper
            # would take a different branch and could contact host systemd.
            for command in ('sh', 'grep', 'awk', 'md5sum', 'rm', 'rmdir', 'sed'):
                (bindir / command).symlink_to(shutil.which(command))
            # Model systemctl's important contract: try-restart leaves an inactive
            # service alone, while restart starts it. Never contact host systemd.
            (bindir / 'systemctl').write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$COMMAND_LOG"
case " $* " in
  *" restart "*) echo unexpected-blocking-start >&2; exit 99;;
  *" try-restart "*)
    case " $* " in *" --no-block "*) :;; *) exit 98;; esac
    if [ "$TEST_ACTIVE" = 1 ]; then echo restarted >> "$COMMAND_LOG"; fi;;
esac
''')
            for name, status in [('systemd-tmpfiles', 0), ('systemd-detect-virt', 1), ('selinuxenabled', 0 if selinux else 1), ('make', 0), ('semodule', 0), ('restorecon', 0)]:
                (bindir / name).write_text('#!/bin/sh\nexit %d\n' % status)
            for path in bindir.iterdir():
                if not path.is_symlink():
                    path.chmod(0o755)
            if selinux:
                for directory in ('usr/share/selinux/packages/himmelblaud',
                                  'usr/share/selinux/devel', 'run/systemd/system'):
                    (root / directory).mkdir(parents=True, exist_ok=True)
                (root / 'usr/share/selinux/devel/Makefile').touch()
            source = (ROOT / relative).read_text()
            # Redirect package-owned paths, including legacy-file cleanup, into
            # the disposable filesystem. The RPM branch does not need systemd.
            for prefix in ('/etc/', '/run/', '/usr/lib/', '/usr/share/', '/var/'):
                source = source.replace(prefix, str(root) + prefix)
            script = root / 'postinst'
            script.write_text(source)
            env = dict(os.environ, PATH=str(bindir),
                       COMMAND_LOG=str(log), TEST_ACTIVE=str(int(active)), DPKG_ROOT='')
            result = subprocess.run(['sh', str(script), '1'], env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return log.read_text()

    def test_fresh_install_does_not_start_unconfigured_daemon(self):
        commands = self.run_script('src/daemon/scripts/postinst')
        self.assertIn('--no-block try-restart himmelblaud.service', commands)
        self.assertNotIn('restarted', commands)
        self.assertNotIn(' enable --now ', commands)

    def test_upgrade_queues_restart_of_existing_daemon(self):
        commands = self.run_script('src/daemon/scripts/postinst', active=True)
        self.assertIn('restarted', commands)

    def test_policy_install_does_not_start_unconfigured_daemon(self):
        commands = self.run_script('src/selinux/scripts/postinst', selinux=True)
        self.assertIn('--no-block try-restart himmelblaud.service', commands)
        self.assertNotIn('restarted', commands)

    def test_ssh_install_does_not_start_inactive_server(self):
        commands = self.run_script('src/sshd-config/scripts/postinst')
        self.assertIn('--no-block try-restart ssh', commands)
        self.assertNotIn('restarted', commands)

    def test_ssh_upgrade_does_not_wait_for_ordered_daemon(self):
        commands = self.run_script('src/sshd-config/scripts/postinst', active=True)
        self.assertIn('restarted', commands)


if __name__ == '__main__':
    unittest.main()
