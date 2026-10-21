#!/usr/bin/env python3
"""Exercise package scripts without touching host configuration or services."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Sandbox:
    def __init__(self, root, active=False, selinux=False, debian=False):
        self.root = root
        bindir = root / 'bin'
        bindir.mkdir(parents=True)
        self.log = root / 'commands'
        self.states = root / 'services'
        self.states.mkdir()
        for command in ('sh', 'grep', 'awk', 'md5sum', 'rm', 'rmdir', 'sed',
                        'install', 'touch', 'mv'):
            (bindir / command).symlink_to(shutil.which(command))
        (bindir / 'systemctl').write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$COMMAND_LOG"
operation=
for arg do
    case "$arg" in --*) ;; *) operation="$arg"; break;; esac
done
case "$operation" in
    is-active)
        for arg do
            case "$arg" in *.service) test -f "$TEST_STATES/$arg" || exit 3;; esac
        done;;
    restart) exit 99;;
    try-restart|start)
        case " $* " in *" --no-block "*) :;; *) exit 98;; esac
        for arg do
            case "$arg" in *.service)
                if [ "$operation" = start ] || [ -f "$TEST_STATES/$arg" ]; then
                    touch "$TEST_STATES/$arg"
                    echo "started $arg" >> "$COMMAND_LOG"
                fi;;
            esac
        done;;
    stop)
        for arg do
            case "$arg" in *.service) rm -f "$TEST_STATES/$arg";; esac
        done;;
esac
''')
        for name, status in [('systemd-tmpfiles', 0), ('systemd-detect-virt', 1),
                             ('selinuxenabled', 0 if selinux else 1),
                             ('make', 0), ('semodule', 0), ('restorecon', 0)]:
            (bindir / name).write_text('#!/bin/sh\nexit %d\n' % status)
        if debian:
            (bindir / 'deb-systemd-helper').write_text('#!/bin/sh\nexit 0\n')
            # Model an invocation held until readiness is reported. Use the
            # interpreter directly so the private PATH remains self-contained.
            (bindir / 'deb-systemd-invoke').write_text(
                '#!/bin/sh\n[ "$1" = try-restart ] || exit 0\nexec "%s" -c "import time; time.sleep(2)"\n' % shutil.which('python3'))
        for path in bindir.iterdir():
            if not path.is_symlink():
                path.chmod(0o755)
        (root / 'run/systemd/system').mkdir(parents=True)
        if selinux:
            for directory in ('usr/share/selinux/packages/himmelblaud', 'usr/share/selinux/devel'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            (root / 'usr/share/selinux/devel/Makefile').touch()
        if active:
            for unit in ('himmelblaud.service', 'himmelblaud-tasks.service'):
                (self.states / unit).touch()
        self.env = dict(os.environ, PATH=str(bindir), COMMAND_LOG=str(self.log),
                        TEST_STATES=str(self.states), DPKG_ROOT='')

    def source(self, source, arg='1', timeout=10):
        # One pass: inserted roots may themselves contain /var/ or /run/.
        source = re.sub(r'/(?:etc|run|usr/lib|usr/share|var)/',
                        lambda match: str(self.root) + match.group(0), source)
        script = self.root / 'maintscript'
        script.write_text(source)
        result = subprocess.run(['sh', str(script), arg], env=self.env,
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise AssertionError(result.stderr)
        return self.log.read_text() if self.log.exists() else ''

    def run(self, relative, arg='1', timeout=10):
        return self.source((ROOT / relative).read_text(), arg, timeout)


class InstallLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Exercise roots containing /var/, as with TMPDIR=/var/tmp.
        self.root = Path(self.tmp.name) / 'var/tmp'

    def test_fresh_install_does_not_start_unconfigured_daemon(self):
        box = Sandbox(self.root)
        box.run('src/daemon/scripts/postinst')
        self.assertFalse(list(box.states.iterdir()))
        self.assertFalse((self.root / 'run/himmelblau-package-restart').exists())

    def test_upgrade_recovers_after_legacy_preun_stop(self):
        box = Sandbox(self.root, active=True)
        box.run('src/daemon/scripts/postinst', '2')
        # Exact stop performed by the previously released RPM %preun. Testing
        # only the updated prerm would miss upgrades from the old packages.
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service himmelblau-hsm-pin-init.service')
        self.assertFalse(list(box.states.iterdir()))
        box.run('src/daemon/scripts/posttrans')
        self.assertEqual(len(list(box.states.iterdir())), 2)
        self.assertFalse((self.root / 'run/himmelblau-package-restart').exists())

    def test_upgrade_waits_for_selinux_posttrans(self):
        box = Sandbox(self.root, active=True, selinux=True)
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        box.run('src/daemon/scripts/posttrans')
        self.assertFalse(list(box.states.iterdir()))
        self.assertTrue((self.root / 'run/himmelblau-package-restart').exists())
        box.run('src/selinux/scripts/postinst')
        self.assertEqual(len(list(box.states.iterdir())), 2)
        self.assertFalse((self.root / 'run/himmelblau-package-restart').exists())

    def test_inactive_upgrade_stays_inactive(self):
        box = Sandbox(self.root)
        box.run('src/daemon/scripts/postinst', '2')
        box.run('src/daemon/scripts/posttrans')
        self.assertFalse(list(box.states.iterdir()))

    def test_new_prerm_does_not_stop_upgrade(self):
        box = Sandbox(self.root, active=True)
        box.run('src/daemon/scripts/prerm', '1')
        self.assertEqual(len(list(box.states.iterdir())), 2)
        box.run('src/daemon/scripts/prerm', '0')
        self.assertFalse(list(box.states.iterdir()))

    def test_debian_restart_releases_package_pipes(self):
        box = Sandbox(self.root, active=True, debian=True)
        # A foreground helper or a background helper inheriting the package's
        # captured pipes would keep communicate() waiting and hit this timeout.
        box.run('src/daemon/scripts/postinst', 'configure', timeout=1)

    def test_policy_install_does_not_start_unconfigured_daemon(self):
        box = Sandbox(self.root, selinux=True)
        box.run('src/selinux/scripts/postinst')
        self.assertFalse(list(box.states.iterdir()))

    def test_ssh_install_does_not_start_inactive_server(self):
        box = Sandbox(self.root)
        box.run('src/sshd-config/scripts/postinst')
        self.assertFalse(list(box.states.iterdir()))

    def test_ssh_upgrade_queues_restart(self):
        box = Sandbox(self.root)
        (box.states / 'ssh.service').touch()
        commands = box.run('src/sshd-config/scripts/postinst')
        self.assertIn('--no-block try-restart ssh', commands)


if __name__ == '__main__':
    unittest.main()
