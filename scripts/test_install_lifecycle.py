#!/usr/bin/env python3
"""Exercise package scripts without touching host configuration or services."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Sandbox:
    def __init__(self, root, active=False, selinux=False, debian=False, policy_updated=True,
                 container=False):
        self.root = root
        bindir = root / 'bin'
        bindir.mkdir(parents=True)
        self.log = root / 'commands'
        self.states = root / 'services'
        self.states.mkdir()
        for command in ('sh', 'grep', 'awk', 'md5sum', 'rm', 'rmdir', 'sed',
                        'install', 'touch', 'mv', 'sleep'):
            (bindir / command).symlink_to(shutil.which(command))
        (bindir / 'systemctl').write_text('''#!/bin/sh
printf '%s\n' "$*" >> "$COMMAND_LOG"
operation=
units=
for arg do
    case "$arg" in
        --*) ;;
        *)
            if [ -z "$operation" ]; then
                operation="$arg"
            else
                case "$arg" in
                    *.service) units="$units $arg";;
                    ssh|sshd) units="$units $arg.service";;
                esac
            fi;;
    esac
done
case "$operation" in
    is-active)
        for arg in $units; do
            test -f "$TEST_STATES/$arg" || exit 3
        done;;
    restart) echo unexpected-unconditional-restart >> "$COMMAND_LOG"; exit 99;;
    try-restart|start)
        if [ "$operation" = try-restart ]; then
            case " $* " in *" --no-block "*) :;; *) exit 98;; esac
        fi
        for arg in $units; do
                if [ "$operation" = start ]; then
                    # --no-block accepts the job before its result is known.
                    # Blocking starts wait, then report the simulated result.
                    case " $* " in *" --no-block "*)
                        if [ "${TEST_START_FAIL:-0}" != 0 ] || [ "${TEST_START_DELAY:-0}" != 0 ]; then
                            exit 0
                        fi;;
                    esac
                    sleep "${TEST_START_DELAY:-0}"
                    [ "${TEST_START_FAIL:-0}" = 0 ] || exit 1
                fi
                if [ "$operation" = start ] || [ -f "$TEST_STATES/$arg" ]; then
                    touch "$TEST_STATES/$arg"
                    echo "started $arg" >> "$COMMAND_LOG"
                fi
        done;;
    stop)
        for arg in $units; do
            rm -f "$TEST_STATES/$arg"
        done;;
esac
''')
        for name, status in [('systemd-tmpfiles', 0), ('systemd-detect-virt', 0 if container else 1),
                             ('selinuxenabled', 0 if selinux else 1),
                             ('make', 0), ('semodule', 0), ('restorecon', 0)]:
            (bindir / name).write_text('#!/bin/sh\nexit %d\n' % status)
        for name in ('make', 'semodule'):
            variable = 'TEST_' + name.upper() + '_STATUS'
            (bindir / name).write_text('#!/bin/sh\nexit "${%s:-0}"\n' % variable)
        (bindir / 'rpm').write_text('''#!/bin/sh
[ "${TEST_RPM_QUERY_FAIL:-0}" = 0 ] || exit 1
case "$*" in
    *himmelblau-selinux) printf '%s' "$TEST_POLICY_TID";;
    *himmelblau) printf '%s' 200;;
    *) exit 1;;
esac
''')
        if debian:
            (bindir / 'deb-systemd-helper').write_text('#!/bin/sh\nexit 0\n')
            # Model an invocation held until readiness is reported. Use the
            # interpreter directly so the private PATH remains self-contained.
            (bindir / 'deb-systemd-invoke').write_text(
                '#!/bin/sh\nprintf "deb-systemd-invoke %%s\\n" "$*" >> "$COMMAND_LOG"\n'
                'case "$1" in restart|try-restart) ;; *) exit 0;; esac\n'
                'exec "%s" -c "import time; time.sleep(2)"\n' % shutil.which('python3'))
        for path in bindir.iterdir():
            if not path.is_symlink():
                path.chmod(0o755)
        (root / 'run/systemd/system').mkdir(parents=True)
        (root / 'proc').mkdir()
        (root / 'proc/cmdline').write_text('')
        if selinux:
            for directory in ('usr/share/selinux/packages/himmelblaud', 'usr/share/selinux/devel'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            (root / 'usr/share/selinux/devel/Makefile').touch()
        if active:
            for unit in ('himmelblaud.service', 'himmelblaud-tasks.service'):
                (self.states / unit).touch()
        self.env = dict(os.environ, PATH=str(bindir), COMMAND_LOG=str(self.log),
                        TEST_STATES=str(self.states), DPKG_ROOT='',
                        TEST_POLICY_TID='200' if policy_updated else '100')

    def source(self, source, arg='1', timeout=10):
        # One pass: inserted roots may themselves contain /var/ or /run/.
        source = re.sub(r'/(?:etc|run|usr/lib|usr/share|var|proc)/|/\.live-installer',
                        lambda match: str(self.root) + match.group(0), source)
        script = self.root / 'maintscript'
        script.write_text(source)
        result = subprocess.run(['sh', str(script), arg], env=self.env,
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise AssertionError(result.stderr)
        return self.log.read_text() if self.log.exists() else ''

    def run(self, relative, arg='1', timeout=10, wait_workers=True):
        source = (ROOT / relative).read_text()
        if wait_workers and relative in ('src/daemon/scripts/posttrans', 'src/selinux/scripts/postinst'):
            # Production detaches recovery to keep the package process free.
            # Tests normally join those workers to observe their final result.
            source = source.rstrip()
            if source.endswith('exit 0'):
                source = source[:-len('exit 0')]
            source = source.replace('trap recover_upgrade_services 0',
                                    "trap 'recover_upgrade_services; wait' 0")
            source += '\nwait\n'
        return self.source(source, arg, timeout)

    def wait_until(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                raise AssertionError('Timed out waiting for background recovery')
            time.sleep(0.01)


class InstallLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Exercise roots containing /var/, as with TMPDIR=/var/tmp.
        self.root = Path(self.tmp.name) / 'var/tmp'

    def test_fresh_install_does_not_start_unconfigured_daemon(self):
        box = Sandbox(self.root)
        commands = box.run('src/daemon/scripts/postinst')
        self.assertNotIn('unexpected-unconditional-restart', commands)
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

    def test_container_upgrade_recovers_after_legacy_preun_stop(self):
        for policy in ('absent', 'unchanged', 'updated'):
            for active in (False, True):
                with self.subTest(policy=policy, previously_active=active):
                    box = Sandbox(self.root / policy / str(active), active=active,
                                  selinux=policy != 'absent',
                                  policy_updated=policy == 'updated', container=True)
                    commands = box.run('src/daemon/scripts/postinst', '2')
                    self.assertNotIn('try-restart', commands)
                    box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                    box.run('src/daemon/scripts/posttrans')
                    if policy == 'updated':
                        self.assertFalse(list(box.states.iterdir()))
                        box.run('src/selinux/scripts/postinst')
                    self.assertEqual(len(list(box.states.iterdir())), 2 if active else 0)
                    self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_container_upgrade_recovers_only_previously_active_services(self):
        box = Sandbox(self.root, container=True)
        (box.states / 'himmelblaud.service').touch()
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        box.run('src/daemon/scripts/posttrans')
        self.assertEqual([p.name for p in box.states.iterdir()], ['himmelblaud.service'])
        self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_container_policy_recovery_handles_success_failure_and_skip(self):
        # Seed markers separately to exercise the SELinux guard independently
        # from whether the daemon's earlier postinst captured running services.
        for case in ('success', 'missing_makefile', 'missing_sources',
                     'compile_failure', 'install_failure', 'policy_type_mismatch',
                     'disabled_config', 'start_failure'):
            with self.subTest(case=case):
                box = Sandbox(self.root / case, selinux=True, container=True)
                markers = box.root / 'run/himmelblau-package-restart'
                markers.mkdir()
                (markers / 'himmelblaud.service').touch()
                if case == 'missing_makefile':
                    (box.root / 'usr/share/selinux/devel/Makefile').unlink()
                elif case == 'missing_sources':
                    shutil.rmtree(box.root / 'usr/share/selinux/packages/himmelblaud')
                elif case == 'compile_failure':
                    box.env['TEST_MAKE_STATUS'] = '1'
                elif case == 'install_failure':
                    box.env['TEST_SEMODULE_STATUS'] = '1'
                elif case in ('policy_type_mismatch', 'disabled_config'):
                    folder = box.root / 'etc/selinux'
                    folder.mkdir(parents=True)
                    (folder / 'config').write_text('SELINUXTYPE=mls\n' if case == 'policy_type_mismatch'
                                                 else 'SELINUX=disabled\n')
                elif case == 'start_failure':
                    box.env['TEST_START_FAIL'] = '1'
                box.run('src/selinux/scripts/postinst')
                if case == 'start_failure':
                    self.assertFalse(list(box.states.iterdir()))
                    self.assertTrue((markers / 'himmelblaud.service').is_file())
                else:
                    self.assertEqual([p.name for p in box.states.iterdir()], ['himmelblaud.service'])
                    self.assertFalse(markers.exists())

    def test_container_fresh_install_does_not_start_daemons(self):
        box = Sandbox(self.root, selinux=True, container=True)
        box.run('src/daemon/scripts/postinst', '1')
        box.run('src/daemon/scripts/posttrans')
        commands = box.run('src/selinux/scripts/postinst')
        self.assertNotIn('try-restart', commands)
        self.assertFalse(list(box.states.iterdir()))
        self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_live_images_do_not_capture_or_recover_services(self):
        for indicator in ('boot=live', 'rd.live.image', 'run/live', '.live-installer'):
            for container in (False, True):
                with self.subTest(indicator=indicator, container=container):
                    box = Sandbox(self.root / indicator / str(container), active=True,
                                  selinux=True, container=container)
                    if indicator == 'run/live':
                        (box.root / indicator).mkdir()
                    elif indicator == '.live-installer':
                        (box.root / indicator).touch()
                    else:
                        (box.root / 'proc/cmdline').write_text(indicator)
                    commands = box.run('src/daemon/scripts/postinst', '2')
                    markers = box.root / 'run/himmelblau-package-restart'
                    self.assertFalse(markers.exists())
                    self.assertNotIn('try-restart', commands)
                    # Even an existing marker must not bypass the live-image guard.
                    markers.mkdir()
                    (markers / 'himmelblaud.service').touch()
                    box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                    commands = box.run('src/selinux/scripts/postinst')
                    self.assertFalse(list(box.states.iterdir()))
                    self.assertTrue((markers / 'himmelblaud.service').is_file())
                    self.assertNotIn('try-restart', commands)

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

    def test_selinux_failure_and_skip_paths_recover_deferred_services(self):
        cases = ('missing_makefile', 'missing_sources', 'compile_failure',
                 'install_failure', 'policy_type_mismatch', 'disabled_config')
        for case in cases:
            for active in (False, True):
                with self.subTest(case=case, previously_active=active):
                    box = Sandbox(self.root / case / str(active), active=active, selinux=True)
                    box.run('src/daemon/scripts/postinst', '2' if active else '1')
                    box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                    box.run('src/daemon/scripts/posttrans')
                    self.assertFalse(list(box.states.iterdir()))
                    if case == 'missing_makefile':
                        (box.root / 'usr/share/selinux/devel/Makefile').unlink()
                    elif case == 'missing_sources':
                        shutil.rmtree(box.root / 'usr/share/selinux/packages/himmelblaud')
                    elif case == 'compile_failure':
                        box.env['TEST_MAKE_STATUS'] = '1'
                    elif case == 'install_failure':
                        box.env['TEST_SEMODULE_STATUS'] = '1'
                    else:
                        folder = box.root / 'etc/selinux'
                        folder.mkdir(parents=True)
                        (folder / 'config').write_text('SELINUXTYPE=mls\n' if case == 'policy_type_mismatch'
                                                     else 'SELINUX=disabled\n')
                    box.run('src/selinux/scripts/postinst')
                    self.assertEqual(len(list(box.states.iterdir())), 2 if active else 0)
                    self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_failed_policy_and_failed_start_retain_recovery_markers(self):
        box = Sandbox(self.root, active=True, selinux=True)
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        box.run('src/daemon/scripts/posttrans')
        box.env.update(TEST_SEMODULE_STATUS='1', TEST_START_FAIL='1')
        box.run('src/selinux/scripts/postinst')
        self.assertFalse(list(box.states.iterdir()))
        self.assertEqual(len(list((box.root / 'run/himmelblau-package-restart').iterdir())), 2)

    def test_inactive_upgrade_stays_inactive(self):
        box = Sandbox(self.root)
        box.run('src/daemon/scripts/postinst', '2')
        box.run('src/daemon/scripts/posttrans')
        self.assertFalse(list(box.states.iterdir()))

    def test_daemon_only_upgrade_recovers_with_existing_selinux_package(self):
        box = Sandbox(self.root, active=True, selinux=True, policy_updated=False)
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        # No SELinux posttrans runs in this transaction.
        box.run('src/daemon/scripts/posttrans')
        self.assertEqual(len(list(box.states.iterdir())), 2)
        self.assertFalse((self.root / 'run/himmelblau-package-restart').exists())

    def test_failed_transaction_query_does_not_defer_recovery(self):
        box = Sandbox(self.root, active=True, selinux=True)
        box.env['TEST_RPM_QUERY_FAIL'] = '1'
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        box.run('src/daemon/scripts/posttrans')
        self.assertEqual(len(list(box.states.iterdir())), 2)

    def test_failed_recovery_preserves_markers_and_can_retry(self):
        for selinux in (False, True):
            with self.subTest(selinux=selinux):
                box = Sandbox(self.root / str(selinux), active=True, selinux=selinux)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                box.env['TEST_START_FAIL'] = '1'
                box.run('src/daemon/scripts/posttrans')
                if selinux:
                    box.run('src/selinux/scripts/postinst')
                markers = box.root / 'run/himmelblau-package-restart'
                self.assertTrue(markers.is_dir(), 'Failed starts must retain recovery markers')
                self.assertEqual(len(list(markers.iterdir())), 2)
                self.assertFalse(list(box.states.iterdir()))
                box.env['TEST_START_FAIL'] = '0'
                box.run('src/selinux/scripts/postinst' if selinux else 'src/daemon/scripts/posttrans')
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertFalse(markers.exists())

    def test_recovery_does_not_hold_package_pipes_while_waiting(self):
        for selinux in (False, True):
            with self.subTest(selinux=selinux):
                box = Sandbox(self.root / str(selinux), active=True, selinux=selinux)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                box.env['TEST_START_DELAY'] = '2'
                box.run('src/daemon/scripts/posttrans', timeout=1, wait_workers=False)
                if selinux:
                    box.run('src/selinux/scripts/postinst', timeout=1, wait_workers=False)
                markers = box.root / 'run/himmelblau-package-restart'
                self.assertEqual(len(list(markers.iterdir())), 2)
                box.wait_until(lambda: not markers.exists())
                self.assertEqual(len(list(box.states.iterdir())), 2)

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
        box.wait_until(lambda: 'deb-systemd-invoke try-restart' in box.log.read_text())
        self.assertIn('deb-systemd-invoke try-restart himmelblaud.service himmelblaud-tasks.service',
                      box.log.read_text())

    def test_policy_install_does_not_start_unconfigured_daemon(self):
        box = Sandbox(self.root, selinux=True)
        commands = box.run('src/selinux/scripts/postinst')
        self.assertNotIn('unexpected-unconditional-restart', commands)
        self.assertFalse(list(box.states.iterdir()))

    def test_ssh_install_does_not_start_inactive_server(self):
        box = Sandbox(self.root)
        commands = box.run('src/sshd-config/scripts/postinst')
        self.assertNotIn('unexpected-unconditional-restart', commands)
        self.assertFalse(list(box.states.iterdir()))

    def test_ssh_upgrade_queues_restart(self):
        for unit in ('ssh', 'sshd'):
            with self.subTest(active_unit=unit):
                box = Sandbox(self.root / unit)
                (box.states / (unit + '.service')).touch()
                commands = box.run('src/sshd-config/scripts/postinst')
                self.assertIn('--no-block try-restart ' + unit + '\n', commands)
                self.assertIn('started ' + unit + '.service', commands)
                self.assertEqual([p.name for p in box.states.iterdir()], [unit + '.service'])
                self.assertNotIn('unexpected-unconditional-restart', commands)

    def test_failed_upgrade_erase_then_fresh_reinstall_stays_inactive(self):
        box = Sandbox(self.root, active=True)
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        box.env['TEST_START_FAIL'] = '1'
        box.run('src/daemon/scripts/posttrans')
        markers = box.root / 'run/himmelblau-package-restart'
        self.assertTrue(markers.exists())
        box.run('src/daemon/scripts/prerm', '0')
        self.assertFalse(markers.exists())
        box.run('src/daemon/scripts/postrm', '0')
        box.env['TEST_START_FAIL'] = '0'
        box.run('src/daemon/scripts/postinst', '1')
        box.run('src/daemon/scripts/posttrans')
        self.assertFalse(list(box.states.iterdir()))

    def test_postrm_clears_markers_if_prerm_was_skipped(self):
        box = Sandbox(self.root)
        markers = box.root / 'run/himmelblau-package-restart'
        markers.mkdir()
        (markers / 'himmelblaud.service').touch()
        box.run('src/daemon/scripts/postrm', '0')
        self.assertFalse(markers.exists())


if __name__ == '__main__':
    unittest.main()
