#!/usr/bin/env python3
"""Check packaging policy and scripts without touching host configuration or services."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SocketPolicyTests(unittest.TestCase):
    def test_pid1_can_create_and_drain_activated_listeners(self):
        # Static regression only, not an enforcing SELinux integration test.
        # systemd flush_ports()/flush_accept() accepts and closes queued clients
        # while a socket stop is pending, including sockets with Accept=no.
        policy = (ROOT / 'src/selinux/src/himmelblaud.te').read_text()
        policy = re.sub(r'#.*', '', policy)
        grants = re.findall(
            r'allow\s+init_t\s+himmelblaud_t:unix_stream_socket\s+'
            r'\{([^}]+)\}\s*;', policy,
        )
        permissions = set(' '.join(grants).split())
        self.assertTrue(
            {'create', 'bind', 'listen', 'setopt', 'getopt', 'accept'} <= permissions,
            'PID 1 must create listeners and drain queued connections at teardown',
        )


class Sandbox:
    def __init__(self, root, active=False, selinux=False, debian=False, container=False):
        self.root = root
        bindir = root / 'bin'
        bindir.mkdir(parents=True)
        self.log = root / 'commands'
        self.states = root / 'services'
        self.states.mkdir()
        self.limits = root / 'start-limits'
        self.limits.mkdir()
        self.masks = root / 'masked-services'
        self.masks.mkdir()
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
    reset-failed)
        for arg in $units; do
            rm -f "$TEST_LIMITS/$arg"
        done;;
    restart) echo unexpected-unconditional-restart >> "$COMMAND_LOG"; exit 99;;
    try-restart|start)
        for arg in $units; do
            if [ "$operation" = try-restart ] && [ ! -f "$TEST_STATES/$arg" ]; then
                continue
            fi
            # Queuing a job does not establish its completion or success.
            case " $* " in *" --no-block "*)
                if [ "${TEST_START_FAIL:-0}" != 0 ] || [ "${TEST_START_DELAY:-0}" != 0 ]; then
                    exit 0
                fi;;
            esac
            if [ -f "$TEST_MASKS/$arg" ] || [ -f "$TEST_LIMITS/$arg" ]; then
                echo "masked or start-limited $arg" >> "$COMMAND_LOG"
                exit 1
            fi
            sleep "${TEST_START_DELAY:-0}"
            if [ "${TEST_START_FAIL:-0}" != 0 ] || [ "${TEST_FAIL_UNIT:-}" = "$arg" ]; then
                echo "failed $arg" >> "$COMMAND_LOG"
                exit 1
            fi
            if [ "${TEST_REQUIRE_POLICY:-0}" != 0 ] && [ ! -f "$TEST_POLICY_READY" ]; then
                echo "policy not ready $arg" >> "$COMMAND_LOG"
                exit 1
            fi
            if [ "${TEST_REQUIRE_CONFIG:-0}" != 0 ] && [ ! -f "$TEST_CONFIG" ]; then
                echo "config not ready $arg" >> "$COMMAND_LOG"
                exit 1
            fi
            touch "$TEST_STATES/$arg"
            echo "started $arg" >> "$COMMAND_LOG"
        done
        echo "completed $operation" >> "$COMMAND_LOG";;
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
        (bindir / 'make').write_text('#!/bin/sh\nexit "${TEST_MAKE_STATUS:-0}"\n')
        (bindir / 'semodule').write_text('''#!/bin/sh
[ "${TEST_SEMODULE_STATUS:-0}" = 0 ] || exit 1
case " $* " in
    *" -l "*) [ ! -f "$TEST_POLICY_READY" ] || echo himmelblaud;;
    *" -i "*) touch "$TEST_POLICY_READY";;
esac
''')
        if debian:
            (bindir / 'deb-systemd-helper').write_text('#!/bin/sh\nexit 0\n')
            # Model a policy-aware helper that must finish before dpkg proceeds.
            (bindir / 'deb-systemd-invoke').write_text('''#!/bin/sh
printf 'deb-systemd-invoke %s\\n' "$*" >> "$COMMAND_LOG"
case "$1" in restart|try-restart) ;; *) exit 0;; esac
sleep "${TEST_DEB_DELAY:-0.1}"
if [ "${TEST_POLICY_DENY:-0}" = 0 ]; then
    systemctl "$@"
fi
echo completed-deb-systemd-invoke >> "$COMMAND_LOG"
''')
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
        self.policy_ready = root / 'policy-ready'
        if selinux:
            self.policy_ready.touch()
        self.config = root / 'etc/himmelblau/himmelblau.conf'
        self.config.parent.mkdir(parents=True)
        if active:
            self.config.write_text('[global]\ndomain = example.test\n')
            for unit in ('himmelblaud.service', 'himmelblaud-tasks.service'):
                (self.states / unit).touch()
        self.env = dict(os.environ, PATH=str(bindir), COMMAND_LOG=str(self.log),
                        TEST_STATES=str(self.states), DPKG_ROOT='',
                        TEST_POLICY_READY=str(self.policy_ready), TEST_CONFIG=str(self.config),
                        TEST_LIMITS=str(self.limits), TEST_MASKS=str(self.masks))

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

    def run(self, relative, arg='1', timeout=10):
        # Execute the shipped script unchanged. In particular, do not insert
        # waits that would hide detached package-script workers.
        return self.source((ROOT / relative).read_text(), arg, timeout)


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
                                  container=True)
                    commands = box.run('src/daemon/scripts/postinst', '2')
                    self.assertNotIn('try-restart', commands)
                    box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                    box.run('src/daemon/scripts/posttrans')
                    if policy == 'updated':
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

    def test_upgrade_retries_after_selinux_policy_install(self):
        for container in (False, True):
            with self.subTest(container=container):
                box = Sandbox(self.root / str(container), active=True, selinux=True,
                              container=container)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                box.policy_ready.unlink()
                box.env['TEST_REQUIRE_POLICY'] = '1'
                commands = box.run('src/daemon/scripts/posttrans')
                self.assertIn('policy not ready himmelblaud.service', commands)
                self.assertFalse(list(box.states.iterdir()))
                self.assertEqual(len(list((box.root / 'run/himmelblau-package-restart').iterdir())), 2)
                box.run('src/selinux/scripts/postinst')
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_policy_first_upgrade_retries_after_config_restore(self):
        for container in (False, True):
            with self.subTest(container=container):
                box = Sandbox(self.root / str(container), active=True, selinux=True,
                              container=container)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                # Old RPM removal moves the owned config after new %post.
                saved_config = box.config.with_suffix('.conf.rpmsave')
                original = box.config.read_text()
                box.config.rename(saved_config)
                box.env['TEST_REQUIRE_CONFIG'] = '1'
                commands = box.run('src/selinux/scripts/postinst')
                self.assertNotIn('start himmelblaud.service', commands.splitlines())
                self.assertNotIn('start himmelblaud-tasks.service', commands.splitlines())
                self.assertFalse(list(box.states.iterdir()))
                self.assertEqual(len(list((box.root / 'run/himmelblau-package-restart').iterdir())), 2)
                box.run('src/daemon/scripts/posttrans')
                self.assertEqual(box.config.read_text(), original)
                self.assertFalse(saved_config.exists())
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_selinux_failure_and_skip_paths_recover_services(self):
        cases = ('missing_makefile', 'missing_sources', 'compile_failure',
                 'install_failure', 'policy_type_mismatch', 'disabled_config')
        for case in cases:
            for active in (False, True):
                with self.subTest(case=case, previously_active=active):
                    box = Sandbox(self.root / case / str(active), active=active, selinux=True)
                    box.run('src/daemon/scripts/postinst', '2' if active else '1')
                    box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
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
        box.env.update(TEST_SEMODULE_STATUS='1', TEST_START_FAIL='1')
        box.run('src/daemon/scripts/posttrans')
        box.run('src/selinux/scripts/postinst')
        self.assertFalse(list(box.states.iterdir()))
        self.assertEqual(len(list((box.root / 'run/himmelblau-package-restart').iterdir())), 2)

    def test_inactive_upgrade_stays_inactive(self):
        box = Sandbox(self.root)
        box.run('src/daemon/scripts/postinst', '2')
        box.run('src/daemon/scripts/posttrans')
        self.assertFalse(list(box.states.iterdir()))

    def test_daemon_only_upgrade_recovers_with_existing_selinux_package(self):
        box = Sandbox(self.root, active=True, selinux=True)
        box.run('src/daemon/scripts/postinst', '2')
        box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
        # No SELinux posttrans runs in this transaction.
        box.run('src/daemon/scripts/posttrans')
        self.assertEqual(len(list(box.states.iterdir())), 2)
        self.assertFalse((self.root / 'run/himmelblau-package-restart').exists())

    def test_recovery_does_not_need_transaction_queries(self):
        for rpm_available in (False, True):
            with self.subTest(rpm_available=rpm_available):
                box = Sandbox(self.root / str(rpm_available), active=True, selinux=True)
                if rpm_available:
                    # Equal INSTALLTIDs must not imply a later policy handler.
                    rpm = box.root / 'bin/rpm'
                    rpm.write_text('#!/bin/sh\necho rpm-query >> "$COMMAND_LOG"\nprintf 200\n')
                    rpm.chmod(0o755)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                commands = box.run('src/daemon/scripts/posttrans')
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertNotIn('rpm-query', commands)

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

    def test_recovery_completes_before_package_script_returns(self):
        for handler in ('src/daemon/scripts/posttrans', 'src/selinux/scripts/postinst'):
            with self.subTest(handler=handler):
                box = Sandbox(self.root / handler.replace('/', '_'), active=True, selinux=True)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                box.env['TEST_START_DELAY'] = '0.1'
                box.run(handler)
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_partial_recovery_retains_only_failed_marker_and_retries(self):
        for handler in ('src/daemon/scripts/posttrans', 'src/selinux/scripts/postinst'):
            with self.subTest(handler=handler):
                box = Sandbox(self.root / handler.replace('/', '_'), active=True, selinux=True)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                box.env['TEST_FAIL_UNIT'] = 'himmelblaud-tasks.service'
                box.run(handler)
                markers = box.root / 'run/himmelblau-package-restart'
                self.assertEqual([p.name for p in markers.iterdir()], ['himmelblaud-tasks.service'])
                self.assertEqual([p.name for p in box.states.iterdir()], ['himmelblaud.service'])
                box.env.pop('TEST_FAIL_UNIT')
                box.run(handler)
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertFalse(markers.exists())

    def test_recovery_retries_start_limited_marked_units_only(self):
        for handler in ('src/daemon/scripts/posttrans', 'src/selinux/scripts/postinst'):
            with self.subTest(handler=handler):
                box = Sandbox(self.root / handler.replace('/', '_'), active=True, selinux=True)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                box.env['TEST_START_FAIL'] = '1'
                box.run('src/daemon/scripts/posttrans')
                self.assertFalse(list(box.states.iterdir()))
                # Model Restart=on-failure reaching the limit while policy is
                # compiled or another transaction-end handler is pending.
                for unit in ('himmelblaud.service', 'himmelblaud-tasks.service', 'unrelated.service'):
                    (box.limits / unit).touch()
                box.env['TEST_START_FAIL'] = '0'
                commands = box.run(handler)
                self.assertEqual(len(list(box.states.iterdir())), 2)
                self.assertEqual([p.name for p in box.limits.iterdir()], ['unrelated.service'])
                self.assertNotIn('reset-failed unrelated.service', commands)
                self.assertNotIn('reset-failed', commands.splitlines())
                self.assertFalse((box.root / 'run/himmelblau-package-restart').exists())

    def test_recovery_does_not_unmask_services(self):
        for handler in ('src/daemon/scripts/posttrans', 'src/selinux/scripts/postinst'):
            with self.subTest(handler=handler):
                box = Sandbox(self.root / handler.replace('/', '_'), active=True, selinux=True)
                box.run('src/daemon/scripts/postinst', '2')
                box.source('systemctl stop himmelblaud.service himmelblaud-tasks.service')
                for unit in ('himmelblaud.service', 'himmelblaud-tasks.service'):
                    (box.masks / unit).touch()
                    (box.limits / unit).touch()
                commands = box.run(handler)
                self.assertFalse(list(box.states.iterdir()))
                self.assertEqual(len(list(box.masks.iterdir())), 2)
                self.assertEqual(len(list((box.root / 'run/himmelblau-package-restart').iterdir())), 2)
                self.assertNotIn('unmask', commands)

    def test_new_prerm_does_not_stop_upgrade(self):
        box = Sandbox(self.root, active=True)
        box.run('src/daemon/scripts/prerm', '1')
        self.assertEqual(len(list(box.states.iterdir())), 2)
        box.run('src/daemon/scripts/prerm', '0')
        self.assertFalse(list(box.states.iterdir()))

    def test_debian_restart_completes_before_package_script_returns(self):
        box = Sandbox(self.root, active=True, debian=True)
        commands = box.run('src/daemon/scripts/postinst', 'configure')
        self.assertIn('deb-systemd-invoke try-restart himmelblaud.service himmelblaud-tasks.service',
                      commands)
        self.assertIn('completed-deb-systemd-invoke', commands)
        self.assertIn('completed try-restart', commands)

    def test_debian_restart_respects_policy_helper(self):
        box = Sandbox(self.root, active=True, debian=True)
        box.env['TEST_POLICY_DENY'] = '1'
        commands = box.run('src/daemon/scripts/postinst', 'configure')
        self.assertIn('completed-deb-systemd-invoke', commands)
        self.assertNotIn('started ', commands)

    def test_daemon_and_policy_restarts_complete_before_return(self):
        for script in ('src/daemon/scripts/postinst', 'src/selinux/scripts/postinst'):
            with self.subTest(script=script):
                box = Sandbox(self.root / script.replace('/', '_'), active=True,
                              selinux=script.startswith('src/selinux/'))
                box.env['TEST_START_DELAY'] = '0.1'
                commands = box.run(script, '2')
                self.assertIn('completed try-restart', commands)
                self.assertNotIn('--no-block', commands)

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
