"""Cheap smoke-tooling checks; no containers, root, network, or credentials."""

import copy
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import package_smoke as smoke
import package_smoke_guest as guest


class SmokeTests(unittest.TestCase):
    def test_stable_pr_only_and_exact_two_targets(self):
        import re
        workflow = (smoke.ROOT / '.github/workflows/package-smoke.yml').read_text()
        triggers = workflow.split('permissions:', 1)[0]
        self.assertEqual(re.findall(r'^  (\w+):$', triggers, re.M), ['pull_request'])
        self.assertEqual(re.findall(r'branches: \[(.+)\]', triggers), ['stable-2.x, stable-3.x, stable-4.x'])
        self.assertIn('target: [ubuntu26.04, fedora44]', workflow)
        self.assertIn('contents: read', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertEqual(set(smoke.TARGETS), {'ubuntu26.04', 'fedora44'})

    def test_current_generator_supports_both_images(self):
        generator = smoke.load_generator(smoke.ROOT / 'scripts/gen_dockerfiles.py')
        before = copy.deepcopy(generator.DISTS)
        for target, (_, image, _) in smoke.TARGETS.items():
            rendered = smoke.render_builder(generator, target)
            self.assertIn('FROM ' + image, rendered)
            self.assertNotIn('SUSEConnect', rendered)
            self.assertIn('cargo', rendered)
        self.assertEqual(generator.DISTS, before)

    def test_older_generator_uses_family_fallback_without_editing_it(self):
        for target, (fallback, image, _) in smoke.TARGETS.items():
            generator = SimpleNamespace(DISTS={fallback: {'image': 'old', 'tpm': True}})
            before = copy.deepcopy(generator.DISTS)
            generator.render = lambda name, config: (name, config)
            name, config = smoke.render_builder(generator, target)
            self.assertEqual(name, target)
            self.assertEqual(config, {'image': image, 'tpm': True})
            self.assertEqual(generator.DISTS, before)

    def test_newer_generator_disables_local_library_patch(self):
        generator = SimpleNamespace(DISTS={'fedora44': {'image': 'old', 'selinux': True}})
        generator.render = lambda name, config, patch_libhimmelblau, arch='amd64': (name, config, patch_libhimmelblau, arch)
        name, config, local_patch, arch = smoke.render_builder(generator, 'fedora44')
        self.assertFalse(local_patch)
        self.assertEqual(arch, 'amd64')
        self.assertTrue(config['selinux'])

    def test_secret_dependent_recipe_is_rejected(self):
        generator = SimpleNamespace(DISTS={'fedora44': {'scc': True}}, render=lambda *args: '')
        with self.assertRaisesRegex(ValueError, 'registration'):
            smoke.render_builder(generator, 'fedora44')

    def test_runtime_is_minimal_and_uses_systemd(self):
        for target, (_, image, _) in smoke.TARGETS.items():
            text = smoke.runtime_containerfile(target)
            self.assertIn('FROM ' + image, text)
            self.assertIn('/usr/lib/systemd/systemd', text)
            self.assertNotIn('cargo', text)
            self.assertNotIn('DynamicUser=', text)

    def test_failed_install_collects_diagnostics_and_cleans_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = root / 'packages'
            artifacts.mkdir()
            for name in smoke.PACKAGES:
                (artifacts / (name + '.deb')).write_bytes(b'candidate')
            calls = []
            def run(*args, **kwargs):
                calls.append(args)
                if 'apt-get' in args:
                    raise subprocess.CalledProcessError(1, args)
            with patch.object(smoke, 'run', side_effect=run), patch.object(smoke.subprocess, 'run') as diagnostics:
                with self.assertRaises(subprocess.CalledProcessError):
                    smoke.smoke('ubuntu26.04', artifacts, root / 'logs')
            self.assertEqual(calls[-1][:3], ('podman', 'rm', '--force'))
            self.assertEqual(diagnostics.call_count, 4)
            self.assertFalse((root / 'logs/passed').exists())

    def test_missing_candidate_fails_before_starting_container(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(smoke, 'run') as run:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'two candidate'):
                smoke.smoke('fedora44', root / 'absent', root / 'logs')
            run.assert_not_called()

    def test_status_requires_successful_response(self):
        for code, output, expected in [(0, '', False), (0, 'not working!\n', False), (1, 'working!\n', False), (0, 'Banner\nworking!\n', True)]:
            self.assertEqual(guest.working(subprocess.CompletedProcess([], code, output)), expected)

    def test_wait_is_bounded(self):
        with patch.object(guest.time, 'monotonic', side_effect=[0, 1, 3]), patch.object(guest.time, 'sleep'):
            with self.assertRaises(RuntimeError):
                guest.wait_for(lambda: False, seconds=2)

    def test_health_rejects_restarts(self):
        with patch.object(guest, 'ready', return_value=True), patch.object(guest, 'properties', return_value={'MainPID': '123', 'NRestarts': '1', 'Result': 'success'}):
            with self.assertRaisesRegex(RuntimeError, 'Unhealthy'):
                guest.healthy()

    def test_health_rejects_changed_pid(self):
        healthy = {'MainPID': '123', 'NRestarts': '0', 'Result': 'success'}
        with patch.object(guest, 'ready', return_value=True), patch.object(guest.time, 'sleep'), patch.object(guest, 'properties', side_effect=[healthy, healthy, dict(healthy, MainPID='456')]):
            with self.assertRaisesRegex(RuntimeError, 'restarted'):
                guest.healthy()


if __name__ == '__main__':
    unittest.main()
