"""Nightly publishing contracts tested without Docker or network writes."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).with_name("nightly_packages.py")
SPEC = importlib.util.spec_from_file_location("nightly_packages", MODULE)
np = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(np)


class SourceSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(os.chdir, self.previous)
        np.packages.git("init", "-q")
        np.packages.git("config", "user.name", "Packaging test")
        np.packages.git("config", "user.email", "packaging@example.invalid")
        np.packages.git("config", "commit.gpgsign", "false")
        (self.repo / "scripts").mkdir()
        (self.repo / "src/daemon").mkdir(parents=True)
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "5.0.0"\n')
        (self.repo / "src/daemon/Cargo.toml").write_text(
            '[package]\nname="himmelblaud"\n[package.metadata.deb]\nname="himmelblau"\n'
            '[package.metadata.generate-rpm]\nname="himmelblau"\n'
        )
        (self.repo / "Makefile").write_text(
            "DEB_TARGETS := ubuntu24.04\n"
            "RPM_TARGETS := rocky8 rawhide\n"
            "SLE_TARGETS := sle16\n"
        )
        (self.repo / "scripts/gen_dockerfiles.py").write_text(
            'DISTS = {"ubuntu24.04": {"family": "deb"}, '
            '"rocky8": {"family": "rpm", "arm64": False}, '
            '"rawhide": {"family": "rpm"}, '
            '"sle16": {"family": "zypper"}}\n'
            'PACKAGES = [("himmelblaud", "src/daemon", True)]\n'
            'raise RuntimeError("configuration inspection must not execute this")\n'
        )
        np.packages.git("add", ".")
        np.packages.git("commit", "-qm", "main source")
        self.source_sha = np.packages.resolve("HEAD")
        np.packages.git("update-ref", "refs/remotes/origin/main", self.source_sha)

    def specs(self, *args):
        return [json.loads(entry["spec"]) for entry in np.matrix(*args)["include"]]

    def test_matrix_uses_main_version_public_repository_and_native_runners(self):
        specs = self.specs(self.source_sha, "20260924", "123")
        self.assertEqual(len(specs), 7)
        self.assertEqual({spec["repository"] for spec in specs}, {"himmelblau/nightly"})
        self.assertEqual({spec["source_sha"] for spec in specs}, {self.source_sha})
        self.assertFalse(any(spec["distro"] == "rocky8" and spec["architecture"] == "arm64"
                             for spec in specs))
        arm = next(spec for spec in specs
                   if spec["distro"] == "ubuntu24.04" and spec["architecture"] == "arm64")
        self.assertEqual(arm["runner"], "ubuntu-24.04-arm")
        self.assertNotIn("scc", arm)

    def test_nightly_versions_sort_below_stable_identities(self):
        deb = self.specs(self.source_sha, "20260924", "123", "ubuntu24.04", "amd64")[0]
        rpm = self.specs(self.source_sha, "20260924", "123", "rawhide", "arm64")[0]
        nightly_id = f"20260924.123.git{self.source_sha[:12]}"
        self.assertEqual(deb["nightly_id"], nightly_id)
        self.assertEqual(deb["deb_revision_append"], f"~{nightly_id}")
        self.assertEqual(deb["expected_packages"][0]["version"],
                         f"5.0.0-ubuntu24.04~{nightly_id}")
        self.assertEqual(rpm["rpm_package_release"], f"0.{nightly_id}")
        self.assertEqual(rpm["expected_packages"][0]["version"], f"5.0.0-0.{nightly_id}")

    def test_upload_tags_identify_source_build_and_distro(self):
        spec = self.specs(self.source_sha, "20260924", "123", "sle16", "amd64")[0]
        self.assertEqual(
            set(spec["upload_tags"].split(",")),
            {
                "nightly",
                f"source-{self.source_sha}",
                f"nightly-{spec['nightly_id']}",
                "distro-sle16",
            },
        )

    def test_filters_and_invalid_inputs(self):
        self.assertEqual(len(self.specs(self.source_sha, "20260924", "7", "rawhide", "arm64")), 1)
        for args in [
            ("bad", "20260924", "7"),
            (self.source_sha, "2026-09-24", "7"),
            (self.source_sha, "20260924", "0"),
            (self.source_sha, "20260924", "7", "unknown"),
            (self.source_sha, "20260924", "7", "rocky8", "arm64"),
        ]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.specs(*args)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.old_sha = "b" * 40
        self.spec = {
            "channel": "nightly",
            "tag": "5.0.0",
            "source_sha": self.sha,
            "nightly_id": "20260924.123.git" + self.sha[:12],
            "repository": "himmelblau/nightly",
            "distro": "ubuntu24.04",
            "destination": "ubuntu/noble",
            "format": "deb",
            "architecture": "amd64",
            "supported_architectures": ["amd64", "arm64"],
            "expected": ["himmelblau", "pam-himmelblau"],
            "upload_tags": ",".join([
                "nightly",
                f"source-{self.sha}",
                "nightly-20260924.123.git" + self.sha[:12],
                "distro-ubuntu24.04",
            ]),
        }

    def remote(self, name, nightly_id=None, source_sha=None, architecture="amd64", **overrides):
        nightly_id = nightly_id or self.spec["nightly_id"]
        source_sha = source_sha or self.sha
        return {
            "format": "deb",
            "name": name,
            "version": f"5.0.0-ubuntu24.04~{nightly_id}",
            "epoch": 0,
            "distro": {"slug": "ubuntu"},
            "distro_version": {"slug": "noble"},
            "architectures": [{"name": architecture}],
            "tags": {"user": ["nightly", f"source-{source_sha}", f"nightly-{nightly_id}"]},
            "slug_perm": f"{name}-{nightly_id}-{architecture}",
            "is_deleteable": True,
            "is_sync_completed": True,
            "is_sync_failed": False,
            **overrides,
        }

    def build(self, nightly_id=None, source_sha=None, architecture="amd64"):
        return [self.remote(name, nightly_id, source_sha, architecture) for name in self.spec["expected"]]

    def test_complete_current_source_skips_and_partial_source_rebuilds(self):
        complete = self.build()
        self.assertEqual(np.complete_current_builds(complete, self.spec), [self.spec["nightly_id"]])
        self.assertEqual(np.complete_current_builds(complete[:1], self.spec), [])

    def test_different_source_or_unsynchronized_package_is_not_complete(self):
        self.assertEqual(np.complete_current_builds(self.build(source_sha=self.old_sha), self.spec), [])
        pending = self.build()
        pending[0]["is_sync_completed"] = False
        self.assertEqual(np.complete_current_builds(pending, self.spec), [])
        failed = self.build()
        failed[0]["is_sync_failed"] = True
        self.assertEqual(np.complete_current_builds(failed, self.spec), [])

    def test_duplicate_identity_fails_closed(self):
        remote = self.build()
        remote.append(dict(remote[0], slug_perm="duplicate"))
        with self.assertRaisesRegex(ValueError, "Multiple nightly"):
            np.complete_current_builds(remote, self.spec)

    def test_cleanup_deletes_previous_build_after_complete_replacement(self):
        old_id = "20260923.122.git" + self.old_sha[:12]
        remote = self.build(old_id, self.old_sha) + self.build()
        retained, deletions = np.cleanup_plan(remote, self.spec)
        self.assertEqual(retained, self.spec["nightly_id"])
        self.assertEqual({package["slug_perm"] for package in deletions},
                         {package["slug_perm"] for package in self.build(old_id, self.old_sha)})

    def test_cleanup_keeps_previous_build_until_replacement_is_complete(self):
        old_id = "20260923.122.git" + self.old_sha[:12]
        with self.assertRaisesRegex(RuntimeError, "complete synchronized"):
            np.cleanup_plan(self.build(old_id, self.old_sha) + self.build()[:1], self.spec)

    def test_stale_retry_cannot_replace_or_delete_a_newer_nightly(self):
        newer_id = "20260925.124.git" + self.old_sha[:12]
        remote = self.build() + self.build(newer_id, self.old_sha)
        with self.assertRaisesRegex(RuntimeError, "refusing stale run"):
            np.cleanup_plan(remote, self.spec)
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test"}), \
             patch.object(np, "inventory", return_value=remote), \
             patch.object(np.packages, "output") as output:
            with self.assertRaisesRegex(RuntimeError, "refusing stale run"):
                np.preflight(self.spec)
        output.assert_not_called()

    def test_cleanup_does_not_touch_other_architecture_or_unmanaged_packages(self):
        old_id = "20260923.122.git" + self.old_sha[:12]
        remote = self.build() + self.build(old_id, self.old_sha, "arm64")
        remote.append(self.remote("foreign", old_id, self.old_sha, tags={"user": []}))
        _, deletions = np.cleanup_plan(remote, self.spec)
        self.assertEqual(deletions, [])

    def test_preflight_outputs_skip_for_complete_source(self):
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test"}), \
             patch.object(np, "inventory", return_value=self.build()), \
             patch.object(np.packages, "output") as output:
            np.preflight(self.spec)
        output.assert_called_once_with("build_required", "false")

    def test_preflight_outputs_build_for_partial_source(self):
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test"}), \
             patch.object(np, "inventory", return_value=self.build()[:1]), \
             patch.object(np.packages, "output") as output:
            np.preflight(self.spec)
        output.assert_called_once_with("build_required", "true")

    def test_publish_uses_nightly_source_and_build_tags(self):
        records = [{
            "name": "himmelblau",
            "version": np.expected_version(self.spec, self.spec["nightly_id"]),
            "architecture": "amd64",
            "filename": "himmelblau.deb",
        }]
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test"}), \
             patch.object(np.packages, "validate_artifacts", return_value=records), \
             patch.object(np.packages, "synchronized_missing", return_value=records), \
             patch.object(np.packages, "api_packages", return_value=[]), \
             patch.object(np.packages, "upload_plan", return_value=([], False)), \
             patch.object(np.packages.subprocess, "run") as execute:
            np.packages.publish(Path("artifacts"), self.spec)
        command = execute.call_args.args[0]
        self.assertEqual(command[command.index("--tags") + 1], self.spec["upload_tags"])
        self.assertIn("himmelblau/nightly/ubuntu/noble", command)

    def test_prepare_disables_matrix_when_source_is_complete_and_reconciled(self):
        result = {"include": [{"spec": json.dumps(self.spec)}]}
        with patch.dict(os.environ, {
            "NIGHTLY_DATE": "20260924", "GITHUB_RUN_NUMBER": "123",
            "CLOUDSMITH_API_KEY": "test",
        }), patch.object(np.packages, "resolve", side_effect=[self.sha, self.sha]), \
             patch.object(np, "matrix", return_value=result), \
             patch.object(np, "inventory", return_value=self.build()), \
             patch.object(np.packages, "output") as output:
            np.prepare()
        self.assertIn(unittest.mock.call("enabled", "false"), output.call_args_list)

    def test_prepare_enables_matrix_for_cleanup_only(self):
        old_id = "20260923.122.git" + self.old_sha[:12]
        result = {"include": [{"spec": json.dumps(self.spec)}]}
        with patch.dict(os.environ, {
            "NIGHTLY_DATE": "20260924", "GITHUB_RUN_NUMBER": "123",
            "CLOUDSMITH_API_KEY": "test",
        }), patch.object(np.packages, "resolve", side_effect=[self.sha, self.sha]), \
             patch.object(np, "matrix", return_value=result), \
             patch.object(np, "inventory", return_value=self.build(old_id, self.old_sha) + self.build()), \
             patch.object(np.packages, "output") as output:
            np.prepare()
        self.assertIn(unittest.mock.call("enabled", "true"), output.call_args_list)


class ContainerBuildTests(unittest.TestCase):
    def test_nightly_version_overrides_are_passed_only_to_package_container(self):
        sha = "a" * 40
        nightly_id = "20260924.123.git" + sha[:12]
        spec = {
            "channel": "nightly",
            "tag": "5.0.0",
            "source_sha": sha,
            "repository": "himmelblau/nightly",
            "distro": "ubuntu24.04",
            "format": "deb",
            "architecture": "amd64",
            "platform": "linux/amd64",
            "expected": ["himmelblau"],
            "expected_packages": [{
                "name": "himmelblau",
                "version": f"5.0.0-ubuntu24.04~{nightly_id}",
                "architectures": ["amd64", "all"],
            }],
            "deb_revision_append": f"~{nightly_id}",
            "rpm_package_release": f"0.{nightly_id}",
        }
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            commands = []

            def fake_run(command, **kwargs):
                commands.append(command)
                if command[:3] == ["docker", "run", "--rm"]:
                    directory = source / "target/debian"
                    directory.mkdir()
                    (directory / "himmelblau.deb").write_bytes(b"package")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(np.packages, "run", return_value=sha), \
                 patch.object(np.packages.subprocess, "run", side_effect=fake_run), \
                 patch.object(np.packages, "package_metadata", return_value={
                     "name": "himmelblau",
                     "version": f"5.0.0-ubuntu24.04~{nightly_id}",
                     "architecture": "amd64",
                 }):
                np.packages.build(source, Path(temporary) / "artifacts", spec)

        image_build = next(command for command in commands if command[:2] == ["docker", "build"])
        package_build = next(command for command in commands if command[:3] == ["docker", "run", "--rm"])
        self.assertNotIn("DEB_REVISION_APPEND", " ".join(image_build))
        self.assertIn(f"DEB_REVISION_APPEND=~{nightly_id}", package_build)
        self.assertNotIn("RPM_PACKAGE_RELEASE", " ".join(package_build))


class WorkflowContractTests(unittest.TestCase):
    def test_nightly_workflows_are_scheduled_public_and_registration_free(self):
        workflows = MODULE.parents[1] / "workflows"
        caller = (workflows / "nightly-packages.yml").read_text()
        target = (workflows / "nightly-package-target.yml").read_text()
        self.assertIn('cron: "0 0 * * *"', caller)
        self.assertIn("github.ref == 'refs/heads/main'", caller)
        self.assertIn("himmelblau/nightly", MODULE.read_text())
        self.assertNotIn("SCC_", caller + target)
        self.assertNotIn("entitlement", caller.lower() + target.lower())
        self.assertIn("retention-days: 3", target)


if __name__ == "__main__":
    unittest.main()
