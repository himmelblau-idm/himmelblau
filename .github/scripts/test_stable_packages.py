"""Release contracts tested without Docker, Cloudsmith credentials or network writes."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).with_name("stable_packages.py")
SPEC = importlib.util.spec_from_file_location("stable_packages", MODULE)
sp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sp)


class SourceSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(os.chdir, self.previous)
        sp.git("init", "-q")
        sp.git("config", "user.name", "Packaging test")
        sp.git("config", "user.email", "packaging@example.invalid")
        sp.git("config", "commit.gpgsign", "false")
        sp.git("config", "tag.gpgsign", "false")
        (self.repo / "scripts").mkdir()
        (self.repo / "src/daemon").mkdir(parents=True)
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "3.1.14"\n')
        (self.repo / "src/daemon/Cargo.toml").write_text(
            '[package]\nname="himmelblaud"\n[package.metadata.deb]\nname="himmelblau"\n'
            '[package.metadata.generate-rpm]\nname="himmelblau"\n')
        (self.repo / "Makefile").write_text(
            'DEB_TARGETS := ubuntu24.04\nRPM_TARGETS := rocky8 rawhide\nSLE_TARGETS := sle15sp6\n')
        (self.repo / "scripts/gen_dockerfiles.py").write_text(
            'DISTS = {"ubuntu24.04": {"family": "deb"}, '
            '"rocky8": {"family": "rpm", "arm64": False}, '
            '"rawhide": {"family": "rpm"}, '
            '"sle15sp6": {"family": "zypper", "scc": True}}\n'
            'PACKAGES = [("himmelblaud", "src/daemon", True)]\n'
            'raise RuntimeError("configuration inspection must not execute this")\n')
        sp.git("add", ".")
        sp.git("commit", "-qm", "release")
        sp.git("tag", "3.1.14")
        self.tag_sha = sp.resolve("HEAD")
        (self.repo / "build-fix").write_text("fix")
        sp.git("add", ".")
        sp.git("commit", "-qm", "distro build fix")
        self.fix_sha = sp.resolve("HEAD")
        sp.git("update-ref", "refs/remotes/origin/stable-3.x", self.fix_sha)

    def specs(self, *args):
        return [json.loads(entry["spec"]) for entry in sp.matrix(*args)["include"]]

    def test_defaults_use_tag_and_branch_supported_architectures(self):
        specs = self.specs("3.1.14")
        self.assertEqual(len(specs), 5)
        self.assertEqual({s["source_sha"] for s in specs}, {self.tag_sha})
        self.assertNotIn("rawhide", {s["distro"] for s in specs})
        self.assertFalse(any(s["distro"] == "rocky8" and s["architecture"] == "arm64" for s in specs))
        self.assertEqual(next(s for s in specs if s["distro"] == "sle15sp6")["destination"], "opensuse/15.6")

    def test_single_distro_fix_and_architecture_filter(self):
        specs = self.specs("3.1.14", self.fix_sha, "ubuntu24.04", "arm64")
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]["source_sha"], self.fix_sha)
        self.assertEqual(specs[0]["tag_sha"], self.tag_sha)
        self.assertEqual(specs[0]["runner"], "ubuntu-24.04-arm")
        self.assertEqual(specs[0]["expected"], ["himmelblau"])

    def test_source_branch_name_resolves_remote_tracking_branch(self):
        specs = self.specs("3.1.14", "stable-3.x", "ubuntu24.04")
        self.assertEqual({s["source_sha"] for s in specs}, {self.fix_sha})

    def test_invalid_inputs_and_empty_selection(self):
        for args in [("3.1.14;echo bad",), ("3.1.14-alpha",), ("5.0.0",),
                     ("3.1.14", "", "rawhide"), ("3.1.14", "", "unknown"),
                     ("3.1.14", "", "rocky8", "arm64"),
                     ("3.1.14", "", "all", "x86")]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                sp.matrix(*args)

    def test_source_version_bump_is_rejected(self):
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion="3.1.15"\n')
        sp.git("add", ".")
        sp.git("commit", "-qm", "new release version")
        sp.git("update-ref", "refs/remotes/origin/stable-3.x", sp.resolve("HEAD"))
        with self.assertRaisesRegex(ValueError, "versions"):
            sp.matrix("3.1.14", "HEAD", "ubuntu24.04")

    def test_fix_outside_stable_branch_is_rejected(self):
        sp.git("update-ref", "refs/remotes/origin/stable-3.x", self.tag_sha)
        with self.assertRaisesRegex(ValueError, "stable branch"):
            sp.matrix("3.1.14", self.fix_sha)

    def test_revision_before_tag_is_rejected(self):
        sp.git("tag", "-f", "3.1.14", self.fix_sha)
        with self.assertRaisesRegex(ValueError, "descend"):
            sp.matrix("3.1.14", self.tag_sha)

    def test_unchanged_version_does_not_dispatch_but_exact_retry_does(self):
        with patch.dict(os.environ, {"GITHUB_REF_NAME": "stable-3.x"}), patch.object(sp, "output") as out:
            sp.tag_version()
            self.assertIn(unittest.mock.call("dispatch", "false"), out.call_args_list)
            sp.git("checkout", "-q", self.tag_sha)
            out.reset_mock()
            sp.tag_version()
            self.assertIn(unittest.mock.call("dispatch", "true"), out.call_args_list)

    def test_new_tag_pushes_exact_ref_and_dispatches(self):
        sp.git("tag", "-d", "3.1.14")
        actual_run = sp.subprocess.run

        def fake_push(command, **kwargs):
            if command[:3] == ["git", "push", "origin"]:
                self.assertEqual(command[3], "refs/tags/3.1.14")
                return subprocess.CompletedProcess(command, 0)
            return actual_run(command, **kwargs)

        with patch.dict(os.environ, {"GITHUB_REF_NAME": "stable-3.x"}), \
             patch.object(sp, "output") as out, patch.object(sp.subprocess, "run", side_effect=fake_push):
            sp.tag_version()
        self.assertEqual(sp.resolve("refs/tags/3.1.14"), self.fix_sha)
        self.assertIn(unittest.mock.call("dispatch", "true"), out.call_args_list)

    def test_conflicting_tag_is_not_moved(self):
        sp.git("checkout", "-q", self.tag_sha)
        sp.git("tag", "-f", "3.1.14", self.fix_sha)
        with patch.dict(os.environ, {"GITHUB_REF_NAME": "stable-3.x"}), self.assertRaisesRegex(ValueError, "Conflicting"):
            sp.tag_version()
        self.assertEqual(sp.resolve("refs/tags/3.1.14"), self.fix_sha)

    def test_automatic_events_ignore_manual_overrides(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "repository_dispatch", "RELEASE_TAG": "3.1.14",
                                    "REQUESTED_REVISION": self.fix_sha, "REQUESTED_DISTRO": "unknown",
                                    "REQUESTED_ARCHITECTURE": "unknown"}), patch.object(sp, "output") as out:
            sp.prepare()
        result = json.loads(next(call.args[1] for call in out.call_args_list if call.args[0] == "matrix"))
        self.assertEqual(len(result["include"]), 5)
        self.assertEqual(json.loads(result["include"][0]["spec"])["source_sha"], self.tag_sha)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"tag": "4.0.2", "tag_sha": "a" * 40, "source_sha": "b" * 40,
                     "repository": "himmelblau/himmelblau-4", "distro": "ubuntu24.04",
                     "destination": "ubuntu/noble", "format": "deb", "architecture": "amd64",
                     "expected": ["himmelblau", "pam-himmelblau"]}
        self.records = [{"name": name, "version": "4.0.2-ubuntu24.04", "architecture": "amd64", "filename": name + ".deb"}
                        for name in self.spec["expected"]]

    def remote(self, record, **overrides):
        return {**record, "format": "deb", "distro": {"slug": "ubuntu"},
                "distro_version": {"slug": "noble"}, "architectures": [{"name": "amd64"}],
                "tags": {"user": ["release-4.0.2", "source-" + self.spec["source_sha"]]},
                "is_sync_completed": True, "is_sync_failed": False, **overrides}

    def test_partial_upload_retry_fills_only_missing_identity(self):
        missing, pending = sp.upload_plan(self.records, [self.remote(self.records[0])], self.spec)
        self.assertEqual(missing, [self.records[1]])
        self.assertFalse(pending)

    def test_post_tag_fix_fills_empty_target_but_cannot_replace_original(self):
        self.assertEqual(sp.upload_plan(self.records, [], self.spec), (self.records, False))
        original = self.remote(self.records[1], tags={"user": ["release-4.0.2", "source-" + "a" * 40]})
        with self.assertRaisesRegex(ValueError, "another or unknown source"):
            sp.upload_plan(self.records, [original], self.spec)

    def test_pending_failed_and_duplicate_packages(self):
        pending = self.remote(self.records[0], is_sync_completed=False)
        self.assertTrue(sp.upload_plan(self.records, [pending], self.spec)[1])
        with self.assertRaisesRegex(ValueError, "synchronization"):
            sp.upload_plan(self.records, [self.remote(self.records[0], is_sync_failed=True)], self.spec)
        remote = self.remote(self.records[0])
        with self.assertRaisesRegex(ValueError, "Multiple"):
            sp.upload_plan(self.records, [remote, remote], self.spec)

    def test_other_distro_or_architecture_does_not_suppress_upload(self):
        wrong_distro = self.remote(self.records[0], distro_version={"slug": "jammy"})
        wrong_arch = self.remote(self.records[1], architectures=[{"name": "arm64"}])
        self.assertEqual(sp.upload_plan(self.records, [wrong_distro, wrong_arch], self.spec), (self.records, False))

    def test_noarch_identity_can_be_reused_between_architecture_jobs(self):
        local = {**self.records[0], "architecture": "all"}
        remote = self.remote(local, architectures=[{"name": "all"}])
        self.assertEqual(sp.upload_plan([local], [remote], self.spec), ([], False))

    def test_missing_api_key_fails_before_artifact_validation_or_upload(self):
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": ""}), \
             patch.object(sp, "validate_artifacts") as validate, \
             patch.object(sp, "api_packages") as lookup, patch.object(sp.subprocess, "run") as upload:
            with self.assertRaisesRegex(ValueError, "CLOUDSMITH_API_KEY is missing; the workflow supplies it from CLOUDSMITH_PACKAGE_PUBLISHER"):
                sp.publish(Path("artifacts"), self.spec)
            validate.assert_not_called()
            lookup.assert_not_called()
            upload.assert_not_called()

    def test_preflight_conflict_prevents_every_upload(self):
        remote = self.remote(self.records[1], tags={})
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test-not-a-secret"}), \
             patch.object(sp, "validate_artifacts", return_value=self.records), \
             patch.object(sp, "api_packages", return_value=[remote]), patch.object(sp.subprocess, "run") as upload:
            with self.assertRaises(ValueError):
                sp.publish(Path("artifacts"), self.spec)
            upload.assert_not_called()

    def test_package_lookup_reads_every_page_without_exposing_api_key(self):
        first = [self.remote(self.records[0])] * 100
        last = [self.remote(self.records[1], tags={})]
        pages = [io.BytesIO(json.dumps(first).encode()), io.BytesIO(json.dumps(last).encode())]
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test-not-a-secret"}), \
             patch.object(sp.urllib.request, "urlopen", side_effect=pages) as request:
            rows = sp.api_packages(self.spec["repository"], "deb", self.spec["tag"])
        self.assertEqual(len(rows), 101)
        for call in request.call_args_list:
            self.assertNotIn("test-not-a-secret", call.args[0].full_url)
            query = sp.urllib.parse.parse_qs(sp.urllib.parse.urlsplit(call.args[0].full_url).query)
            self.assertEqual(query["query"], ["format:deb version:4.0.2-*"])
        self.assertEqual(query["page"], ["2"])

    def test_authentication_error_does_not_print_response_or_credentials(self):
        error = sp.urllib.error.HTTPError("https://api.cloudsmith.io/", 401, "test-not-a-secret", {}, None)
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test-not-a-secret"}), \
             patch.object(sp.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                sp.api_packages(self.spec["repository"], "deb", self.spec["tag"])
        self.assertIn("401", str(raised.exception))
        self.assertNotIn("test-not-a-secret", str(raised.exception))

    def test_upload_uses_environment_key_and_explicitly_disables_replacement(self):
        remote = [self.remote(record) for record in self.records]
        with patch.dict(os.environ, {"CLOUDSMITH_API_KEY": "test-not-a-secret"}), \
             patch.object(sp, "validate_artifacts", return_value=self.records), \
             patch.object(sp, "api_packages", side_effect=[[], remote]), \
             patch.object(sp.subprocess, "run") as upload:
            sp.publish(Path("artifacts"), self.spec)
        for call in upload.call_args_list:
            self.assertIn("--no-republish", call.args[0])
            self.assertNotIn("test-not-a-secret", " ".join(call.args[0]))

    def test_artifact_checks_detect_corruption_traversal_and_extra_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            records = []
            for record in self.records:
                filename = record["name"] + ".deb"
                (directory / filename).write_bytes(b"package fixture")
                records.append({**record, "filename": filename, "sha256": sp.digest(directory / filename)})
            manifest = {"spec": self.spec, "packages": records}
            (directory / "manifest.json").write_text(json.dumps(manifest))
            self.assertEqual(sp.validate_artifacts(directory, self.spec), records)
            (directory / "extra").write_text("unexpected")
            with self.assertRaisesRegex(ValueError, "Unexpected files"):
                sp.validate_artifacts(directory, self.spec)
            (directory / "extra").unlink()
            (directory / records[0]["filename"]).write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "integrity"):
                sp.validate_artifacts(directory, self.spec)
            records[0]["filename"] = "../escape.deb"
            (directory / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                sp.validate_artifacts(directory, self.spec)


class ContainerBuildTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"tag": "4.0.2", "tag_sha": "a" * 40, "source_sha": "b" * 40,
                     "repository": "himmelblau/himmelblau-4", "distro": "ubuntu24.04",
                     "destination": "ubuntu/noble", "format": "deb", "architecture": "arm64",
                     "platform": "linux/arm64", "scc": False, "expected": ["himmelblau"]}

    def build_packages(self, spec=None, **options):
        """Exercise package validation with Docker replaced at the process boundary."""
        spec = spec or self.spec
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            artifacts = Path(temporary) / "artifacts"
            commands = []

            def fake_container(command, **kwargs):
                commands.append(command)
                if command[:2] == ["python3", "scripts/gen_dockerfiles.py"]:
                    self.assertNotIn("--arch", command)
                elif command[:3] == ["docker", "run", "--rm"]:
                    directory = source / "target/debian"
                    directory.mkdir()
                    (directory / "himmelblau.deb").write_bytes(b"built package")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(sp, "run", return_value=spec["source_sha"]), \
                 patch.object(sp.subprocess, "run", side_effect=fake_container), \
                 patch.object(sp, "package_metadata", return_value={"name": "himmelblau", "version": "4.0.2-ubuntu24.04", "architecture": spec["architecture"]}):
                sp.build(source, artifacts, spec, **options)
            return commands, sp.validate_artifacts(artifacts, spec)

    def test_native_container_commands_and_validated_artifact(self):
        commands, records = self.build_packages()
        docker = [c for c in commands if c[0] == "docker" and c[1] in {"build", "run"}]
        self.assertEqual(len(docker), 2)
        for command in docker:
            self.assertIn("linux/arm64", command)
            self.assertNotIn("-it", command)
            self.assertNotIn("CLOUDSMITH_API_KEY", " ".join(command))
        self.assertNotIn("--cache-from", docker[0])
        self.assertNotIn("--no-cache", docker[0])
        self.assertEqual(len(records), 1)

    def test_cached_image_is_loaded_for_native_package_build_and_validation(self):
        cache_ref = "ghcr.io/himmelblau-idm/himmelblau-build-cache:v1-ubuntu24.04-arm64"
        commands, records = self.build_packages(container_cache_ref=cache_ref)
        image_build = next(c for c in commands if c[:3] == ["docker", "buildx", "build"])
        package_build = next(c for c in commands if c[:3] == ["docker", "run", "--rm"])
        self.assertIn("--load", image_build)
        self.assertIn("--pull", image_build)
        self.assertEqual(image_build[image_build.index("--platform") + 1], "linux/arm64")
        self.assertEqual(image_build[image_build.index("--cache-from") + 1], f"type=registry,ref={cache_ref}")
        self.assertEqual(image_build[image_build.index("--cache-to") + 1],
                         f"type=registry,ref={cache_ref},mode=max,ignore-error=true")
        self.assertNotIn("--no-cache", image_build)
        self.assertEqual(package_build[-1], image_build[image_build.index("-t") + 1])
        self.assertEqual(len(records), 1)

    def test_cached_amd64_image_uses_native_platform(self):
        spec = {**self.spec, "architecture": "amd64", "platform": "linux/amd64"}
        commands, records = self.build_packages(
            spec=spec, container_cache_ref="ghcr.io/himmelblau-idm/himmelblau-build-cache:v1-ubuntu24.04-amd64")
        image_build = next(c for c in commands if c[:3] == ["docker", "buildx", "build"])
        package_build = next(c for c in commands if c[:3] == ["docker", "run", "--rm"])
        self.assertEqual(image_build[image_build.index("--platform") + 1], "linux/amd64")
        self.assertEqual(package_build[package_build.index("--platform") + 1], "linux/amd64")
        self.assertEqual(records[0]["architecture"], "amd64")

    def test_failed_cached_image_build_stops_packaging_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            artifacts = Path(temporary) / "artifacts"
            commands = []

            def fail_image_build(command, **kwargs):
                commands.append(command)
                if command[:3] == ["docker", "buildx", "build"]:
                    raise subprocess.CalledProcessError(1, command)
                return subprocess.CompletedProcess(command, 0)

            with patch.object(sp, "run", return_value=self.spec["source_sha"]), \
                 patch.object(sp.subprocess, "run", side_effect=fail_image_build):
                with self.assertRaises(subprocess.CalledProcessError):
                    sp.build(source, artifacts, self.spec, container_cache_ref="ghcr.io/test/cache:arm64")
            self.assertFalse(any(c[:2] == ["docker", "run"] for c in commands))
            self.assertEqual(commands[-1], ["docker", "image", "rm", "-f", "himmelblau-stable-ubuntu24.04-arm64"])
            self.assertFalse((artifacts / "manifest.json").exists())

    def test_refresh_rebuilds_cached_installation_layers(self):
        commands, records = self.build_packages(
            container_cache_ref="ghcr.io/himmelblau-idm/himmelblau-build-cache:v1-ubuntu24.04-arm64",
            refresh_build_container=True)
        image_build = next(c for c in commands if c[:3] == ["docker", "buildx", "build"])
        self.assertIn("--no-cache", image_build)
        self.assertIn("--cache-to", image_build)
        self.assertEqual(len(records), 1)

    def test_refresh_also_works_without_registry_cache_setup(self):
        commands, records = self.build_packages(refresh_build_container=True)
        image_build = next(c for c in commands if c[:2] == ["docker", "build"])
        self.assertIn("--no-cache", image_build)
        self.assertNotIn("--cache-to", image_build)
        self.assertEqual(len(records), 1)

    def test_build_cli_passes_cache_and_refresh_options(self):
        with patch("sys.argv", ["stable_packages.py", "build", "--container-cache-ref", "ghcr.io/test/cache:arm64",
                                "--refresh-build-container"]), \
             patch.dict(os.environ, {"TARGET_SPEC": json.dumps(self.spec)}), \
             patch.object(sp, "build") as build:
            sp.main()
        build.assert_called_once_with(Path("source"), Path("artifacts"), self.spec,
                                      container_cache_ref="ghcr.io/test/cache:arm64", refresh_build_container=True)

    def test_suse_secret_is_private_quoted_and_removed_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            spec = {**self.spec, "distro": "sle16", "scc": True}
            email, regcode = "user@example.invalid", "code' with shell; chars"
            secrets = []

            def fail_container(command, **kwargs):
                if command[:2] == ["docker", "build"]:
                    self.assertNotIn("--cache-from", command)
                    self.assertNotIn("--cache-to", command)
                    secret = Path(command[command.index("--secret") + 1].split("src=", 1)[1])
                    secrets.append(secret)
                    self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
                    self.assertIn("regcode=" + sp.shlex.quote(regcode), secret.read_text())
                    self.assertNotIn(regcode, " ".join(command))
                    self.assertNotIn(str(secret), str(source))
                    raise subprocess.CalledProcessError(1, command)
                return subprocess.CompletedProcess(command, 0)

            with patch.dict(os.environ, {"SCC_EMAIL": email, "SCC_REGCODE": regcode}), \
                 patch.object(sp, "run", return_value=spec["source_sha"]), \
                 patch.object(sp.subprocess, "run", side_effect=fail_container):
                with self.assertRaises(subprocess.CalledProcessError):
                    sp.build(source, Path(temporary) / "artifacts", spec,
                             container_cache_ref="ghcr.io/test/cache:sle16")
            self.assertEqual(len(secrets), 1)
            self.assertFalse(secrets[0].exists())

    def test_package_metadata_rejects_wrong_architecture_and_version(self):
        with patch.object(sp, "run", return_value="Package: himmelblau\nVersion: 4.0.2-ubuntu24.04\nArchitecture: amd64"):
            with self.assertRaisesRegex(ValueError, "architecture"):
                sp.package_metadata("image", Path("/source"), Path("/source/target/test.deb"), self.spec)
        with patch.object(sp, "run", return_value="Package: himmelblau\nVersion: 4.0.3-ubuntu24.04\nArchitecture: arm64"):
            with self.assertRaisesRegex(ValueError, "version"):
                sp.package_metadata("image", Path("/source"), Path("/source/target/test.deb"), self.spec)

    def test_rpm_metadata_accepts_native_arm_and_noarch_but_not_epochs(self):
        spec = {**self.spec, "format": "rpm", "rpm": "aarch64"}
        for architecture in ["aarch64", "noarch"]:
            with patch.object(sp, "run", return_value=f"himmelblau\n4.0.2-1\n{architecture}\n0"):
                result = sp.package_metadata("image", Path("/source"), Path("/source/test.rpm"), spec)
            self.assertEqual(result["architecture"], architecture)
        with patch.object(sp, "run", return_value="himmelblau\n4.0.2-1\naarch64\n1"):
            with self.assertRaisesRegex(ValueError, "epoch"):
                sp.package_metadata("image", Path("/source"), Path("/source/test.rpm"), spec)


if __name__ == "__main__":
    unittest.main()
