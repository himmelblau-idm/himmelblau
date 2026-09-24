#!/usr/bin/env python3
"""Unit tests for stable_maintenance.py (standard library only)."""

from __future__ import annotations

import datetime as dt
import io
import importlib.util
import json
import os
import shlex
import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("stable_maintenance.py")
DOCKERFILE = SCRIPT.parent.parent / "stable-maintenance.Dockerfile"
WORKFLOW = SCRIPT.parent.parent / "workflows" / "stable-maintenance.yml"
SPEC = importlib.util.spec_from_file_location("stable_maintenance", SCRIPT)
assert SPEC and SPEC.loader
sm = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = sm
SPEC.loader.exec_module(sm)


UTC = dt.timezone.utc
NOW = dt.datetime(2026, 9, 24, 12, tzinfo=UTC)


class BranchAndCliTests(unittest.TestCase):
    def test_exact_stable_branches_only(self):
        for branch in sm.STABLE_BRANCHES:
            self.assertEqual(sm.require_branch(branch), branch)
        for unsafe in (None, "main", "stable-4", "stable-4.x;echo", " stable-4.x"):
            with self.assertRaises(sm.MaintenanceError):
                sm.require_branch(unsafe)

    def test_global_options_must_precede_subcommand(self):
        parser = sm.build_parser()
        args = parser.parse_args([
            "--repo-dir", "source", "--state-dir", "/tmp/state", "guard", "--branch", "stable-4.x",
        ])
        self.assertEqual(args.repo_dir, Path("source"))
        self.assertEqual(args.state_dir, "/tmp/state")
        with self.assertRaises(SystemExit):
            parser.parse_args(["guard", "--branch", "stable-4.x", "--repo-dir", "source"])

    def test_requested_branch_is_defensive_default(self):
        with mock.patch.dict(os.environ, {"REQUESTED_BRANCH": "stable-3.x", "STABLE_BRANCH": ""}):
            args = sm.build_parser().parse_args(["--repo-dir", "source", "--state-dir", "/tmp/s", "guard"])
            self.assertEqual(args.branch, "stable-3.x")

    def test_runner_scrubs_all_authentication_material(self):
        env = {
            "PATH": "/bin", "AZURE_API_KEY": "secret", "AZURE_COGNITIVE_SERVICES_API_KEY": "secret",
            "AZURE_RESOURCE_NAME": "resource", "AZURE_OPENAI_DEPLOYMENT": "model",
            "GITHUB_TOKEN": "github", "GH_TOKEN": "github", "SAFE": "yes",
        }
        runner = sm.Runner(Path.cwd(), env)
        self.assertNotIn("SAFE", runner.env)
        self.assertEqual(runner.env["HOME"], "/nonexistent")
        self.assertEqual(runner.env["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        for key in env:
            if key.startswith("AZURE_") or key in {"GITHUB_TOKEN", "GH_TOKEN"}:
                self.assertNotIn(key, runner.env)

    def test_state_is_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            state.save({"skip": True})
            self.assertEqual(state.load(), {"skip": True})
            self.assertEqual(os.stat(state.path).st_mode & 0o777, 0o600)

    def test_locked_build_command_has_security_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.shutil, "which", side_effect=["/usr/bin/podman"]):
            source = Path(tmp) / "source"; source.mkdir()
            cargo_home = Path(tmp) / "project-cargo-home"
            cargo_home.mkdir(parents=True, exist_ok=True)
            (source / ".git").mkdir()
            (cargo_home / "registry").mkdir()
            (cargo_home / "git").mkdir()
            runner = mock.Mock(root=source.resolve())
            runner.run.return_value = sm.CommandResult(0, "", "")
            env = {
                "MAINTENANCE_BUILD_IMAGE": "registry.example/build@sha256:abc",
                "MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home),
            }
            with mock.patch.dict(os.environ, env):
                sm.locked_build(runner, target_dir=Path(tmp) / "target")
            argv = runner.run.call_args_list[0].args[0]
            joined = " ".join(argv)
            self.assertIn("--network=none", argv)
            self.assertIn("--cap-drop=ALL", argv)
            self.assertIn("--security-opt=no-new-privileges", argv)
            self.assertIn("/workspace:ro", joined)
            self.assertIn(f"{(source / '.git').resolve()}:/workspace/.git:ro", joined)
            self.assertIn("/target:rw,nosuid,nodev,size=6g", joined)
            self.assertNotIn(f"{Path(tmp) / 'target'}:/target", joined)
            self.assertNotIn("/home/runner/.cargo", joined)
            self.assertNotIn("/home/runner/.rustup", joined)
            self.assertIn("/opt/project-cargo:rw,nosuid,nodev,size=16m", joined)
            self.assertIn(f"{(cargo_home / 'registry').resolve()}:/opt/project-cargo/registry:ro", joined)
            self.assertIn(f"{(cargo_home / 'git').resolve()}:/opt/project-cargo/git:ro", joined)
            self.assertNotIn(f"{cargo_home.resolve()}:/opt/project-cargo:ro", joined)
            self.assertIn("CARGO_HOME=/opt/project-cargo", argv)
            self.assertIn("RUSTUP_HOME=/usr/local/rustup", argv)
            self.assertIn("PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", argv)
            self.assertIn("O365_GEN_DIR=/target/o365-generated", argv)
            for limit in ("65532:65532", "--pids-limit=512", "--cpus=4", "--memory=8g", "--memory-swap=8g"):
                self.assertIn(limit, argv)
            self.assertNotIn("AZURE", joined)
            self.assertNotIn("GITHUB_TOKEN", joined)
            cleanup = runner.run.call_args_list[-1].args[0]
            self.assertEqual(cleanup[:3], ["/usr/bin/podman", "rm", "-f"])
            self.assertRegex(cleanup[3], r"^himmelblau-maint-[0-9a-f]{16}$")

    def test_networked_write_command_uses_only_source_and_project_cache_mounts(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
            base = Path(tmp); source = base / "source"; cache = base / "project-cache"
            for path in (source, cache): path.mkdir()
            (source / ".git").mkdir()
            runner = mock.Mock(root=source.resolve()); runner.run.return_value = sm.CommandResult(0, "{}", "")
            env = {
                "MAINTENANCE_BUILD_IMAGE": "image@sha256:abc", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache),
            }
            with mock.patch.dict(os.environ, env):
                sm.contained_repo_command(
                    runner, ["cargo", "update", "-p", "x@1.0.0", "--precise", "1.0.1"],
                    network=True, source_rw=True, cache_rw=True,
                )
            argv = runner.run.call_args_list[0].args[0]; joined = " ".join(argv)
            self.assertIn("--network=bridge", argv)
            self.assertIn(f"{source.resolve()}:/workspace:rw", joined)
            git_mount = f"{(source / '.git').resolve()}:/workspace/.git:ro"
            self.assertIn(git_mount, joined)
            self.assertGreater(argv.index(git_mount), argv.index(f"{source.resolve()}:/workspace:rw"))
            self.assertNotIn(f"{(source / '.git').resolve()}:/workspace/.git:rw", joined)
            self.assertIn(f"{cache.resolve()}:/opt/project-cargo:rw", joined)
            self.assertIn(f"--user {os.getuid()}:{os.getgid()}", joined)
            self.assertNotIn(str(Path.home()), joined)

    def test_offline_container_fails_closed_without_registry_cache(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
            base = Path(tmp); source = base / "source"; cache = base / "project-cache"
            for path in (source, cache): path.mkdir()
            (source / ".git").mkdir()
            runner = mock.Mock(root=source.resolve())
            env = {
                "MAINTENANCE_BUILD_IMAGE": "image@sha256:abc", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache),
            }
            with mock.patch.dict(os.environ, env), self.assertRaisesRegex(sm.MaintenanceError, "registry cache"):
                sm.contained_repo_command(
                    runner, ["cargo", "build", "--locked"],
                    network=False, source_rw=False, cache_rw=False,
                )
            runner.run.assert_not_called()

    def test_container_fails_closed_for_missing_or_symlinked_git_admin(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
            base = Path(tmp); source = base / "source"; cache = base / "cache"
            for path in (source, cache, cache / "registry"): path.mkdir()
            runner = mock.Mock(root=source.resolve())
            env = {
                "MAINTENANCE_BUILD_IMAGE": "image@sha256:abc", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache),
            }
            with mock.patch.dict(os.environ, env), self.assertRaisesRegex(sm.MaintenanceError, "non-symlink"):
                sm.contained_repo_command(runner, ["cargo", "build"], network=False, source_rw=False, cache_rw=False)
            outside = base / "outside-git"; outside.mkdir(); (source / ".git").symlink_to(outside, target_is_directory=True)
            with mock.patch.dict(os.environ, env), self.assertRaisesRegex(sm.MaintenanceError, "non-symlink"):
                sm.contained_repo_command(runner, ["cargo", "build"], network=False, source_rw=False, cache_rw=False)
            runner.run.assert_not_called()

    def test_tooling_integrity_requires_exact_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "tool.py"; script.write_bytes(b"trusted tooling\n")
            digest = __import__("hashlib").sha256(script.read_bytes()).hexdigest()
            sm.verify_tooling_integrity(script, digest)
            for invalid in ("", "A" * 64, "0" * 64):
                with self.assertRaises(sm.MaintenanceError):
                    sm.verify_tooling_integrity(script, invalid)
            target = Path(tmp) / "target.py"; target.write_bytes(script.read_bytes())
            link = Path(tmp) / "link.py"; link.symlink_to(target)
            with self.assertRaisesRegex(sm.MaintenanceError, "unsafe"):
                sm.verify_tooling_integrity(link, digest)

    def test_no_direct_host_cargo_or_crate2nix_calls_remain(self):
        source = SCRIPT.read_text()
        self.assertNotRegex(source, r'runner\.run\(\s*\[\s*["\'](?:cargo|crate2nix)["\']')
        self.assertNotRegex(source, r'runner\.run\(\s*crate2nix_command')

    def test_cargo_updates_use_contained_networked_write(self):
        runner = mock.Mock()
        expected = sm.CommandResult(0, "", "")
        with mock.patch.object(sm, "contained_repo_command", return_value=expected) as contained:
            result = sm.contained_cargo_update(runner, "serde", "1.0.0", "1.0.1")
        self.assertEqual(result, expected)
        contained.assert_called_once_with(
            runner, ["cargo", "update", "-p", "serde@1.0.0", "--precise", "1.0.1"],
            network=True, source_rw=True, cache_rw=True, timeout=300, check=False,
        )

    def test_workflow_uses_runtime_paths_and_containerized_tools(self):
        workflow = WORKFLOW.read_text()
        self.assertNotIn("MAINTENANCE_PROJECT_CARGO_HOME: ${{ runner.temp }}", workflow)
        self.assertNotIn("STATE_DIR: ${{ runner.temp }}/stable-maintenance\n", workflow)
        self.assertIn("MAINTENANCE_PROJECT_CARGO_HOME=%s", workflow)
        self.assertIn("STATE_DIR=%s", workflow)
        self.assertNotIn("cargo install", workflow)
        self.assertNotIn("MAINTENANCE_CARGO_BIN", workflow)
        self.assertNotIn("MAINTENANCE_RUSTUP_HOME", workflow)
        self.assertEqual(workflow.count("AZURE_API_KEY:"), 2)
        smoke_block = workflow.split("      - name: Smoke-test maintenance image Git tooling\n", 1)[1]
        smoke_block = smoke_block.split("\n      - name:", 1)[0].split("        run: |\n", 1)[1]
        smoke_command = "\n".join(
            line[10:] if line.startswith("          ") else line for line in smoke_block.splitlines()
        )
        smoke_argv = shlex.split(smoke_command)
        self.assertEqual(smoke_argv[-2], "-euc")
        for command in ("rustc --version", "cargo --version", "cargo-vet --version", "cargo-audit --version", "crate2nix --version"):
            self.assertIn(command, smoke_argv[-1])
        self.assertIn("snapshot.ubuntu.com:443", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertNotIn("github.event.repository", workflow)
        self.assertIn(
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", workflow,
        )
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertIn("permission-workflows: write", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ steps.publish-token.outputs.token }}", workflow)

        dockerfile = DOCKERFILE.read_text()
        self.assertRegex(dockerfile, r"FROM rust:1\.98\.0-bookworm@sha256:[0-9a-f]{64} AS rust-toolchain")
        self.assertRegex(dockerfile, r"FROM rust:1\.98\.0-bookworm@sha256:[0-9a-f]{64} AS maintenance-tools")
        self.assertIn("COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo", dockerfile)
        self.assertIn("COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup", dockerfile)
        self.assertIn("UBUNTU_SNAPSHOT=20260924T000000Z", dockerfile)
        for package, version in (("cargo-vet", "0.10.2"), ("cargo-audit", "0.22.2"), ("crate2nix", "0.15.0")):
            self.assertIn(f"{package} --version {version} --locked", dockerfile)

    def test_checkout_regular_file_accepts_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir()
            (root / "Cargo.toml").write_text("[workspace]\n")
            self.assertEqual(sm.checkout_regular_file(root, "Cargo.toml"), root / "Cargo.toml")

    def test_checkout_regular_file_rejects_leaf_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir()
            outside = Path(tmp) / "outside"; outside.mkdir()
            (outside / "Cargo.toml").write_text("[workspace]\n")
            (root / "Cargo.toml").symlink_to(outside / "Cargo.toml")
            with self.assertRaisesRegex(sm.MaintenanceError, "non-symlink regular file"):
                sm.checkout_regular_file(root, "Cargo.toml")

    def test_checkout_regular_file_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir()
            outside = Path(tmp) / "outside"; outside.mkdir()
            (root / "supply-chain").symlink_to(outside, target_is_directory=True)
            (outside / "audits.toml").write_text("safe")
            with self.assertRaisesRegex(sm.MaintenanceError, "non-symlink regular file"):
                sm.checkout_regular_file(root, "supply-chain/audits.toml")
            self.assertEqual((outside / "audits.toml").read_text(), "safe")

    def test_http_json_sets_json_content_type_for_body(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b"{}"

        seen = None
        def open_request(request, **kwargs):
            nonlocal seen
            seen = request
            return Response()

        with mock.patch.object(sm.urllib.request, "urlopen", side_effect=open_request):
            sm.http_json("https://example.test", method="POST", body={"ok": True})
        self.assertEqual(seen.get_header("Content-type"), "application/json")

    def test_http_json_preserves_explicit_content_type(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b"{}"

        seen = None
        def open_request(request, **kwargs):
            nonlocal seen
            seen = request
            return Response()

        with mock.patch.object(sm.urllib.request, "urlopen", side_effect=open_request):
            sm.http_json(
                "https://example.test", method="POST", body={"ok": True},
                headers={"content-type": "application/custom"},
            )
        self.assertEqual(seen.get_header("Content-type"), "application/custom")

    def test_select_writes_enabled_and_matrix_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            args = mock.Mock(branch="stable-4.x")
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                sm.phase_select(args, mock.Mock(), mock.Mock())
            lines = output.read_text().splitlines()
            self.assertEqual(lines[0], "enabled=true")
            self.assertEqual(json.loads(lines[1].removeprefix("matrix=")), {
                "include": [{"branch": "stable-4.x"}],
            })

    def test_secure_push_keeps_token_out_of_argv_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.Mock()
            token = "github-secret-token"
            def inspect_call(argv, **kwargs):
                self.assertNotIn(token, " ".join(argv))
                self.assertNotIn("force", " ".join(argv))
                self.assertEqual(kwargs["private_env"]["MAINTENANCE_GITHUB_PUSH_TOKEN"], token)
                askpass = Path(kwargs["private_env"]["GIT_ASKPASS"])
                self.assertTrue(askpass.is_file())
                self.assertEqual(askpass.stat().st_mode & 0o777, 0o700)
                return sm.CommandResult(0, "", "")
            runner.run.side_effect = inspect_call
            sm.secure_github_push(
                runner, Path(tmp), "owner/repo", sm.AUTOMATION_PREFIX + "stable-4.x-1", token,
            )
            self.assertFalse(any(Path(tmp).iterdir()))

    def test_pr_body_has_global_utf8_budget_and_reserved_marker(self):
        value = {
            "main_head": "a" * 40,
            "dependency_updates": [{"crate": "é" * 200, "new": str(i)} for i in range(500)],
            "vet_accepted": [], "dependabot_imported": [], "backports_applied": [],
        }
        body = sm.build_pr_body(value, max_bytes=4096)
        self.assertLessEqual(len(body.encode()), 4096)
        self.assertTrue(body.endswith(f"{sm.MARKER} {'a' * 40}"))

    def test_runner_rejects_oversized_streamed_output(self):
        runner = sm.Runner(Path.cwd(), {"PATH": os.environ["PATH"]})
        with self.assertRaises(sm.MaintenanceError):
            runner.run([sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"], max_output=100)


class VersionPolicyTests(unittest.TestCase):
    def release(self, version, age_hours, yanked=False):
        return {
            "num": version, "created_at": (NOW - dt.timedelta(hours=age_hours)).isoformat(), "yanked": yanked,
        }

    def test_quarantine_boundary(self):
        self.assertTrue(sm.release_is_eligible("serde", NOW - dt.timedelta(hours=252), NOW))
        self.assertFalse(sm.release_is_eligible("serde", NOW - dt.timedelta(hours=251, minutes=59), NOW))

    def test_libhimmelblau_is_immediately_eligible(self):
        self.assertTrue(sm.release_is_eligible("libhimmelblau", NOW, NOW))

    def test_advisory_exception_is_immediately_eligible(self):
        self.assertTrue(sm.release_is_eligible("danger", NOW, NOW, advisory_required=True))

    def test_patch_only_newest_first_and_filters_yanked_prerelease(self):
        releases = [
            self.release("1.3.0", 1000), self.release("1.2.5", 300), self.release("1.2.4", 300),
            self.release("1.2.6-beta.1", 300), self.release("1.2.7", 300, True), self.release("1.2.3", 1000),
        ]
        self.assertEqual(
            sm.candidate_versions("1.2.3", releases, crate="x", started=NOW), ["1.2.5", "1.2.4"],
        )

    def test_exact_advisory_fixed_version_may_cross_major_and_quarantine(self):
        releases = [self.release("9.0.0", 1000), self.release("2.0.2", 1), self.release("2.0.0", 1), self.release("1.2.4", 1)]
        self.assertEqual(
            sm.candidate_versions("1.2.3", releases, crate="x", started=NOW, fixed_requirements=[">=2.0.0"]),
            ["2.0.2", "2.0.0"],
        )

    def test_advisory_range_may_cross_minor_and_quarantine(self):
        releases = [
            self.release("3.0.0", 1), self.release("2.9.9", 1), self.release("2.1.0", 1),
            self.release("2.0.0", 1),
        ]
        self.assertEqual(
            sm.candidate_versions(
                "1.5.0", releases, crate="danger", started=NOW,
                fixed_requirements=[">=2.0.0, <3.0.0"],
            ),
            ["2.9.9", "2.1.0", "2.0.0"],
        )

    def test_cargo_audit_version_requirement_subset(self):
        self.assertTrue(sm.semver_satisfies(sm.SemVer.parse("1.2.4"), ">=1.2.3, <2.0.0"))
        self.assertFalse(sm.semver_satisfies(sm.SemVer.parse("2.0.0"), ">=1.2.3, <2.0.0"))
        self.assertTrue(sm.semver_satisfies(sm.SemVer.parse("1.4.0"), "^1.2.3"))
        self.assertFalse(sm.semver_satisfies(sm.SemVer.parse("2.0.0"), "^1.2.3"))
        self.assertFalse(sm.semver_satisfies(sm.SemVer.parse("1.2.3"), "attacker expression"))

    def test_semver_rejects_partial_or_malformed_versions(self):
        for bad in ("1", "1.2", "v1.2.3", "01.2.3", "1.2.3/../../x"):
            with self.assertRaises(ValueError):
                sm.SemVer.parse(bad)

    def test_patch_bump(self):
        self.assertEqual(sm.bump_patch("4.0.9"), "4.0.10")
        with self.assertRaises(sm.MaintenanceError):
            sm.bump_patch("4.0.9-rc.1")

    def test_transitive_freshness_detects_new_unknown_and_fresh_packages(self):
        before = {("direct", "1.0.0"): "id"}
        after = {("direct", "1.0.1"): "id2", ("new", "2.0.0"): "id3", ("old", "3.0.0"): "id4"}
        published = {
            ("direct", "1.0.1"): NOW - dt.timedelta(hours=300),
            ("new", "2.0.0"): NOW - dt.timedelta(hours=10),
            ("old", "3.0.0"): NOW - dt.timedelta(hours=300),
        }
        self.assertEqual(
            sm.transitive_freshness_violations(before, after, published, NOW), [("new", "2.0.0")],
        )

    def test_transitive_advisory_and_libhimmelblau_exceptions(self):
        after = {("libhimmelblau", "0.9.0"): "a", ("fixed", "9.0.0"): "b"}
        published = {key: NOW for key in after}
        self.assertEqual(
            sm.transitive_freshness_violations({}, after, published, NOW, {("fixed", "9.0.0")}), [],
        )


class CargoVetTests(unittest.TestCase):
    def test_parser_returns_only_explicit_unvetted_commands(self):
        output = """
        Vetting Failed!
          cargo vet diff serde 1.0.1 1.0.2 publisher used-by 2 files changed
          cargo vet inspect novel-crate 0.1.0 publisher used-by 100 lines
        Existing imported audit: cargo vet certify ignored 1.0.0
        """
        self.assertEqual(sm.parse_cargo_vet_output(output), [
            sm.VetItem("serde", "1.0.1", "1.0.2"), sm.VetItem("novel-crate", None, "0.1.0"),
        ])

    def test_covered_dependencies_produce_no_items(self):
        self.assertEqual(sm.parse_cargo_vet_output("Vetting Succeeded!"), [])

    def test_audit_serialization_delta_and_full_version(self):
        delta = sm.serialize_audit("serde", "1.0.1", "1.0.2")
        self.assertIn("[[audits.serde]]", delta)
        self.assertIn('who = "Codex (automated via Azure OpenAI)"', delta)
        self.assertIn('delta = "1.0.1 -> 1.0.2"', delta)
        full = sm.serialize_audit("fresh", None, "0.1.0")
        self.assertIn('version = "0.1.0"', full)
        self.assertNotIn("delta", full)

    def test_audit_serialization_rejects_injection(self):
        with self.assertRaises(sm.MaintenanceError):
            sm.serialize_audit('serde]]\nwho="attacker', None, "1.0.0")

    def test_rejection_only_vet_run_does_not_create_empty_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; (root / "supply-chain").mkdir(parents=True)
            (root / "supply-chain/audits.toml").write_text("")
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock(root=root.resolve())
            rejected = sm.VetItem("transitive", "1.0.0", "1.0.1")

            def git(argv, **kwargs):
                if argv in (["status", "--porcelain"], ["diff", "--name-only"]):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)

            runner.git.side_effect = git
            vet_failed = sm.CommandResult(1, "cargo vet diff transitive 1.0.0 1.0.1\n", "")
            vet_clean = sm.CommandResult(0, "Vetting Succeeded!\n", "")
            with mock.patch.object(sm, "contained_repo_command", side_effect=[vet_failed, vet_clean]), \
                 mock.patch.object(sm, "AzureAI", return_value=mock.Mock()), \
                 mock.patch.object(sm, "safe_vet_decision", return_value=False), \
                 mock.patch.object(sm, "_fallback_after_vet_rejection", return_value=([], [])):
                sm.phase_vet_dependencies(mock.Mock(), state, runner)

            self.assertEqual(state.load()["vet_rejected"], [sm.asdict(rejected)])
            self.assertFalse(any(call.args[0][0] == "commit" for call in runner.git.call_args_list))

    def test_vet_gap_rejections_are_sticky_across_retries(self):
        prior = sm.VetItem("prior", "1.0.0", "1.0.1")
        newly_rejected = sm.VetItem("new", "2.0.0", "2.0.1")
        rejected = {prior}
        with mock.patch.object(sm, "safe_vet_decision", return_value=False) as decide:
            decisions, added = sm.decide_vet_gaps(
                mock.Mock(), mock.Mock(), [prior, newly_rejected], Path("cache"), rejected,
            )
            retry_decisions, retry_added = sm.decide_vet_gaps(
                mock.Mock(), mock.Mock(), [newly_rejected], Path("cache"), rejected,
            )
        self.assertEqual(decisions, [(prior, False), (newly_rejected, False)])
        self.assertEqual(added, [newly_rejected])
        self.assertEqual(retry_decisions, [(newly_rejected, False)])
        self.assertEqual(retry_added, [])
        decide.assert_called_once()

    def test_real_cargo_audit_patched_requirements(self):
        audit = {"vulnerabilities": {"list": [{
            "package": {"name": "danger"}, "versions": {"patched": [">=2.0.0, <3.0.0"]},
        }]}}
        self.assertEqual(sm.parse_audit_fixed_requirements(audit, 1), {"danger": {">=2.0.0, <3.0.0"}})
        audit["vulnerabilities"]["list"][0]["package"]["version"] = "1.5.0"
        self.assertEqual(sm.audit_vulnerable_targets(audit), [
            ("danger", "1.5.0", [{">=2.0.0, <3.0.0"}]),
        ])

    def test_cargo_audit_malformed_nonzero_fails_closed(self):
        with self.assertRaises(sm.MaintenanceError):
            sm.parse_audit_fixed_requirements({}, 1)
        with self.assertRaises(sm.MaintenanceError):
            sm.parse_audit_fixed_requirements({"vulnerabilities": {"list": []}}, 1)
        self.assertEqual(sm.parse_audit_fixed_requirements({"vulnerabilities": {"list": []}}, 0), {})
        no_fix = {"vulnerabilities": {"list": [{
            "package": {"name": "danger", "version": "1.0.0"}, "versions": {"patched": []},
        }]}}
        self.assertEqual(sm.audit_vulnerable_targets(no_fix), [("danger", "1.0.0", [set()])])

    def test_exact_advisory_groups_require_each_advisory(self):
        groups = [{">=2.0.0"}, {"<2.5.0"}]
        self.assertTrue(sm.satisfies_all_advisories(sm.SemVer.parse("2.4.0"), groups))
        self.assertFalse(sm.satisfies_all_advisories(sm.SemVer.parse("2.6.0"), groups))
        audit = {"vulnerabilities": {"list": [
            {"package": {"name": "foo", "version": "2.0.0"}, "versions": {"patched": [">=2.1.0"]}},
            {"package": {"name": "foo", "version": "2.0.0"}, "versions": {"patched": ["<2.5.0"]}},
        ]}}
        self.assertEqual(len(sm.audit_vulnerable_targets(audit)[0][2]), 2)
        self.assertNotIn(("foo", "1.0.0"), [(name, version) for name, version, _ in sm.audit_vulnerable_targets(audit)])


class ManifestRewriteTests(unittest.TestCase):
    def test_simple_string_and_inline_table(self):
        text = '[dependencies]\nserde = "=1.0.1"\ntokio = { version = "^1.2.3", features = ["rt"] }\n'
        text, count = sm.rewrite_dependency_version(text, "serde", "serde", "1.0.2")
        self.assertEqual(count, 1)
        self.assertIn('serde = "=1.0.2"', text)
        text, count = sm.rewrite_dependency_version(text, "tokio", "tokio", "1.2.4")
        self.assertEqual(count, 1)
        self.assertIn('version = "^1.2.4"', text)

    def test_package_rename(self):
        text = '[dependencies]\nrenamed = { package = "real-crate", version = "1.0.0" }\n'
        rewritten, count = sm.rewrite_dependency_version(text, "renamed", "real-crate", "1.0.1")
        self.assertEqual(count, 1)
        self.assertIn('version = "1.0.1"', rewritten)

    def test_workspace_dependency_updates_root_not_inherited_member(self):
        root = '[workspace.dependencies]\nserde = "1.0.0"\n'
        member = '[dependencies]\nserde = { workspace = true }\n'
        rewritten_root, root_count = sm.rewrite_dependency_version(root, "serde", "serde", "1.0.1")
        rewritten_member, member_count = sm.rewrite_dependency_version(member, "serde", "serde", "1.0.1")
        self.assertEqual(root_count, 1)
        self.assertEqual(member_count, 0)
        self.assertIn('serde = "1.0.1"', rewritten_root)
        self.assertEqual(rewritten_member, member)

    def test_refuses_ambiguous_dynamic_shapes(self):
        for text in (
            '[dependencies]\nserde = {\n version = "1.0.0"\n}\n',
            '[dependencies.serde]\nversion = "1.0.0"\n',
            '[dependencies]\nserde = env.VERSION\n',
        ):
            with self.subTest(text=text):
                with self.assertRaises(sm.MaintenanceError):
                    sm.rewrite_dependency_version(text, "serde", "serde", "1.0.1")

    def test_path_only_dependency_is_not_modified(self):
        text = '[dependencies]\nserde = { path = "../serde", version = "1.0.0" }\n'
        rewritten, count = sm.rewrite_dependency_version(text, "serde", "serde", "1.0.1")
        self.assertEqual((rewritten, count), (text, 0))

    def test_duplicate_direct_versions_keep_package_identity_and_binding(self):
        metadata = {
            "workspace_members": ["member1", "member2"],
            "packages": [
                {"id": "member1", "manifest_path": "/repo/a/Cargo.toml"},
                {"id": "member2", "manifest_path": "/repo/b/Cargo.toml"},
                {"id": "foo1", "name": "foo", "version": "1.2.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
                {"id": "foo2", "name": "foo", "version": "2.3.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
            ],
            "resolve": {"nodes": [
                {"id": "member1", "deps": [{"name": "foo_v1", "pkg": "foo1"}]},
                {"id": "member2", "deps": [{"name": "foo", "pkg": "foo2"}]},
            ]},
        }
        targets = sm.direct_registry_packages(metadata)
        self.assertEqual([(t.version, t.bindings) for t in targets], [
            ("1.2.0", (("/repo/a/Cargo.toml", "foo_v1"),)),
            ("2.3.0", (("/repo/b/Cargo.toml", "foo"),)),
        ])

    def test_exact_manifest_binding_does_not_mutate_unrelated_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); member = root / "member"; member.mkdir()
            (root / "Cargo.toml").write_text('[workspace]\n[workspace.dependencies]\nfoo = "2.3.0"\n')
            manifest = member / "Cargo.toml"
            manifest.write_text('[package]\nname="m"\nversion="0.1.0"\n[dependencies]\nfoo = "1.2.0"\n')
            target = sm.DirectTarget("foo1", "foo", "1.2.0", ((str(manifest), "foo"),))
            changed = sm.update_direct_dependency_manifests(
                root, {"workspace_members": [], "packages": []}, "foo", "1.2.1", target,
            )
            self.assertEqual(changed, ["member/Cargo.toml"])
            self.assertIn('foo = "2.3.0"', (root / "Cargo.toml").read_text())

    def test_workspace_inherited_binding_mutates_root_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); member = root / "member"; member.mkdir()
            (root / "Cargo.toml").write_text('[workspace]\n[workspace.dependencies]\nfoo = "1.2.0"\n')
            manifest = member / "Cargo.toml"
            manifest.write_text('[package]\nname="m"\nversion="0.1.0"\n[dependencies]\nfoo = { workspace = true }\n')
            target = sm.DirectTarget("foo1", "foo", "1.2.0", ((str(manifest), "foo"),))
            changed = sm.update_direct_dependency_manifests(
                root, {"workspace_members": [], "packages": []}, "foo", "1.2.1", target,
            )
            self.assertEqual(changed, ["Cargo.toml"])
            self.assertIn("workspace = true", manifest.read_text())
            self.assertIn('foo = "1.2.1"', (root / "Cargo.toml").read_text())


class CommitFilteringTests(unittest.TestCase):
    def test_obvious_subjects_are_filtered(self):
        subjects = [
            "cargo vet", "Cargo Audit", "cargo audit/cargo vet", "cargo fmt", "cargo clippy",
            "Version 4.0.5", "Branch stable-4.x", "Update Cargo.nix", "Regenerate Cargo.nix",
            "nix crate2nix -- generate", "chore: refresh cargo vet metadata", "feat: new capability",
            "docs(parser): clarify", "refactor!: API", "style: rustfmt", "test: more tests", "chore(deps): bump x",
            "i18n: add German", "l10n: add French", "feat(i18n): add Spanish",
        ]
        for subject in subjects:
            with self.subTest(subject=subject):
                self.assertIsNotNone(sm.prefilter_commit(subject, ["src/a.rs"]))

    def test_ambiguous_fix_security_ci_and_revert_are_not_title_filtered(self):
        for subject in ("fix: prevent panic", "security: harden parser", "ci: repair packaging", "Revert bad fix", "Update parser"):
            with self.subTest(subject=subject):
                self.assertIsNone(sm.prefilter_commit(subject, ["src/a.rs"]))

    def test_path_and_author_filters(self):
        self.assertEqual(sm.prefilter_commit("Update stuff", ["Cargo.lock"]), "dependency metadata only")
        self.assertEqual(sm.prefilter_commit("Repair action", [".github/workflows/ci.yml"]), "CI only")
        self.assertEqual(sm.prefilter_commit("Whatever", ["src/a.rs"], author="dependabot[bot]"), "dependabot/dependency update")
        self.assertEqual(sm.prefilter_commit("Merge branch", ["src/a.rs"], parents=2), "merge")

    def test_dependabot_admission_is_only_workflow_uses_lines(self):
        safe = [{"filename": ".github/workflows/ci.yml", "status": "modified", "patch": "@@ -1 +1 @@\n- uses: a/b@old\n+ uses: a/b@" + "a" * 40}]
        self.assertTrue(sm.safe_workflow_dependency_pr(safe))
        self.assertFalse(sm.safe_workflow_dependency_pr([
            {"filename": ".github/workflows/ci.yml", "status": "modified", "patch": "@@ -1 +1 @@\n- run: safe\n+ run: curl evil"},
        ]))
        self.assertFalse(sm.safe_workflow_dependency_pr([
            {"filename": ".github/scripts/tool.py", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new"},
        ]))
        self.assertFalse(sm.safe_action_ref_patch("- uses: a/b@old\n+ uses: evil/b@" + "a" * 40))
        self.assertFalse(sm.safe_action_ref_patch("- uses: a/b@old\n+ uses: a/b@short"))
        self.assertTrue(sm.safe_action_ref_patch(
            "- uses: a/b@old\n- # v3\n+ uses: a/b@" + "b" * 40 + "\n+ # v4",
        ))


class MutationBoundaryTests(unittest.TestCase):
    def test_model_output_has_no_patch_application_path(self):
        source = SCRIPT.read_text()
        for removed in ("PATCH_SCHEMA", "trivial_build_repair", "conflict_resolution", "safe_apply_patch"):
            self.assertNotIn(removed, source)

    def test_vet_rejects_dirty_entry_before_running_tools(self):
        runner = mock.Mock()
        runner.git.return_value = sm.CommandResult(0, " M supply-chain/audits.toml\n", "")
        with mock.patch.object(sm, "contained_repo_command") as contained, self.assertRaisesRegex(
            sm.MaintenanceError, "clean before cargo-vet certification",
        ):
            sm.phase_vet_dependencies(mock.Mock(), mock.Mock(), runner)
        contained.assert_not_called()

    def test_vet_rejects_every_changed_path_except_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "supply-chain").mkdir()
            (root / "supply-chain/audits.toml").write_text("")
            state = sm.State(root / "state")
            runner = mock.Mock(root=root)
            def git(argv, **kwargs):
                if argv == ["status", "--porcelain"]:
                    return sm.CommandResult(0, "", "")
                if argv == ["diff", "--name-only"]:
                    return sm.CommandResult(0, "supply-chain/config.toml\n", "")
                raise AssertionError(argv)
            runner.git.side_effect = git
            clean_vet = sm.CommandResult(0, "", "")
            with mock.patch.object(sm, "contained_repo_command", return_value=clean_vet), self.assertRaisesRegex(
                sm.MaintenanceError, "unexpected files changed",
            ):
                sm.phase_vet_dependencies(mock.Mock(), state, runner)

    def test_refresh_commits_only_the_import_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock()
            def git(argv, **kwargs):
                if argv == ["status", "--porcelain"]:
                    return sm.CommandResult(0, "", "")
                if argv == ["diff", "--name-only"]:
                    return sm.CommandResult(0, "supply-chain/imports.lock\n", "")
                if argv in (["add", "--", "supply-chain/imports.lock"], ["commit", "-m", "chore: refresh cargo vet metadata"]):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)
            runner.git.side_effect = git
            with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "cargo_metadata", return_value={"packages": []}):
                sm.phase_refresh_vet_imports(mock.Mock(), state, runner)
            runner.git.assert_any_call(["add", "--", "supply-chain/imports.lock"])
            runner.git.assert_any_call(["commit", "-m", "chore: refresh cargo vet metadata"])

    def test_refresh_rejects_unexpected_output(self):
        runner = mock.Mock()
        runner.git.side_effect = [
            sm.CommandResult(0, "", ""),
            sm.CommandResult(0, "supply-chain/audits.toml\n", ""),
        ]
        with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, "", "")), \
             self.assertRaisesRegex(sm.MaintenanceError, "unexpected path"):
            sm.phase_refresh_vet_imports(mock.Mock(), mock.Mock(), runner)

    def test_conflicting_backport_is_aborted_without_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            sha, head = "a" * 40, "b" * 40
            state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
            runner = mock.Mock()
            def git(argv, **kwargs):
                if argv[:4] == ["log", "-1", "--format=%H", "--fixed-strings"]:
                    return sm.CommandResult(0, "", "")
                if argv == ["rev-parse", "HEAD"]:
                    return sm.CommandResult(0, head + "\n", "")
                if argv == ["cherry-pick", "-x", sha]:
                    return sm.CommandResult(1, "", "")
                if argv == ["status", "--porcelain=v1"]:
                    return sm.CommandResult(0, "UU src/a.rs\n", "")
                if argv in (["cherry-pick", "--abort"], ["reset", "--hard", head]):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)
            runner.git.side_effect = git
            with mock.patch.object(sm, "AzureAI", side_effect=AssertionError("AI must not resolve conflicts")):
                sm.phase_apply_backports(mock.Mock(), state, runner)
            self.assertEqual(state.load()["backports_applied"], [])
            self.assertEqual(state.load()["backports_conflict_skipped"], [sha])

    def test_conflicting_dependabot_pr_is_reset_without_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            commit, head, pre_head = "a" * 40, "b" * 40, "c" * 40
            pr = {
                "number": 17,
                "user": {"login": "dependabot[bot]"},
                "base": {"ref": "stable-4.x", "repo": {"full_name": "o/r"}},
                "head": {"sha": head, "repo": {"full_name": "o/r"}},
            }
            files = [{
                "filename": ".github/workflows/ci.yml", "status": "modified",
                "patch": "@@ -1 +1 @@\n- uses: a/b@old\n+ uses: a/b@" + "d" * 40,
            }]
            runner = mock.Mock()
            def git(argv, **kwargs):
                if argv == ["rev-parse", "HEAD"]:
                    return sm.CommandResult(0, pre_head + "\n", "")
                if argv in (["diff", "--quiet"], ["diff", "--cached", "--quiet"]):
                    return sm.CommandResult(0, "", "")
                if argv == ["fetch", "--no-tags", "origin", head]:
                    return sm.CommandResult(0, "", "")
                if argv == ["rev-parse", "FETCH_HEAD"]:
                    return sm.CommandResult(0, head + "\n", "")
                if argv == ["merge-base", "--is-ancestor", "origin/stable-4.x", head]:
                    return sm.CommandResult(0, "", "")
                if argv == ["rev-list", "--reverse", f"origin/stable-4.x..{head}"]:
                    return sm.CommandResult(0, commit + "\n", "")
                if argv == ["diff-tree", "--no-commit-id", "--name-only", "-r", commit]:
                    return sm.CommandResult(0, ".github/workflows/ci.yml\n", "")
                if argv == ["diff-tree", "--no-commit-id", "--summary", "-r", commit]:
                    return sm.CommandResult(0, "", "")
                if argv == ["show", "--format=", "--unified=1", commit]:
                    return sm.CommandResult(0, files[0]["patch"], "")
                if argv == ["cherry-pick", commit]:
                    return sm.CommandResult(1, "", "")
                if argv == ["status", "--porcelain=v1"]:
                    return sm.CommandResult(0, "UU .github/workflows/ci.yml\n", "")
                if argv in (["cherry-pick", "--abort"], ["reset", "--hard", pre_head]):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)
            runner.git.side_effect = git
            with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                 mock.patch.object(sm, "github_paginated", return_value=[pr]), \
                 mock.patch.object(sm, "_pr_files", return_value=files), \
                 mock.patch.object(sm, "AzureAI", side_effect=AssertionError("AI must not resolve conflicts")):
                sm.phase_import_dependabot(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(state.load()["dependabot_imported"], [])
            self.assertEqual(state.load()["dependabot_skipped"], [{"number": 17, "reason": "validation or cherry-pick failure"}])


class MarkerConflictAndAITests(unittest.TestCase):
    SHA = "a" * 40

    def test_marker_parsing(self):
        self.assertEqual(sm.marker_sha(f"body\n{sm.MARKER} {self.SHA}\n"), self.SHA)
        self.assertIsNone(sm.marker_sha("ordinary commit"))
        with self.assertRaises(sm.MaintenanceError):
            sm.marker_sha(f"{sm.MARKER} {'a' * 40}\n{sm.MARKER} {'b' * 40}\n")
        self.assertEqual(
            sm.latest_marker_sha(f"new\n{sm.MARKER} {'b' * 40}\nold\n{sm.MARKER} {'a' * 40}\n"),
            "b" * 40,
        )

    def test_version_commit_body_contains_exact_marker(self):
        args = sm.version_commit_args("4.0.5", self.SHA)
        self.assertEqual(args, ["commit", "-m", "Version 4.0.5", "-m", f"{sm.MARKER} {self.SHA}"])
        self.assertEqual(sm.crate2nix_command(), ["crate2nix", "generate"])

    def test_conflict_status_parser(self):
        self.assertTrue(sm.has_unresolved_conflicts("UU src/a.rs\n M src/b.rs\n"))
        self.assertTrue(sm.has_unresolved_conflicts("DU src/a.rs\n"))
        self.assertFalse(sm.has_unresolved_conflicts(" M file named UU.txt\n?? new\n"))

    def test_malformed_ai_json_fails_closed(self):
        for value in ("not json", "[]", '{"decision":true,"reason":"extra"}', '{"decision":"yes"}'):
            with self.subTest(value=value):
                with self.assertRaises(sm.MaintenanceError):
                    result = sm.validate_json_decision(value, ["decision"])
                    if type(result["decision"]) is not bool:
                        raise sm.MaintenanceError("decision is not boolean")

    def test_strict_decision_json(self):
        self.assertEqual(sm.validate_json_decision('{"decision":true}', ["decision"]), {"decision": True})

    def test_stable_context_inventory_and_missing_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "src").mkdir(); (root / "src/a.rs").write_text("stable\n")
            runner = mock.Mock(root=root)
            runner.git.return_value = sm.CommandResult(0, "src/a.rs\0", "")
            context = sm.stable_path_context(runner, ["src/a.rs", "src/deleted.rs"])
            self.assertIn("stable", context)
            self.assertIn("MISSING_OR_DELETED_ON_STABLE", context)

    def test_backport_classification_error_aborts_instead_of_advancing_cutoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            cutoff, main, commit = "a" * 40, "b" * 40, "c" * 40
            state.save({"branch": "stable-4.x", "cutoff": cutoff, "main_head": main})
            runner = mock.Mock()

            def git(argv, **kwargs):
                if argv == ["rev-list", "--reverse", f"{cutoff}..{main}"]:
                    return sm.CommandResult(0, commit + "\n", "")
                if argv[:2] == ["show", "--format=fuller"]:
                    return sm.CommandResult(0, "patch", "")
                raise AssertionError(argv)

            runner.git.side_effect = git
            record = {
                "sha": commit, "subject": "Fix stable bug", "body": "", "author": "Maintainer",
                "parents": 1, "paths": ["src/a.rs"],
            }
            ai = mock.Mock()
            ai.call.side_effect = sm.MaintenanceError("temporary Azure failure")
            with mock.patch.object(sm, "_commit_record", return_value=record), \
                 mock.patch.object(sm, "AzureAI", return_value=ai), \
                 self.assertRaisesRegex(sm.MaintenanceError, "unable to classify main commit"):
                sm.phase_classify_backports(mock.Mock(), state, runner)
            self.assertNotIn("backport_candidates", state.load())

    def test_schema_validation_rejects_extra_keys_and_wrong_types(self):
        for value in ({"decision": "true"}, {"decision": True, "reason": "extra"}):
            with self.subTest(value=value):
                with self.assertRaises(sm.MaintenanceError):
                    sm.validate_schema_result(value, sm.BOOL_SCHEMA)

    def test_azure_retries_malformed_structured_output_with_bound(self):
        ai = object.__new__(sm.AzureAI)
        ai.key, ai.model, ai.url = "secret", "model", "https://example.invalid"
        responses = [{"output_text": "bad"}, {"output_text": "{}"}, {"output_text": '{"decision":true}'}]
        with mock.patch.object(sm, "http_json", side_effect=responses) as request, mock.patch.object(sm.time, "sleep"):
            self.assertEqual(ai.call("instructions", "data", sm.BOOL_SCHEMA, "decision"), {"decision": True})
            self.assertEqual(request.call_count, 3)


class CrateArchiveTests(unittest.TestCase):
    @staticmethod
    def archive(member_name="crate-1.0.0/src/lib.rs", *, symlink=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
            info = tarfile.TarInfo(member_name)
            if symlink:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                bundle.addfile(info)
            else:
                data = b"pub fn safe() {}\n"
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
        return stream.getvalue()

    def test_safe_archive_is_cached_read_only(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            sm, "download_crate_archive", return_value=self.archive(),
        ):
            source = sm.cache_crate_source("crate", "1.0.0", Path(tmp) / "cache")
            lib = source / "src/lib.rs"
            self.assertEqual(lib.read_text(), "pub fn safe() {}\n")
            self.assertEqual(lib.stat().st_mode & 0o777, 0o400)

    def test_archive_rejects_traversal_and_symlink(self):
        for archive in (self.archive("crate-1.0.0/../../escape"), self.archive(symlink=True)):
            with self.subTest():
                with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
                    sm, "download_crate_archive", return_value=archive,
                ):
                    with self.assertRaises(sm.MaintenanceError):
                        sm.cache_crate_source("crate", "1.0.0", Path(tmp) / "cache")


class GuardTests(unittest.TestCase):
    def test_blocking_pr_persists_skip_and_writes_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock()
            args = mock.Mock(branch="stable-4.x")
            response = [{
                "number": 9, "updated_at": "2026-01-01T00:00:00Z", "state": "open",
                "head": {"ref": sm.AUTOMATION_PREFIX + "stable-4.x-x", "repo": {"full_name": "o/r"}},
                "user": {"login": "github-actions[bot]"}, "labels": [],
            }]
            output = Path(tmp) / "output"
            with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                 mock.patch.object(sm, "github_headers", return_value={}), \
                 mock.patch.object(sm, "http_json", return_value=response), \
                 mock.patch.object(sm, "github_search_items", return_value=[]), \
                 mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                sm.phase_guard(args, state, runner)
            self.assertTrue(state.load()["skip"])
            self.assertEqual(output.read_text(), "proceed=false\n")

    def test_closed_unmerged_pr_does_not_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            args = mock.Mock(branch="stable-4.x")
            closed = [{
                "number": 9, "updated_at": "2026-01-01T00:00:00Z", "state": "closed", "merged_at": None,
                "head": {"ref": sm.AUTOMATION_PREFIX + "stable-4.x-x", "repo": {"full_name": "o/r"}},
                "user": {"login": "github-actions[bot]"}, "labels": [],
            }]
            with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                 mock.patch.object(sm, "github_headers", return_value={}), \
                 mock.patch.object(sm, "http_json", return_value=closed), \
                 mock.patch.object(sm, "github_search_items", return_value=[]):
                sm.phase_guard(args, state, mock.Mock())
            self.assertFalse(state.load()["skip"])

    def test_guard_ignores_fork_spoof_and_obeys_latest_validated_run(self):
        fork = {"number": 1, "updated_at": "2027", "state": "open",
                "head": {"ref": sm.AUTOMATION_PREFIX + "x", "repo": {"full_name": "evil/fork"}},
                "user": {"login": "github-actions[bot]"}, "labels": [{"name": sm.AUTOMATION_LABEL}]}
        merged = {"number": 2, "updated_at": "2026", "state": "closed", "merged_at": "2026-01-02",
                  "head": {"ref": sm.AUTOMATION_PREFIX + "x", "repo": {"full_name": "o/r"}},
                  "user": {"login": "github-actions[bot]"}, "labels": []}
        self.assertEqual(sm.latest_automation_pr([fork, merged], "o/r")["number"], 2)
        closed = {**merged, "number": 3, "updated_at": "2028", "merged_at": None, "state": "closed"}
        self.assertIsNone(closed["merged_at"])
        self.assertEqual(sm.latest_automation_pr([merged, closed], "o/r")["number"], 3)
        self.assertEqual(
            [pr["number"] for pr in sm.validated_automation_prs([merged, closed], "o/r") if pr.get("state") == "open"],
            [],
        )

    def test_github_pagination_is_bounded_and_collects_pages(self):
        pages = [[{"n": i} for i in range(100)], [{"n": 100}]]
        with mock.patch.object(sm, "http_json", side_effect=pages), mock.patch.object(sm, "github_headers", return_value={}):
            self.assertEqual(len(sm.github_paginated("https://api.github.com/repos/o/r/pulls")), 101)
        with mock.patch.object(sm, "http_json", return_value=[{}] * 100), mock.patch.object(sm, "github_headers", return_value={}):
            with self.assertRaises(sm.MaintenanceError):
                sm.github_paginated("https://api.github.com/repos/o/r/pulls", max_pages=2)


class InitializePhaseTests(unittest.TestCase):
    def test_initialize_requires_remote_head_and_validates_marker_ancestry(self):
        current, main, cutoff = "c" * 40, "d" * 40, "a" * 40
        class FakeRunner:
            def git(self, argv, **kwargs):
                key = tuple(argv)
                if key[:2] in {("diff", "--quiet"), ("diff", "--cached")}:
                    return sm.CommandResult(0, "", "")
                if key == ("rev-parse", "HEAD") or key == ("rev-parse", "origin/stable-4.x"):
                    return sm.CommandResult(0, current + "\n", "")
                if key == ("branch", "--show-current"):
                    return sm.CommandResult(0, "stable-4.x\n", "")
                if key[0] == "fetch":
                    return sm.CommandResult(0, "", "")
                if key == ("rev-parse", "origin/main"):
                    return sm.CommandResult(0, main + "\n", "")
                if key[0] == "log":
                    return sm.CommandResult(0, f"Version 4.0.5\n\n{sm.MARKER} {cutoff}\n", "")
                if key[:2] == ("merge-base", "--is-ancestor"):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(key)
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            sm.phase_initialize(mock.Mock(branch="stable-4.x"), state, FakeRunner())
            saved = state.load()
            self.assertEqual(saved["original_head"], current)
            self.assertEqual(saved["main_head"], main)
            self.assertEqual(saved["cutoff"], cutoff)


if __name__ == "__main__":
    unittest.main(verbosity=2)
