#!/usr/bin/env python3
"""Unit tests for stable_maintenance.py (standard library only)."""

from __future__ import annotations

import datetime as dt
import io
import importlib.util
import json
import os
import shlex
import stat
import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("stable_maintenance.py")
DOCKERFILE = SCRIPT.parent.parent / "stable-maintenance.Dockerfile"
ORPHAN_FIXTURE_FAILURE = "grandchild {orphan} survived the process-group kill"
WORKFLOW = SCRIPT.parent.parent / "workflows" / "stable-maintenance.yml"
SPEC = importlib.util.spec_from_file_location("stable_maintenance", SCRIPT)
assert SPEC and SPEC.loader
sm = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = sm
SPEC.loader.exec_module(sm)


# cargo-vet 0.10.2 JsonReport with suggestions disabled by --locked.
VET_SUCCESS = json.dumps({
    "conclusion": "success", "vetted_fully": [],
    "vetted_partially": [], "vetted_with_exemptions": [],
})
VET_LOCKED_FAILURE = json.dumps({
    "conclusion": "fail (vetting)",
    "failures": [{"name": "example", "version": "1.0.0", "missing_criteria": ["safe-to-deploy"]}],
    "suggest": None,
})
VET_CHECK_REPORT = json.dumps({
    "conclusion": "fail (vetting)",
    "failures": [{"name": "example", "version": "1.0.0", "missing_criteria": ["safe-to-deploy"]}],
    "suggest": {"suggestions": [{
        "name": "example", "suggested_criteria": ["safe-to-deploy"],
        "suggested_diff": {"from": "0.9.0", "to": "1.0.0"},
    }]},
})

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

    def test_registry_cache_grants_read_access_without_write_or_file_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "registry"; registry.mkdir(mode=0o300)
            source = registry / "src"; source.mkdir(mode=0o300)
            code = source / "lib.rs"; code.write_text("public crate source")
            code.chmod(0o200)
            executable = source / "configure"; executable.write_text("script")
            executable.chmod(0o300)
            original_open = sm.os.open
            def permission_aware_open(path, flags, *args, **kwargs):
                if (flags & os.O_ACCMODE) == os.O_RDONLY and not flags & os.O_PATH:
                    if str(path).startswith("/proc/self/fd/"):
                        metadata = os.stat(path)
                    else:
                        metadata = os.stat(path, dir_fd=kwargs.get("dir_fd"), follow_symlinks=False)
                    if stat.S_IMODE(metadata.st_mode) & 0o444 == 0:
                        raise PermissionError(13, "simulated runner access denial")
                return original_open(path, flags, *args, **kwargs)
            with mock.patch.object(sm.os, "open", side_effect=permission_aware_open):
                sm.make_registry_cache_readable(registry)
            self.assertEqual(registry.stat().st_mode & 0o777, 0o755)
            self.assertEqual(source.stat().st_mode & 0o777, 0o755)
            self.assertEqual(code.stat().st_mode & 0o777, 0o644)
            self.assertEqual(executable.stat().st_mode & 0o777, 0o744)
            self.assertEqual(code.read_text(), "public crate source")

    def test_registry_cache_rejects_links_and_special_files_without_touching_destination(self):
        for kind in ("symlink", "directory-symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                registry = Path(tmp) / "registry"; registry.mkdir()
                outside = Path(tmp) / "outside"; outside.write_text("private")
                outside.chmod(0o600)
                entry = registry / "unsafe"
                if kind == "symlink": entry.symlink_to(outside)
                elif kind == "directory-symlink": entry.symlink_to(Path(tmp), target_is_directory=True)
                elif kind == "hardlink": os.link(outside, entry)
                else: os.mkfifo(entry)
                with self.assertRaises(sm.MaintenanceError):
                    sm.make_registry_cache_readable(registry)
                self.assertEqual(outside.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.getuid() == 0, "requires root to reproduce a different build UID")
    def test_registry_source_is_readable_by_actual_build_uid(self):
        def build_user():
            os.setgroups([]); os.setgid(65532); os.setuid(65532)
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o755)
            registry = Path(tmp) / "registry"; registry.mkdir(mode=0o700)
            code = registry / "lib.rs"; code.write_text("public crate source")
            code.chmod(0o600)
            # The running Python may live under a root-only pyenv directory.
            # Use system tools the dropped UID can execute to probe file access.
            command = ["/bin/cat", str(code)]
            try:
                denied = sm.subprocess.run(command, preexec_fn=build_user, capture_output=True, text=True, env={"LC_ALL": "C"})
            except sm.subprocess.SubprocessError:
                self.skipTest("environment denies changing UID/GID despite UID 0")
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("Permission denied", denied.stderr)
            sm.make_registry_cache_readable(registry)
            readable = sm.subprocess.run(command, preexec_fn=build_user, capture_output=True, text=True, env={"LC_ALL": "C"})
            self.assertEqual(readable.returncode, 0, readable.stderr)
            self.assertEqual(readable.stdout.strip(), "public crate source")
            command = ["/bin/sh", "-c", "printf '%s' changed > \"$1\"", "sh", str(code)]
            denied_write = sm.subprocess.run(command, preexec_fn=build_user, capture_output=True, text=True, env={"LC_ALL": "C"})
            self.assertNotEqual(denied_write.returncode, 0)
            self.assertEqual(code.read_text(), "public crate source")

    def test_registry_cache_os_errors_are_safe_and_close_descriptors(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "registry"; registry.mkdir()
            code = registry / "lib.rs"; code.write_text("source"); code.chmod(0o600)
            original_open = sm.os.open
            for error in (OSError(40, "secret-path"), FileNotFoundError(2, "secret-path")):
                opened = []
                def replaced_entry(path, *args, **kwargs):
                    if path == "lib.rs": raise error
                    fd = original_open(path, *args, **kwargs); opened.append(fd); return fd
                with self.subTest(error=type(error).__name__), mock.patch.object(sm.os, "open", side_effect=replaced_entry):
                    with self.assertRaises(sm.MaintenanceError) as raised:
                        sm.make_registry_cache_readable(registry)
                self.assertNotIn("secret-path", str(raised.exception))
                self.assertIs(raised.exception.__cause__, error)
                self.assertEqual(code.stat().st_mode & 0o777, 0o600)
                for fd in opened:
                    with self.assertRaises(OSError): os.fstat(fd)
            with mock.patch.object(sm.os, "open", side_effect=PermissionError(13, "secret-path")), \
                 self.assertRaises(sm.MaintenanceError):
                sm.make_registry_cache_readable(registry)

    def test_registry_cache_depth_limit_is_checked_and_closes_every_descriptor(self):
        original_open = sm.os.open
        for depth in (128, 129):
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as tmp:
                registry = Path(tmp) / "registry"; registry.mkdir(mode=0o700)
                leaf = registry
                for _ in range(depth):
                    leaf = leaf / "d"; leaf.mkdir(mode=0o700)
                code = leaf / "secret-marker.rs"; code.write_text("source"); code.chmod(0o600)
                opened = []
                def tracked_open(*args, **kwargs):
                    fd = original_open(*args, **kwargs); opened.append(fd); return fd
                with mock.patch.object(sm.os, "open", side_effect=tracked_open):
                    if depth == 128:
                        sm.make_registry_cache_readable(registry)
                        self.assertEqual(code.stat().st_mode & 0o777, 0o644)
                    else:
                        with self.assertRaisesRegex(sm.MaintenanceError, "depth") as raised:
                            sm.make_registry_cache_readable(registry)
                        self.assertNotIn("secret-marker", str(raised.exception))
                        self.assertEqual(code.stat().st_mode & 0o777, 0o600)
                        self.assertEqual(leaf.stat().st_mode & 0o777, 0o700)
                for fd in opened:
                    with self.assertRaises(OSError): os.fstat(fd)

    @unittest.skipUnless(os.getuid() == 0, "root-only UID probe")
    def test_build_uid_probe_does_not_execute_private_python(self):
        results = [
            sm.CommandResult(1, "", "Permission denied"),
            sm.CommandResult(0, "public crate source\n", ""),
            sm.CommandResult(1, "", "Permission denied"),
        ]
        with mock.patch.object(sm.sys, "executable", "/root/private/python"), \
             mock.patch.object(sm.subprocess, "run", side_effect=results) as run:
            self.test_registry_source_is_readable_by_actual_build_uid()
        self.assertEqual([call.args[0][0] for call in run.call_args_list], ["/bin/cat", "/bin/cat", "/bin/sh"])

    def test_locked_build_command_has_security_boundaries(self):
        engines = {"podman": "/usr/bin/podman", "docker": "/usr/bin/docker"}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            sm.shutil, "which", side_effect=engines.get,
        ) as which:
            source = Path(tmp) / "source"; source.mkdir()
            cargo_home = Path(tmp) / "project-cargo-home"
            cargo_home.mkdir(parents=True, exist_ok=True)
            (source / ".git").mkdir()
            (cargo_home / "registry").mkdir()
            private_source = cargo_home / "registry" / "lib.rs"
            private_source.write_text("public source")
            private_source.chmod(0o600)
            (cargo_home / "git").mkdir()
            runner = mock.Mock(root=source.resolve())
            runner.run.return_value = sm.CommandResult(0, "", "")
            env = {
                "MAINTENANCE_BUILD_IMAGE": "registry.example/build@sha256:abc",
                "MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home),
            }
            with mock.patch.dict(os.environ, env):
                sm.locked_build(runner, target_dir=Path(tmp) / "target")
            self.assertEqual(private_source.stat().st_mode & 0o777, 0o644)
            which.assert_called_once_with("docker")
            argv = runner.run.call_args_list[0].args[0]
            self.assertEqual(runner.run.call_args_list[0].kwargs["max_output"], sm.MAX_BUILD_OUTPUT_BYTES)
            joined = " ".join(argv)
            self.assertIn("--network=none", argv)
            self.assertEqual(argv.count("--init"), 1)
            self.assertIn("--cap-drop=ALL", argv)
            self.assertIn("--security-opt=no-new-privileges", argv)
            self.assertIn("/workspace:ro", joined)
            self.assertIn(f"{(source / '.git').resolve()}:/workspace/.git:ro", joined)
            self.assertIn("/target:rw,nosuid,nodev,exec,size=6g", argv)
            self.assertIn("/workspace/target:rw,nosuid,nodev,noexec,size=64m,mode=1777", argv)
            self.assertTrue((source / "target").is_dir())
            self.assertEqual(list((source / "target").iterdir()), [])
            self.assertIn("/tmp:rw,nosuid,nodev,noexec,size=1g", argv)
            self.assertNotIn(f"{Path(tmp) / 'target'}:/target", joined)
            self.assertNotIn("/home/runner/.cargo", joined)
            self.assertNotIn("/home/runner/.rustup", joined)
            self.assertIn("/opt/project-cargo:rw,nosuid,nodev,size=16m", joined)
            self.assertIn(f"{(cargo_home / 'registry').resolve()}:/opt/project-cargo/registry:ro", joined)
            self.assertIn(f"{(cargo_home / 'git').resolve()}:/opt/project-cargo/git:ro", joined)
            self.assertNotIn(f"{cargo_home.resolve()}:/opt/project-cargo:ro", joined)
            self.assertIn("CARGO_HOME=/opt/project-cargo", argv)
            self.assertIn("HOME=/tmp", argv)
            self.assertIn("XDG_CACHE_HOME=/tmp", argv)
            self.assertIn("RUSTUP_HOME=/usr/local/rustup", argv)
            self.assertIn("PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", argv)
            self.assertIn("O365_GEN_DIR=/target/o365-generated", argv)
            self.assertIn("CARGO_PROFILE_DEV_DEBUG=0", argv)
            self.assertIn("CARGO_PROFILE_TEST_DEBUG=0", argv)
            self.assertIn("CARGO_INCREMENTAL=0", argv)
            self.assertIn(sm.BUILD_RESOURCE_PROBE, argv)
            self.assertEqual(argv[-9:], ["python3", "-I", "-c", sm.BUILD_RESOURCE_PROBE,
                             "cargo", "build", "--workspace", "--locked", "--message-format=json"])
            for limit in ("65532:65532", "--pids-limit=512", "--cpus=4", "--memory=8g", "--memory-swap=8g"):
                self.assertIn(limit, argv)
            self.assertNotIn("AZURE", joined)
            self.assertNotIn("GITHUB_TOKEN", joined)
            cleanup = runner.run.call_args_list[-1].args[0]
            self.assertEqual(cleanup[:3], ["/usr/bin/docker", "rm", "-f"])
            self.assertRegex(cleanup[3], r"^himmelblau-maint-[0-9a-f]{16}$")

    @unittest.skipUnless(os.environ.get("MAINTENANCE_CONTAINER_TESTS") == "1",
                         "requires the built maintenance Docker image")
    def test_generated_assets_build_in_read_only_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"; source.mkdir()
            (source / ".git").mkdir()
            (source / "src").mkdir()
            (source / "src/lib.rs").write_text(
                '#[cfg(not(debug_assertions))]\ncompile_error!("dev assertions disabled");\n'
                'pub fn fixture() {}\n'
                '#[test]\n#[should_panic]\nfn overflow_checks_remain_enabled() {\n'
                '    let _ = std::hint::black_box(u32::MAX) + std::hint::black_box(1);\n}\n')
            with (source / "src/lib.rs").open("a") as handle:
                handle.write("""
#[test]
fn killed_orphan_is_reaped() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 300 & echo $!; wait"])
        .process_group(0)
        .stdout(Stdio::piped())
        .spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let orphan: i32 = line.trim().parse().unwrap();
    // Kill both the shell and its child, just like the compliance timeout.
    assert_eq!(unsafe { kill(-(child.id() as i32), 9) }, 0);
    child.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if unsafe { kill(orphan, 0) } != 0 { return; }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("__ORPHAN_FAILURE__");
}
""".replace("__ORPHAN_FAILURE__", ORPHAN_FIXTURE_FAILURE))
            (source / "Cargo.toml").write_text(
                '[package]\nname = "asset-mount-fixture"\nversion = "0.1.0"\nedition = "2021"\n')
            (source / "Cargo.lock").write_text(
                'version = 3\n\n[[package]]\nname = "asset-mount-fixture"\nversion = "0.1.0"\n')
            (source / "build.rs").write_text("""
fn main() {
    assert_eq!(std::env::var("DEBUG").unwrap(), "false");
    assert_eq!(std::env::var("OPT_LEVEL").unwrap(), "0");
    assert_eq!(std::env::var("CARGO_INCREMENTAL").unwrap(), "0");
    let output = "target/release/qr-greeter-build";
    std::fs::create_dir_all(output).unwrap();
    std::fs::write(format!("{output}/asset"), "generated").unwrap();
    assert_eq!(std::fs::read_to_string(format!("{output}/asset")).unwrap(), "generated");
    assert!(std::fs::write("source-sentinel", "changed").is_err());
    assert!(std::fs::write(".git/sentinel", "changed").is_err());
}
""")
            for path in (source / "source-sentinel", source / ".git/sentinel"):
                path.write_text("unchanged"); path.chmod(0o666)
            # Existing host output must also be obscured by disposable storage.
            (source / "target").mkdir()
            (source / "target/host-sentinel").write_text("unchanged")
            cargo_home = Path(tmp) / "cargo-home"; cargo_home.mkdir()
            (cargo_home / "registry").mkdir()
            runner = sm.Runner(source.resolve(), os.environ)
            with mock.patch.dict(os.environ, {"MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home)}):
                result = sm.locked_build(runner)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
            profiles = [item["profile"] for item in artifacts if item.get("reason") == "compiler-artifact"]
            self.assertTrue(profiles)
            for profile in profiles:
                self.assertIn(profile["debuginfo"], (None, 0))
                self.assertEqual(profile["opt_level"], "0")
                self.assertTrue(profile["debug_assertions"])
                self.assertTrue(profile["overflow_checks"])
            # The final test gate compiles in its own fresh /target tmpfs, too.
            with mock.patch.dict(os.environ, {"MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home)}):
                tests = sm.locked_tests(runner)
            self.assertEqual(tests.returncode, 0, tests.stderr)
            self.assertIn("2 passed", tests.stdout)
            self.assertEqual((source / "source-sentinel").read_text(), "unchanged")
            self.assertEqual((source / ".git/sentinel").read_text(), "unchanged")
            self.assertEqual((source / "target/host-sentinel").read_text(), "unchanged")
            self.assertEqual(list((source / "target").iterdir()), [source / "target/host-sentinel"])
            # Exercise real libtest/Cargo failure output without logging its payload.
            with (source / "src/lib.rs").open("a") as handle:
                handle.write('#[test]\nfn intentional_failure() { panic!("SECRET_TEST_PAYLOAD"); }\n')
            with mock.patch.dict(os.environ, {"MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home)}), \
                 mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                failure = sm.locked_tests(runner)
            self.assertEqual(failure.returncode, 101)
            report_line = next(line for line in output.getvalue().splitlines() if line.startswith("test-diagnostics: "))
            diagnostic = json.loads(report_line.removeprefix("test-diagnostics: "))
            self.assertTrue(any(target["kind"] == "lib" for target in diagnostic["failed_targets"]))
            self.assertEqual(diagnostic["summaries"][0]["failed"], 1)
            self.assertIn("target_free_bytes", diagnostic["resources"])
            self.assertNotIn("SECRET_TEST_PAYLOAD", output.getvalue())
            self.assertIn('"oom_killed":false', output.getvalue())
            # Exercise the real Cargo/rustc JSON linker error format, too.
            (source / "src/lib.rs").unlink()
            (source / "src/main.rs").write_text("fn main() {}\n")
            (source / "build.rs").write_text(
                'fn main() { println!("cargo:rustc-link-lib=maintenance_missing_fixture"); }\n')
            with mock.patch.dict(os.environ, {"MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home)}), \
                 mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                failure = sm.locked_build(runner)
            self.assertNotEqual(failure.returncode, 0)
            diagnostic = json.loads(output.getvalue().splitlines()[0].removeprefix("build-diagnostics: "))
            self.assertIn("maintenance_missing_fixture", diagnostic["missing_libraries"])
            self.assertTrue(any(x["crate"] == "asset-mount-fixture" and "bin" in x["kind"]
                                for x in diagnostic["compiler_errors"]))
            self.assertIn("target_free_bytes", diagnostic["resources"])
            self.assertEqual((source / "source-sentinel").read_text(), "unchanged")
            self.assertEqual((source / ".git/sentinel").read_text(), "unchanged")
            self.assertEqual((source / "target/host-sentinel").read_text(), "unchanged")

    def test_generated_assets_mount_rejects_unsafe_host_mountpoints(self):
        for kind in ("file", "symlink", "dangling-symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "source"; source.mkdir()
                (source / ".git").mkdir()
                cargo_home = Path(tmp) / "cargo-home"; cargo_home.mkdir()
                (cargo_home / "registry").mkdir()
                outside = Path(tmp) / "outside"; outside.mkdir()
                marker = outside / "marker"; marker.write_text("unchanged")
                target = source / "target"
                if kind == "file":
                    target.write_text("unchanged")
                elif kind == "symlink":
                    target.symlink_to(outside, target_is_directory=True)
                else:
                    target.symlink_to(Path(tmp) / "missing", target_is_directory=True)
                runner = mock.Mock(root=source.resolve())
                runner.run.return_value = sm.CommandResult(0, "", "")
                env = {
                    "MAINTENANCE_BUILD_IMAGE": "build:local",
                    "MAINTENANCE_PROJECT_CARGO_HOME": str(cargo_home),
                }
                with mock.patch.dict(os.environ, env), mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
                    with self.assertRaisesRegex(sm.MaintenanceError, "target mountpoint"):
                        sm.locked_build(runner)
                runner.run.assert_not_called()
                self.assertEqual(marker.read_text(), "unchanged")
                if kind == "file":
                    self.assertEqual(target.read_text(), "unchanged")
                else:
                    self.assertTrue(target.is_symlink())

    def test_failed_build_reports_bounded_hints_without_raw_output(self):
        secret = "secret-token-do-not-log"
        failures = (
            (101, f"error: Permission denied: /opt/project-cargo/registry/{secret}",
             "hints=permission-denied paths=project-cache rust_codes=none"),
            (101, f"error: Read-only file system: /workspace/{secret}",
             "hints=read-only-filesystem paths=source rust_codes=none"),
            (101, f"error: no matching package named `{secret}` found", "hints=offline-cache-miss"),
            (101, "error: lock file needs to be updated but --locked was passed", "hints=lockfile-needs-update"),
            (101, f"No space left on device: /target/{secret}", "hints=no-space paths=target"),
            (101, f"failed to run custom build command for `{secret}`", "hints=build-script-failed"),
            (101, f"error[E0308]: {secret}\nerror[E0308]: duplicate\ncould not compile", "rust_codes=E0308"),
            (125, f"Cannot connect to the Docker daemon at https://{secret}", "hints=docker-daemon"),
            (126, f"OCI runtime create failed: {secret}", "hints=container-start"),
            (137, f"::error::{secret}\x1b[31m", "hints=unclassified paths=unknown rust_codes=none"),
        )
        for exit_code, stderr, expected in failures:
            with self.subTest(stderr=expected), mock.patch.object(sm, "contained_repo_command") as command:
                result = sm.CommandResult(exit_code, f"::error::{secret}", stderr)
                command.return_value = result
                output = io.StringIO()
                with mock.patch.object(sm.sys, "stderr", output):
                    self.assertIs(sm.locked_build(mock.Mock()), result)
                diagnostic = output.getvalue()
                self.assertIn(f"build-debug: exit={exit_code}", diagnostic)
                self.assertIn(expected, diagnostic)
                self.assertNotIn(secret, diagnostic)
                self.assertNotIn("::error::", diagnostic)
                self.assertNotIn("\x1b", diagnostic)
                self.assertEqual(len(diagnostic.splitlines()), 2)
                self.assertLess(len(diagnostic), 1200)
                self.assertEqual(command.call_args.args[1], ["cargo", "build", "--workspace", "--locked", "--message-format=json"])
                self.assertEqual(command.call_args.kwargs, {
                    "network": False, "source_rw": False, "cache_rw": False, "check": False,
                })
        output = io.StringIO()
        with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, secret, secret)), \
             mock.patch.object(sm.sys, "stderr", output):
            sm.locked_build(mock.Mock())
        self.assertEqual(output.getvalue(), "")
        output = io.StringIO()
        stderr = "\n".join(f"error[E{number:04d}]: {secret}" for number in range(20))
        with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(101, "", stderr)), \
             mock.patch.object(sm.sys, "stderr", output):
            sm.locked_build(mock.Mock())
        self.assertIn("rust_codes=" + ",".join(f"E{number:04d}" for number in range(8)), output.getvalue())
        self.assertNotIn("E0008", output.getvalue())
        self.assertNotIn(secret, output.getvalue())

    def test_build_failure_identifies_operations_without_echoing_output(self):
        secret = "secret-token-do-not-log"
        cases = (
            (f"error: couldn't read /opt/project-cargo/registry/src/{secret}: Permission denied (os error 13)",
             "operations=read-file permission_paths=project-cache os_errors=13"),
            (f"error: could not execute process `rustc /workspace/{secret} /opt/project-cargo/{secret}` (never executed)\nCaused by:\n  Permission denied (os error 13)",
             "operations=start-process permission_paths=unknown os_errors=13"),
            (f"error: linking with `cc` failed: exit status: 1\ncc: /tmp/{secret}: Permission denied",
             "operations=link permission_paths=temporary os_errors=none"),
            (f"error: failed to run custom build command for `{secret}`\nfailed to open /workspace/{secret}: Permission denied (os error 13)",
             "operations=run-build-script,open-file permission_paths=source os_errors=13"),
            (f"failed to create temporary file /target/{secret}: Permission denied (os error 13)",
             "operations=create-temporary-file permission_paths=target os_errors=13"),
            (f"{secret}: failed to map segment from shared object: Operation not permitted (os error 1)",
             "operations=load-library permission_paths=unknown os_errors=1"),
            (f"::error::{secret}\x1b[31m", "operations=unknown permission_paths=unknown os_errors=none"),
        )
        for stderr, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(
                sm, "contained_repo_command", return_value=sm.CommandResult(101, secret, stderr),
            ), mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                sm.locked_build(mock.Mock())
                diagnostic = output.getvalue()
                self.assertIn(expected, diagnostic)
                self.assertNotIn(secret, diagnostic)
                self.assertNotIn("::error::", diagnostic)
                self.assertNotIn("\x1b", diagnostic)
                self.assertEqual(len(diagnostic.splitlines()), 2)
                self.assertLess(len(diagnostic), 1200)
        stderr = "\n".join(f"Permission denied (os error {number})" for number in range(20))
        with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(101, "", stderr)), \
             mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
            sm.locked_build(mock.Mock())
        self.assertIn("os_errors=0,1,2,3,4,5,6,7", output.getvalue())
        self.assertNotIn(",8", output.getvalue())

    def test_operation_not_permitted_is_a_permission_denied_hint(self):
        """EPERM-only failures use the same primary hint as EACCES."""
        stderr = "Operation not permitted (os error 1)"
        with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(101, "", stderr)), \
             mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
            sm.locked_build(mock.Mock())
        self.assertIn("hints=permission-denied ", output.getvalue())
        self.assertIn("permission_paths=unknown os_errors=1", output.getvalue())

    def test_permission_paths_require_an_explicit_denied_operand(self):
        """Only unambiguous diagnostic operands determine permission buckets."""
        secret = "secret-token-do-not-log"
        cases = (
            (f"could not execute process `rustc /workspace/{secret} /opt/project-cargo/{secret}`: Permission denied", "unknown"),
            (f"could not execute process `/usr/local/rustup/rustc /target/{secret}`: Operation not permitted", "unknown"),
            (f"failed to spawn `/tmp/{secret}`: Permission denied", "unknown"),
            (f'"/usr/local/rustup/rustc /workspace/{secret}": Permission denied', "unknown"),
            (f"rustc /workspace/{secret} --out-dir /target/{secret}: Permission denied", "unknown"),
            (f"error: failed to open /workspace/{secret}: Permission denied; command: /opt/project-cargo/{secret}", "unknown"),
            (f"Permission denied while running /target/{secret}", "unknown"),
            (f"error: couldn't read /elsewhere/workspace/{secret}: Permission denied", "unknown"),
            (f"failed to open /target-other/{secret}: Permission denied", "unknown"),
            (f"error: couldn't read /workspace/{secret}/opt/project-cargo/file: Permission denied", "source"),
            (f"error: couldn't read '/opt/project-cargo/{secret} with spaces': Permission denied (os error 13)", "project-cache"),
            (f'failed to open "/workspace/{secret} with spaces": Permission denied', "source"),
            (f"unable to open `/target/{secret}`: Operation not permitted (os error 1)", "target"),
            (f"cc: /tmp/{secret}: Permission denied", "temporary"),
            (f"error: could not read /usr/local/rustup/{secret}: Permission denied", "toolchain"),
            (f"/opt/project-cargo/{secret}: failed to map segment from shared object: Operation not permitted", "project-cache"),
            (f"/tmp/{secret}: Permission denied\nfailed to open /workspace/{secret}: Permission denied", "source,temporary"),
            (f"error: couldn't read /workspace/{secret}: Permission denied\n::error::{secret}\x1b[31m /target/{secret}", "source"),
        )
        for stderr, expected in cases:
            with self.subTest(stderr=stderr), mock.patch.object(
                sm, "contained_repo_command", return_value=sm.CommandResult(101, secret, stderr),
            ), mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                sm.locked_build(mock.Mock())
                diagnostic = output.getvalue()
                self.assertIn(f"permission_paths={expected} ", diagnostic)
                self.assertIn("hints=permission-denied ", diagnostic)
                self.assertNotIn(secret, diagnostic)
                self.assertNotIn("::error::", diagnostic)
                self.assertNotIn("\x1b", diagnostic)
                self.assertEqual(len(diagnostic.splitlines()), 2)
                self.assertLess(len(diagnostic), 1200)

    def test_cargo_json_build_diagnostics_identify_linker_failure_and_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text('version = 3\n[[package]]\nname = "example"\nversion = "1.2.3"\n')
            message = {"reason": "compiler-message", "package_id": "registry+https://registry.invalid/index#example@1.2.3",
                       "target": {"name": "example", "kind": ["bin"], "src_path": "/workspace/src/main.rs"},
                       "message": {"level": "error", "message": "linking with `cc` failed: exit status: 1",
                                   "code": None, "spans": [], "rendered": "::error::SECRET_RENDERED",
                                   "children": [{"message": "cc SECRET_ARGUMENT /SECRET/PATH"},
                                                {"message": "rust-lld: error: unable to find library -lkrb5\nrust-lld: error: undefined symbol: krb5_init_context"}]}}
            stdout = "\n".join(json.dumps(x) for x in (
                {"reason": "compiler-artifact"}, {"reason": "build-script-executed", "env": [["TOKEN", "SECRET_ENV"]]},
                message, {"reason": "maintenance-resources", "resources": {"memory_oom_kill": 1, "target_free_bytes": 123, "TOKEN": "SECRET_ENV"}}))
            result = sm.CommandResult(101, stdout, "could not compile example")
            with mock.patch.object(sm, "contained_repo_command", return_value=result), \
                 mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                self.assertIs(sm.locked_build(mock.Mock(root=root)), result)
            report = json.loads(output.getvalue().splitlines()[0].removeprefix("build-diagnostics: "))
            self.assertEqual(report["compiler_errors"][0], {"crate": "example", "version": "1.2.3", "target": "example",
                "kind": ["bin"], "source": "src/main.rs", "code": "none", "locations": []})
            self.assertEqual(report["missing_libraries"], ["krb5"])
            self.assertEqual(report["undefined_symbols"], ["krb5_init_context"])
            self.assertEqual(report["linker_causes"], ["missing-library", "undefined-symbol"])
            self.assertEqual(report["resources"], {"memory_oom_kill": 1, "target_free_bytes": 123})
            self.assertEqual((report["completed_artifacts"], report["completed_build_scripts"]), (1, 1))
            self.assertIn("operations=link", output.getvalue())
            self.assertNotIn("SECRET", output.getvalue())
            self.assertNotIn("::error::", output.getvalue())

    def test_cargo_json_diagnostics_are_bounded_and_reject_unsafe_fields(self):
        item = {"reason": "compiler-message", "package_id": "file:///workspace/example#1.2.3",
                "target": {"name": "::error::TOKEN\n", "kind": ["bin", "::error::TOKEN"], "src_path": "../../TOKEN"},
                "message": {"level": "error", "code": {"code": "E0308"}, "message": "TOKEN\x1b[31m",
                            "spans": [{"file_name": "src/main.rs", "line_start": 12, "column_start": 3, "text": ["TOKEN"]},
                                      {"file_name": "https://TOKEN", "line_start": 1, "column_start": 1}], "children": None}}
        malformed = ['not JSON TOKEN', '{broken', '[]', '{"reason":"compiler-message","message":null}',
                     '{"reason":"compiler-message","message":{"level":"error"},"target":null}']
        result = sm.CommandResult(101, "\n".join([*malformed, *[json.dumps(item) for _ in range(20)]]),
                                  "undefined reference to `::error::TOKEN'\nNo space left on device\nBus error")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
            root = Path(tmp)
            (root / "Cargo.lock").write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            sm.report_build_diagnostics(result, root)
        report = json.loads(output.getvalue().removeprefix("build-diagnostics: "))
        self.assertEqual(len(report["compiler_errors"]), 8)
        self.assertEqual(report["compiler_errors"][0]["crate"], "example")
        self.assertEqual(report["compiler_errors"][0]["code"], "E0308")
        self.assertEqual(report["compiler_errors"][0]["locations"], ["src/main.rs:12:3"])
        self.assertEqual(report["compiler_errors"][0]["target"], "unknown")
        self.assertIn("bus-error", report["linker_causes"])
        self.assertIn("no-space", report["linker_causes"])
        self.assertNotIn("TOKEN", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertLess(len(output.getvalue()), 6000)

    def test_failed_build_script_names_are_checked_against_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
            root = Path(tmp)
            (root / "Cargo.lock").write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            sm.report_build_diagnostics(sm.CommandResult(101, "", "failed to run custom build command for `example v1.2.3`\n"
                "failed to run custom build command for `SECRET v1.2.3`\nthread 'main' panicked at /workspace/src/example/build.rs:12:7:\nSECRET"), root)
        report = json.loads(output.getvalue().removeprefix("build-diagnostics: "))
        self.assertEqual(report["failed_build_scripts"], ["example"])
        self.assertEqual(report["panic_locations"], ["src/example/build.rs:12:7"])
        self.assertNotIn("SECRET", output.getvalue())

    def test_build_resource_probe_preserves_exit_and_captures_before_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = sm.Runner(Path(tmp), os.environ)
            # A checkout-local module must not intercept the trusted probe.
            (Path(tmp) / "json.py").write_text('raise RuntimeError("untrusted checkout module")\n')
            result = runner.run([sys.executable, "-I", "-c", sm.BUILD_RESOURCE_PROBE, sys.executable, "-c",
                                 'import sys; print("cargo output"); print("cargo error", file=sys.stderr); sys.exit(7)'], check=False)
        self.assertEqual(result.returncode, 7)
        self.assertIn("cargo output", result.stdout)
        self.assertIn("cargo error", result.stderr)
        resource = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(resource["reason"], "maintenance-resources")
        self.assertIn("temporary_free_bytes", resource["resources"])

    def test_large_cargo_json_build_keeps_exit_status_and_diagnostics(self):
        """Successful and failed builds can exceed the ordinary 4 MiB budget."""
        producer = '''
import json, sys
artifact = json.dumps({"reason": "compiler-artifact", "padding": "x" * 1024})
for _ in range(5000):
    print(artifact)
if int(sys.argv[1]):
    print(json.dumps({"reason": "compiler-message", "package_id": "file:///workspace/example#1.2.3",
                     "target": {"name": "example", "kind": ["bin"], "src_path": "/workspace/src/main.rs"},
                     "message": {"level": "error", "message": "linking with `cc` failed",
                                 "children": [{"message": "cannot find -lfixture_missing: No such file"}]}}))
sys.exit(int(sys.argv[1]))
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir(); (root / ".git").mkdir()
            (root / "Cargo.lock").write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            cache = Path(tmp) / "cache"; cache.mkdir(); (cache / "registry").mkdir()
            real = sm.Runner(root.resolve(), os.environ)
            with self.assertRaisesRegex(sm.MaintenanceError, "output exceeded limit"):
                real.run([sys.executable, "-I", "-c", producer, "0"], check=False)
            env = {"MAINTENANCE_BUILD_IMAGE": "image@sha256:abc", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache)}
            for status in (0, 101):
                def run(argv, **kwargs):
                    if argv[1] == "rm":
                        return sm.CommandResult(0, "", "")
                    return real.run([sys.executable, "-I", "-c", producer, str(status)], **kwargs)
                runner = mock.Mock(root=root.resolve())
                runner.run.side_effect = run
                with self.subTest(status=status), mock.patch.dict(os.environ, env), \
                     mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"), \
                     mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                    result = sm.locked_build(runner)
                    self.assertEqual(result.returncode, status)
                    self.assertGreater(len(result.stdout), 4 * 1024 * 1024)
                    if status:
                        report = json.loads(output.getvalue().splitlines()[0].removeprefix("build-diagnostics: "))
                        self.assertEqual(report["completed_artifacts"], 5000)
                        self.assertEqual(report["compiler_errors"][0]["crate"], "example")
                        self.assertEqual(report["missing_libraries"], ["fixture_missing"])
                    else:
                        self.assertEqual(output.getvalue(), "")
            # Other contained commands retain the existing output limit.
            runner.run.side_effect = None
            runner.run.return_value = sm.CommandResult(0, "", "")
            runner.run.reset_mock()
            with mock.patch.dict(os.environ, env), mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
                sm.contained_repo_command(runner, ["cargo", "metadata"], network=False, source_rw=False, cache_rw=False)
            self.assertEqual(runner.run.call_args_list[0].kwargs["max_output"], 4 * 1024 * 1024)

    def test_disposable_build_settings_are_scoped_and_not_inherited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir(); (root / ".git").mkdir()
            cache = Path(tmp) / "cache"; cache.mkdir(); (cache / "registry").mkdir()
            runner = mock.Mock(root=root.resolve())
            runner.run.return_value = sm.CommandResult(0, "", "")
            env = {
                "MAINTENANCE_BUILD_IMAGE": "build:local",
                "MAINTENANCE_PROJECT_CARGO_HOME": str(cache),
                "CARGO_PROFILE_DEV_DEBUG": "2", "CARGO_PROFILE_TEST_DEBUG": "2",
                "CARGO_INCREMENTAL": "1",
            }
            for command, expected in (
                (["cargo", "build", "--workspace", "--locked", "--message-format=json"],
                 ["CARGO_PROFILE_DEV_DEBUG=0", "CARGO_PROFILE_TEST_DEBUG=0", "CARGO_INCREMENTAL=0"]),
                (["cargo", "test", "--workspace", "--locked"],
                 ["CARGO_PROFILE_DEV_DEBUG=0", "CARGO_PROFILE_TEST_DEBUG=0", "CARGO_INCREMENTAL=0"]),
                (["cargo", "metadata"], []),
                (["cargo", "vet", "--locked", "--frozen"], []),
                (["cargo", "build", "--release"], []),
                (["crate2nix", "generate"], []),
            ):
                with self.subTest(command=command), mock.patch.dict(os.environ, env), \
                     mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
                    runner.run.reset_mock()
                    sm.contained_repo_command(runner, command, network=False, source_rw=False, cache_rw=False)
                argv = runner.run.call_args_list[0].args[0]
                settings = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "-e"
                            and argv[i + 1].startswith(("CARGO_PROFILE_", "CARGO_INCREMENTAL"))]
                self.assertEqual(settings, expected)

    def test_failed_tests_report_only_verified_crates_and_fixed_fields(self):
        secret = "SECRET_TOKEN_credential"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            result = sm.CommandResult(101,
                f"test {secret} ... FAILED\nfailures:\nthread '{secret}' panicked at src/lib.rs:1:2:\n"
                f"assertion failed: {secret}\n::error::{secret}\x1b[31m\r\n"
                "test result: FAILED. 10 passed; 2 failed; 1 ignored; 0 measured; 3 filtered out; finished in 0.01s\n"
                + json.dumps({"reason": "maintenance-resources", "resources": {
                    "target_free_bytes": 42, "memory_oom_kill": 0, "memory_oom": True,
                    "memory_max": -1, "assets_free_bytes": 2**63, "TOKEN": secret}}),
                f"error: test failed, to rerun pass -p example --lib\n"
                f"error: test failed, to rerun pass -p {secret} --test {secret}\n")
            with mock.patch.object(sm, "contained_repo_command", return_value=result) as command, \
                 mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                self.assertIs(sm.locked_tests(mock.Mock(root=root)), result)
            report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
            self.assertEqual(report["exit"], 101)
            self.assertEqual(report["capture"], "complete")
            self.assertEqual(report["failed_targets"], [{"crate": "example", "kind": "lib"},
                                                      {"crate": "unknown", "kind": "test"}])
            self.assertEqual(report["summaries"], [{"passed": 10, "failed": 2, "ignored": 1, "measured": 0, "filtered": 3}])
            self.assertEqual(report["resources"], {"target_free_bytes": 42, "memory_oom_kill": 0})
            self.assertEqual(report["hints"], ["test-failed", "panic", "assertion-failed"])
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn("::error::", output.getvalue())
            self.assertNotIn("\x1b", output.getvalue())
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertEqual(command.call_args.args[1], ["cargo", "test", "--workspace", "--locked"])
            self.assertEqual(command.call_args.kwargs, {
                "network": False, "source_rw": False, "cache_rw": False, "timeout": 3600, "check": False})

    def test_cargo_rerun_arguments_require_matching_delimiters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            for arguments in ("-p example --lib", "`-p example --lib`", "'-p example --lib'", "`-p example@1.2.3 --test fixture`"):
                with self.subTest(arguments=arguments), mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                    sm.report_test_diagnostics(sm.CommandResult(101, "", "error: test failed, to rerun pass " + arguments), root)
                report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
                self.assertEqual(report["failed_targets"][0]["crate"], "example")
            with mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                sm.report_test_diagnostics(sm.CommandResult(101, "", "error: doctest failed, to rerun pass `-p example --doc`"), root)
            report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
            self.assertEqual(report["failed_targets"], [{"crate": "example", "kind": "doc"}])
            self.assertIn("doctest-failed", report["hints"])
            for arguments in ("`-p example --lib'", "'-p example --lib`", "`-p example --lib` SECRET", "`-p example --lib"):
                with self.subTest(arguments=arguments), mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                    sm.report_test_diagnostics(sm.CommandResult(101, "", "error: test failed, to rerun pass " + arguments), root)
                report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
                self.assertEqual(report["failed_targets"], [])

    def test_test_compilation_and_linker_causes_do_not_echo_operands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            cases = (
                ("error[E0308]: SECRET", [], ["E0308"]),
                ("linking with `SECRET` failed: cannot find -lSECRET", ["missing-library"], []),
                ("undefined reference to `SECRET'", ["undefined-symbol"], []),
                ("No space left on device: SECRET", ["no-space"], []),
                ("signal: 9, SIGKILL: kill SECRET", ["killed"], []),
                ("signal: 7, SIGBUS: SECRET", ["bus-error"], []),
                ("memory allocation failed: Cannot allocate memory SECRET", ["out-of-memory"], []),
            )
            for diagnostic, causes, codes in cases:
                stderr = (diagnostic + "\nerror: could not compile `example` (lib test) due to 1 previous error\n"
                          "error: could not compile `SECRET` (bin \"SECRET\") due to 2 previous errors\n")
                with self.subTest(diagnostic=diagnostic), mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                    sm.report_test_diagnostics(sm.CommandResult(101, "SECRET", stderr), root)
                report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
                self.assertEqual(report["compile_failed"], ["example"])
                self.assertEqual(report["causes"], causes)
                self.assertEqual(report["rust_codes"], codes)
                self.assertNotIn("SECRET", output.getvalue())

    def test_process_cleanup_diagnostics_do_not_echo_panic_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for message, expected in (
                (ORPHAN_FIXTURE_FAILURE.format(orphan=123456789), ["orphan-not-reaped"]),
                ("threads leaked across invocations: 123456789 -> 987654321", ["thread-count-increased"]),
                ("grandchild SECRET survived the process-group kill", []),
            ):
                with self.subTest(message=message), mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                    sm.report_test_diagnostics(sm.CommandResult(101, "", message + "\nSECRET"), root)
                report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
                self.assertEqual(report["hints"], expected)
                self.assertNotIn("123456789", output.getvalue())
                self.assertNotIn("987654321", output.getvalue())
                self.assertNotIn("SECRET", output.getvalue())

    def test_test_diagnostics_bound_output_and_handle_invalid_lockfiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packages = ["crate_" + str(index) + "x" * 80 for index in range(30)]
            (root / "Cargo.lock").write_text("\n".join(f'[[package]]\nname = "{name}"\nversion = "1.0.0"' for name in packages))
            stdout = "\n".join("test result: FAILED. 9999999 passed; 9999999 failed; 9999999 ignored; "
                               "9999999 measured; 9999999 filtered out; finished in 0.00s" for _ in range(30))
            stderr = "\n".join(f"error: test failed, to rerun pass -p {name} --lib\n"
                               f"error: could not compile `{name}` (lib test) due to 1 previous error\n"
                               f"error[E{index:04d}]: SECRET" for index, name in enumerate(packages))
            result = sm.CommandResult(101, stdout + "\n" + "SECRET" * 10000, stderr)
            with mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                sm.report_test_diagnostics(result, root)
            report = json.loads(output.getvalue().removeprefix("test-diagnostics: "))
            for field in ("failed_targets", "compile_failed", "rust_codes", "summaries"):
                self.assertEqual(len(report[field]), 8)
            self.assertNotIn("SECRET", output.getvalue())
            self.assertLess(len(output.getvalue().encode()), 4096)
            for invalid in ("not toml", "package = 5", "package = " + "[" * 600 + "0" + "]" * 600, "#" * (4 * 1024 * 1024 + 1)):
                (root / "Cargo.lock").write_text(invalid)
                with mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                    sm.report_test_diagnostics(result, root)
                self.assertNotIn(packages[0], output.getvalue())

    def test_test_capture_retains_bounded_tail_and_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = sm.Runner(Path(tmp))
            for status in (0, 101):
                for retain_tail in (False, True):
                    producer = f'import sys; print("START" + "x" * 10000 + "END"); sys.exit({status})'
                    with self.subTest(status=status, tail=retain_tail), self.assertRaises(sm.CommandCaptureError) as caught:
                        runner.run([sys.executable, "-I", "-c", producer], check=False,
                                   max_output=1024, retain_tail=retain_tail)
                    error = caught.exception
                    self.assertEqual(error.reason, "output-limit")
                    self.assertEqual(error.result.returncode, status)
                    self.assertLessEqual(len(error.result.stdout), 1025)
                    self.assertEqual("END" in error.result.stdout, retain_tail)
                    self.assertEqual("START" in error.result.stdout, not retain_tail)
            with self.assertRaises(sm.CommandCaptureError) as caught:
                runner.run([sys.executable, "-I", "-c", 'import time; print("partial", flush=True); time.sleep(30)'],
                           timeout=0.2, retain_tail=True)
            self.assertEqual(caught.exception.reason, "timeout")
            self.assertEqual(caught.exception.result.returncode, -9)
            self.assertIn("partial", caught.exception.result.stdout)

    def test_test_probe_precedes_cleanup_for_failure_timeout_and_overflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir(); (root / ".git").mkdir()
            cache = Path(tmp) / "cache"; cache.mkdir(); (cache / "registry").mkdir()
            env = {"MAINTENANCE_BUILD_IMAGE": "build:local", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache)}
            for outcome in ("failure", "timeout", "output-limit", "success"):
                with self.subTest(outcome=outcome):
                    result = sm.CommandResult(0 if outcome == "success" else 137, "SECRET", "SECRET")
                    failure = sm.CommandCaptureError("original capture failure", outcome, result)
                    calls = []
                    def run(argv, **kwargs):
                        calls.append((argv, kwargs))
                        if argv[1] == "run":
                            if outcome in ("timeout", "output-limit"):
                                raise failure
                            return result
                        if argv[1] == "inspect":
                            return sm.CommandResult(0, json.dumps({"OOMKilled": outcome == "failure", "Running": outcome == "timeout",
                                                                 "ExitCode": 137, "Error": "SECRET"}), "SECRET")
                        if argv[1] == "exec":
                            return sm.CommandResult(0, json.dumps({"reason": "maintenance-resources", "resources": {"target_free_bytes": 123}}), "SECRET")
                        return sm.CommandResult(0, "", "")
                    runner = mock.Mock(root=root); runner.run.side_effect = run
                    with mock.patch.dict(os.environ, env), mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"), \
                         mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                        if outcome in ("timeout", "output-limit"):
                            with self.assertRaises(sm.CommandCaptureError) as caught:
                                sm.locked_tests(runner)
                            self.assertIs(caught.exception, failure)
                            self.assertIn('"capture":"' + outcome + '"', output.getvalue())
                        else:
                            self.assertIs(sm.locked_tests(runner), result)
                    operations = [argv[1] for argv, _ in calls]
                    expected = ["run", "rm"] if outcome == "success" else ["run", "inspect", "rm"]
                    if outcome == "timeout":
                        expected.insert(2, "exec")
                        self.assertIn('"target_free_bytes":123', output.getvalue())
                    self.assertEqual(operations, expected)
                    argv, kwargs = calls[0]
                    self.assertEqual(kwargs, {"timeout": 3600, "check": False, "max_output": 4 * 1024 * 1024, "retain_tail": True})
                    self.assertEqual(argv[-8:], ["python3", "-I", "-c", sm.BUILD_RESOURCE_PROBE, "cargo", "test", "--workspace", "--locked"])
                    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--memory=8g", "--memory-swap=8g", "--pids-limit=512", "--cpus=4"):
                        self.assertIn(flag, argv)
                    self.assertIn(f"{root}:/workspace:ro", argv)
                    self.assertIn(f"{root}/.git:/workspace/.git:ro", argv)
                    self.assertIn("/target:rw,nosuid,nodev,exec,size=6g", argv)
                    self.assertNotIn("SECRET", output.getvalue())
                    if outcome == "success":
                        self.assertEqual(output.getvalue(), "")

    def test_probe_errors_never_mask_test_failure_or_skip_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir(); (root / ".git").mkdir()
            cache = Path(tmp) / "cache"; cache.mkdir(); (cache / "registry").mkdir()
            for bad_probe in (sm.MaintenanceError("SECRET"), sm.CommandResult(0, "SECRET not JSON", ""),
                              sm.CommandResult(0, '{"OOMKilled":"SECRET","Running":false,"ExitCode":true}', "")):
                runner = mock.Mock(root=root)
                failure = sm.CommandCaptureError("original timeout", "timeout", sm.CommandResult(-9, "", "SECRET"))
                runner.run.side_effect = [failure, bad_probe, sm.MaintenanceError("cleanup SECRET")]
                with mock.patch.dict(os.environ, {"MAINTENANCE_BUILD_IMAGE": "build:local", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache)}), \
                     mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"), \
                     mock.patch.object(sm.sys, "stderr", io.StringIO()) as output, \
                     self.assertRaises(sm.CommandCaptureError) as caught:
                    sm.locked_tests(runner)
                self.assertIs(caught.exception, failure)
                self.assertEqual(runner.run.call_args_list[-1].args[0][1:3], ["rm", "-f"])
                self.assertIn('"state":"unavailable"', output.getvalue())
                self.assertNotIn("SECRET", output.getvalue())

    def test_failed_test_gate_blocks_all_later_release_gates(self):
        for capture in (None, "timeout", "output-limit"):
            with tempfile.TemporaryDirectory() as tmp:
                state = sm.State(Path(tmp) / "state")
                runner = mock.Mock(root=Path(tmp))
                result = sm.CommandResult(101, "SECRET", "SECRET")
                outcome = sm.CommandCaptureError("capture failed", capture, result) if capture else result
                with mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                     mock.patch.object(sm, "contained_repo_command", side_effect=[outcome]) as command, \
                     mock.patch.object(sm, "locked_vet_gaps") as vet, \
                     mock.patch.object(sm.sys, "stderr", io.StringIO()) as output, \
                     self.assertRaises(sm.MaintenanceError):
                    sm.phase_validate(mock.Mock(), state, runner)
                self.assertEqual(command.call_count, 1)
                vet.assert_not_called()
                self.assertEqual(state.load()["gate_results"], ["clean-build: passed"])
                self.assertIn("test-diagnostics:", output.getvalue())
                self.assertNotIn("SECRET", output.getvalue())

    def test_clean_build_failure_keeps_later_release_gates_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock()
            failure = sm.CommandResult(101, "", "Permission denied")
            output = io.StringIO()
            with mock.patch.object(sm, "contained_repo_command", return_value=failure) as command, \
                 mock.patch.object(sm.sys, "stderr", output), \
                 self.assertRaisesRegex(sm.MaintenanceError, "clean locked-down build failed"):
                sm.phase_validate(mock.Mock(), state, runner)
            self.assertEqual(command.call_count, 1)
            self.assertNotIn("gate_results", state.load())
            self.assertIn("hints=permission-denied", output.getvalue())

    def test_container_requires_docker_even_when_podman_is_installed(self):
        engines = {"podman": "/usr/bin/podman", "docker": None}
        runner = mock.Mock()
        with mock.patch.object(sm.shutil, "which", side_effect=engines.get) as which, \
             mock.patch.dict(os.environ, {"MAINTENANCE_BUILD_IMAGE": "image@sha256:abc"}), \
             self.assertRaisesRegex(sm.MaintenanceError, "docker and MAINTENANCE_BUILD_IMAGE"):
            sm.contained_repo_command(
                runner, ["cargo", "vet"], network=False, source_rw=False, cache_rw=False,
            )
        which.assert_called_once_with("docker")
        runner.run.assert_not_called()

    def test_vet_store_is_writable_without_source_or_cache_writes(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sm.shutil, "which", return_value="/usr/bin/docker"):
            base = Path(tmp); source = base / "source"; cache = base / "cache"; store = base / "store"
            for path in (source, source / ".git", cache, cache / "registry", store): path.mkdir()
            runner = mock.Mock(root=source.resolve())
            runner.run.return_value = sm.CommandResult(0, "", "")
            env = {"MAINTENANCE_BUILD_IMAGE": "image@sha256:abc", "MAINTENANCE_PROJECT_CARGO_HOME": str(cache)}
            with mock.patch.dict(os.environ, env):
                sm.contained_repo_command(
                    runner, ["cargo", "vet", "--locked", "--frozen"],
                    network=False, source_rw=False, cache_rw=False, vet_store=store,
                )
            argv = runner.run.call_args_list[0].args[0]
            self.assertIn(f"{source.resolve()}:/workspace:ro", argv)
            self.assertIn(f"{(source / '.git').resolve()}:/workspace/.git:ro", argv)
            self.assertIn(f"{(cache / 'registry').resolve()}:/opt/project-cargo/registry:ro", argv)
            self.assertIn(f"{store.resolve()}:/vet-store:rw", argv)
            self.assertEqual(argv[argv.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
            self.assertIn("--network=none", argv)
            self.assertEqual(argv[-6:], ["cargo", "vet", "--locked", "--frozen", "--store-path", "/vet-store"])
            runner.run.reset_mock()
            for unsafe in (source, source / ".git", base / "missing"):
                with mock.patch.dict(os.environ, env), self.assertRaises(sm.MaintenanceError):
                    sm.contained_repo_command(
                        runner, ["cargo", "vet"], network=False, source_rw=False,
                        cache_rw=False, vet_store=unsafe,
                    )
            link = base / "link"; link.symlink_to(store, target_is_directory=True)
            with mock.patch.dict(os.environ, env), self.assertRaises(sm.MaintenanceError):
                sm.contained_repo_command(
                    runner, ["cargo", "vet"], network=False, source_rw=False,
                    cache_rw=False, vet_store=link,
                )
            runner.run.assert_not_called()

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
        for command in (
            "node --version", "rustc --version", "cargo --version", "cargo-vet --version",
            "cargo vet gc", "cargo-audit --version", "crate2nix --version",
        ):
            self.assertIn(command, smoke_argv[-1])
        self.assertIn("export XDG_CACHE_HOME=/tmp", smoke_argv[-1])
        maintain_job = workflow.split("\n  maintain:\n", 1)[1]
        maintain_hardening = maintain_job.split(
            "      - name: Export runner-local maintenance paths\n", 1
        )[0]
        allowed_endpoints = maintain_hardening.split("          allowed-endpoints: >\n", 1)[1]
        self.assertIn("production.cloudfront.docker.com:443", allowed_endpoints.split())
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

        concurrency = maintain_job.split("    concurrency:\n", 1)[1].split("    env:\n", 1)[0]
        self.assertIn("group: stable-maintenance-azure-quota\n", concurrency)
        self.assertNotIn("${{", concurrency)
        self.assertIn("cancel-in-progress: false\n", concurrency)
        self.assertIn("queue: max\n", concurrency)

        dockerfile = DOCKERFILE.read_text()
        self.assertRegex(dockerfile, r"FROM rust:1\.98\.0-bookworm@sha256:[0-9a-f]{64} AS rust-toolchain")
        self.assertRegex(dockerfile, r"FROM rust:1\.98\.0-bookworm@sha256:[0-9a-f]{64} AS maintenance-tools")
        self.assertIn("COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo", dockerfile)
        self.assertIn("COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup", dockerfile)
        self.assertIn("UBUNTU_SNAPSHOT=20260924T000000Z", dockerfile)
        self.assertRegex(dockerfile, r"(?m)^\s+nodejs \\$")
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
            "cutoff": "c" * 40,
            "dependency_updates": [{"crate": "é" * 200, "new": str(i)} for i in range(500)],
            "vet_accepted": [], "dependabot_imported": [], "backports_applied": [],
            "backport_review_required": [{"sha": "b" * 40, "check": "stable-relevance",
                                          "stage": "azure-call", "reason": "azure-retries-exhausted"}],
        }
        body = sm.build_pr_body(value, max_bytes=4096)
        self.assertLessEqual(len(body.encode()), 4096)
        self.assertTrue(body.endswith(f"{sm.MARKER} {'c' * 40}"))
        self.assertIn("Backports requiring manual review: 1", body)
        self.assertIn("b" * 40, body)
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "123"}):
            body = sm.build_pr_body({**value, "already_covered": [{"crate": "noise"}] * 500})
        self.assertLessEqual(len(body.encode()), 2400)
        for heading in ("Summary", "What Changed", "Testing", "Automated Checks", "System Integration Impact", "Checklist"):
            self.assertIn(f"## {heading}", body)
        self.assertIn("https://github.com/o/r/actions/runs/123", body)
        self.assertNotIn("noise", body)

    def test_runner_rejects_oversized_streamed_output(self):
        runner = sm.Runner(Path.cwd(), {"PATH": os.environ["PATH"]})
        with self.assertRaises(sm.MaintenanceError):
            runner.run([sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"], max_output=100)

    def test_publish_labels_draft_before_ready_and_metadata_does_not_claim_release(self):
        for ready_response in (
            {"data": {"markPullRequestReadyForReview": {"pullRequest": {"isDraft": False}}}},
        ):
            with self.subTest(ready=ready_response), tempfile.TemporaryDirectory() as tmp:
                state = sm.State(Path(tmp) / "state")
                state.save({"automation_branch": sm.AUTOMATION_PREFIX + "stable-4.x-test",
                            "branch": "stable-4.x", "main_head": "a" * 40, "metadata_only": True})
                runner = mock.Mock()
                responses = [{"number": 19, "node_id": "PR_test"}, {}, ready_response]
                with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "test-token"}), \
                     mock.patch.object(sm, "secure_github_push"), \
                     mock.patch.object(sm, "http_json", side_effect=responses) as http:
                    sm.phase_publish(mock.Mock(), state, runner)
                calls = http.call_args_list
                self.assertTrue(calls[0].kwargs["body"]["draft"])
                self.assertEqual(calls[0].kwargs["body"]["title"], "Refresh stable-4.x supply-chain metadata")
                self.assertIn("slop-guard-exempt", calls[1].kwargs["body"]["labels"])
                self.assertEqual(calls[2].args[0], "https://api.github.com/graphql")
                self.assertEqual(state.load()["pull_request"], 19)

    def test_publish_recovers_ready_errors_and_cleans_up_failed_drafts(self):
        ready = {"data": {"markPullRequestReadyForReview": {"pullRequest": {"isDraft": False}}}}
        draft = {"state": "open", "draft": True}
        closed = {"state": "closed", "draft": True, "number": 19,
                  "head": {"ref": sm.AUTOMATION_PREFIX + "stable-4.x-test", "repo": {"full_name": "o/r"}},
                  "labels": [{"name": sm.AUTOMATION_LABEL}], "user": {"login": "github-actions[bot]"}}
        errors = {"errors": [{"message": "temporary error"}]}
        for failure in (sm.HTTPStatusError(503), sm.MaintenanceError("invalid JSON"), errors, {}, None):
            for recovery in ("retry", "already-ready", "cleanup", "cleanup-retry", "cleanup-fails"):
                with self.subTest(failure=failure, recovery=recovery), tempfile.TemporaryDirectory() as tmp:
                    state = sm.State(Path(tmp) / "state")
                    state.save({"automation_branch": sm.AUTOMATION_PREFIX + "stable-4.x-test",
                                "branch": "stable-4.x", "main_head": "a" * 40, "version": "4.0.6"})
                    responses = [{"number": 19, "node_id": "PR_test"}, {}, failure]
                    if recovery == "retry":
                        responses.extend([draft, ready])
                    elif recovery == "already-ready":
                        responses.append({"state": "open", "draft": False})
                    else:
                        responses.extend([draft, failure, draft, failure, draft])
                        if recovery == "cleanup":
                            responses.append(closed)
                        elif recovery == "cleanup-retry":
                            responses.extend([sm.HTTPStatusError(503), closed])
                        else:
                            responses.extend([sm.HTTPStatusError(503)] * 3)
                    with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "test-token"}), \
                         mock.patch.object(sm, "secure_github_push"), \
                         mock.patch.object(sm, "http_json", side_effect=responses) as http, \
                         mock.patch.object(sm.time, "sleep") as sleep:
                        if recovery.startswith("cleanup"):
                            expected = "close maintenance PR #19" if recovery == "cleanup-fails" else "bounded retries"
                            with self.assertRaisesRegex(sm.MaintenanceError, expected):
                                sm.phase_publish(mock.Mock(), state, mock.Mock())
                        else:
                            sm.phase_publish(mock.Mock(), state, mock.Mock())
                    mutations = [call for call in http.call_args_list if call.args[0].endswith("graphql")]
                    closes = [call for call in http.call_args_list if call.kwargs.get("method") == "PATCH"]
                    self.assertEqual(len(mutations), 3 if recovery.startswith("cleanup") else 2 if recovery == "retry" else 1)
                    self.assertEqual(len(closes), {"cleanup": 1, "cleanup-retry": 2, "cleanup-fails": 3}.get(recovery, 0))
                    self.assertLessEqual(sleep.call_count, 4)
                    for call in closes:
                        self.assertEqual(call.kwargs["body"], {"state": "closed"})
                    if recovery in ("cleanup", "cleanup-retry"):
                        with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                             mock.patch.object(sm, "github_paginated", return_value=[closed]), \
                             mock.patch.object(sm, "github_search_items", return_value=[]), \
                             mock.patch.object(sm.sys, "stdout", io.StringIO()):
                            sm.phase_guard(mock.Mock(branch="stable-4.x"), state, mock.Mock())
                        self.assertFalse(state.load()["skip"])

    def test_publish_cleans_up_invalid_node_and_label_failure(self):
        for node, label in ((None, {}), ("PR_test", sm.HTTPStatusError(503))):
            with self.subTest(node=node), tempfile.TemporaryDirectory() as tmp:
                state = sm.State(Path(tmp) / "state")
                state.save({"automation_branch": sm.AUTOMATION_PREFIX + "stable-4.x-test",
                            "branch": "stable-4.x", "main_head": "a" * 40, "version": "4.0.6"})
                with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "test-token"}), \
                     mock.patch.object(sm, "secure_github_push"), \
                     mock.patch.object(sm, "http_json", side_effect=[{"number": 19, "node_id": node}, label, {"state": "closed"}]) as http:
                    with self.assertRaises(sm.MaintenanceError):
                        sm.phase_publish(mock.Mock(), state, mock.Mock())
                self.assertEqual(http.call_args.kwargs["body"], {"state": "closed"})


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
    def test_locked_json_report_records_failures_without_suggestions(self):
        self.assertEqual(sm.parse_locked_cargo_vet_report(sm.CommandResult(1, VET_LOCKED_FAILURE, "")), [
            sm.VetItem("example", None, "1.0.0"),
        ])
        report = json.loads(VET_LOCKED_FAILURE)
        report["failures"].append({
            "name": "git-crate", "version": "2.0.0@git:" + "A" * 40,
            "missing_criteria": ["safe-to-run"],
        })
        self.assertEqual(len(sm.parse_locked_cargo_vet_report(sm.CommandResult(1, json.dumps(report), ""))), 2)
        self.assertEqual(sm.parse_locked_cargo_vet_report(sm.CommandResult(0, VET_SUCCESS, "warning")), [])

    def test_locked_json_report_rejects_errors_and_inconsistent_results(self):
        invalid = [
            (1, ""), (1, "store error"), (1, "[]"), (0, "{}"),
            (1, VET_SUCCESS), (0, VET_LOCKED_FAILURE),
            (0, '{"conclusion":"success"}'),
            (1, '{"conclusion":"fail (vetting)","failures":[]}'),
            (1, '{"conclusion":"fail (vetting)","failures":[null]}'),
            (1, '{"conclusion":"fail (violation)","violations":{}}'),
        ]
        for field, value in (("name", "bad name"), ("version", "bogus"),
                             ("version", "1.0.0@git:bad"), ("missing_criteria", []),
                             ("missing_criteria", [None])):
            report = json.loads(VET_LOCKED_FAILURE)
            report["failures"][0][field] = value
            invalid.append((1, json.dumps(report)))
        for code, output in invalid:
            with self.subTest(code=code, output=output), self.assertRaises(sm.MaintenanceError):
                sm.parse_locked_cargo_vet_report(sm.CommandResult(code, output, ""))

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

    def test_parser_accepts_git_target_only_for_delta(self):
        git_version = "1.0.0@git:" + "a" * 40
        self.assertEqual(
            sm.parse_cargo_vet_output(f"cargo vet diff example 0.9.0 {git_version}"),
            [sm.VetItem("example", "0.9.0", git_version)],
        )
        self.assertEqual(sm.parse_cargo_vet_output(f"cargo vet inspect example {git_version}"), [])

    def test_covered_dependencies_produce_no_items(self):
        self.assertEqual(sm.parse_cargo_vet_output("Vetting Succeeded!"), [])

    def test_locked_gaps_must_match_review_suggestions(self):
        locked = sm.CommandResult(1, VET_LOCKED_FAILURE, "")
        mismatched_report = json.loads(VET_CHECK_REPORT)
        mismatched_report["suggest"]["suggestions"][0]["name"] = "other"
        mismatched = sm.CommandResult(255, json.dumps(mismatched_report), "")
        with mock.patch.object(sm, "isolated_vet_command", side_effect=[locked, mismatched]), \
             self.assertRaisesRegex(sm.MaintenanceError, "disagree"):
            sm.reviewable_vet_gaps(mock.Mock(), Path("state"))

    def test_failing_check_preserves_suggestable_exemptions_and_targets_only_new_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            store = root / "supply-chain"
            store.mkdir(parents=True)
            config = ('[[exemptions.already-exempted]]\nversion = "1.0.0"\n'
                      'criteria = ["safe-to-deploy"]\nsuggest = true\n')
            (store / "config.toml").write_text(config)
            (store / "audits.toml").write_text("# Existing audits\n")
            (store / "imports.lock").write_text("# Existing imports\n")
            runner = mock.Mock(root=root)
            commands = []
            def contained(_runner, command, **kwargs):
                commands.append(command)
                self.assertEqual((kwargs["vet_store"] / "config.toml").read_text(), config)
                self.assertFalse(kwargs["source_rw"])
                self.assertFalse(kwargs["cache_rw"])
                if command == ["cargo", "vet", "check", "--output-format=json"]:
                    self.assertTrue(kwargs["network"])
                    return sm.CommandResult(255, VET_CHECK_REPORT, "")
                self.assertEqual(command, ["cargo", "vet", "--locked", "--frozen", "--output-format=json"])
                self.assertFalse(kwargs["network"])
                return sm.CommandResult(255, VET_LOCKED_FAILURE, "")
            with mock.patch.object(sm, "contained_repo_command", side_effect=contained):
                items = sm.reviewable_vet_gaps(runner, Path(tmp))
            self.assertEqual(items, [sm.VetItem("example", "0.9.0", "1.0.0")])
            self.assertEqual(len(commands), 2)
            self.assertEqual((store / "config.toml").read_text(), config)

    def test_unlocked_check_failure_set_must_match_authoritative_locked_gaps(self):
        report = json.loads(VET_CHECK_REPORT)
        report["failures"].append({"name": "unexpected", "version": "2.0.0",
                                   "missing_criteria": ["safe-to-deploy"]})
        with mock.patch.object(sm, "isolated_vet_command", side_effect=[
            sm.CommandResult(255, VET_LOCKED_FAILURE, ""), sm.CommandResult(255, json.dumps(report), ""),
        ]), self.assertRaisesRegex(sm.MaintenanceError, "disagree"):
            sm.reviewable_vet_gaps(mock.Mock(), Path("state"))

    def test_structured_failing_check_report_is_strict(self):
        self.assertEqual(
            sm.parse_cargo_vet_check_suggestions(sm.CommandResult(255, VET_CHECK_REPORT, "")),
            [sm.VetItem("example", "0.9.0", "1.0.0")],
        )
        invalid = [
            (0, VET_CHECK_REPORT), (1, VET_CHECK_REPORT), (137, VET_CHECK_REPORT),
            (-9, VET_CHECK_REPORT), (255, VET_SUCCESS), (255, "not json"),
            (255, '{"conclusion":"fail (vetting)","suggest":null}'),
        ]
        for code, output in invalid:
            with self.subTest(code=code, output=output), self.assertRaises(sm.MaintenanceError):
                sm.parse_cargo_vet_check_suggestions(sm.CommandResult(code, output, ""))

    def test_structured_check_report_supports_inspect_and_git_delta(self):
        report = json.loads(VET_CHECK_REPORT)
        report["suggest"]["suggestions"] = [
            {"name": "fresh", "suggested_diff": {"from": None, "to": "1.2.3"}},
            {"name": "git-delta", "suggested_diff": {
                "from": "1.0.0", "to": "1.0.1@git:" + "a" * 40,
            }},
        ]
        report["failures"] = [{"name": name, "version": version, "missing_criteria": ["safe-to-deploy"]}
                              for name, version in (("fresh", "1.2.3"), ("git-delta", "1.0.1@git:" + "a" * 40))]
        self.assertEqual(
            sm.parse_cargo_vet_check_suggestions(sm.CommandResult(255, json.dumps(report), "")),
            [sm.VetItem("fresh", None, "1.2.3"),
             sm.VetItem("git-delta", "1.0.0", "1.0.1@git:" + "a" * 40)],
        )

    def test_audit_serialization_delta_and_full_version(self):
        delta = sm.serialize_audit("serde", "1.0.1", "1.0.2")
        self.assertIn("[[audits.serde]]", delta)
        self.assertIn('who = "Codex (automated via Azure OpenAI)"', delta)
        self.assertIn('delta = "1.0.1 -> 1.0.2"', delta)
        full = sm.serialize_audit("fresh", None, "0.1.0")
        self.assertIn('version = "0.1.0"', full)
        self.assertNotIn("delta", full)
        git_version = "1.0.0@git:" + "a" * 40
        self.assertIn(f'delta = "0.9.0 -> {git_version}"', sm.serialize_audit("example", "0.9.0", git_version))
        with self.assertRaises(sm.MaintenanceError):
            sm.serialize_audit("example", None, git_version)

    def test_audit_serialization_rejects_injection(self):
        with self.assertRaises(sm.MaintenanceError):
            sm.serialize_audit('serde]]\nwho="attacker', None, "1.0.0")

    def test_rejection_only_vet_run_does_not_create_empty_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; (root / "supply-chain").mkdir(parents=True)
            (root / "supply-chain/audits.toml").write_text("")
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock(root=root.resolve())
            rejected = sm.VetItem("example", "0.9.0", "1.0.0")

            def git(argv, **kwargs):
                if argv in (["status", "--porcelain"], ["diff", "--name-only"]):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)

            runner.git.side_effect = git
            vet_failed = sm.CommandResult(1, VET_LOCKED_FAILURE, "")
            suggestion = sm.CommandResult(255, VET_CHECK_REPORT, "")
            vet_clean = sm.CommandResult(0, VET_SUCCESS, "")
            with mock.patch.object(sm, "contained_repo_command", side_effect=[vet_failed, suggestion, vet_clean]), \
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

    def test_dependency_vet_uses_locked_reports_and_disposable_stores(self):
        for outcome in ("covered", "accepted", "final-gap", "error", "exception"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "source"
                (root / "supply-chain").mkdir(parents=True)
                originals = {name: "# Committed " + name + "\n" for name in (
                    "config.toml", "audits.toml", "imports.lock",
                )}
                for name, content in originals.items():
                    (root / "supply-chain" / name).write_text(content)
                runner = sm.Runner(root)
                runner.git(["init"])
                runner.git(["config", "user.name", "Maintenance test"])
                runner.git(["config", "user.email", "maintenance-test@example.invalid"])
                runner.git(["add", "."])
                runner.git(["commit", "-m", "Initial metadata"])
                initial_head = runner.git(["rev-parse", "HEAD"]).stdout
                state = sm.State(Path(tmp) / "state")
                calls = []
                locked_calls = 0

                def contained(_runner, command, **kwargs):
                    nonlocal locked_calls
                    self.assertEqual(
                        kwargs["network"],
                        command == ["cargo", "vet", "check", "--output-format=json"],
                    )
                    self.assertFalse(kwargs["source_rw"])
                    self.assertFalse(kwargs["cache_rw"])
                    store = kwargs["vet_store"]
                    calls.append(store)
                    audits = (root / "supply-chain/audits.toml").read_text()
                    self.assertEqual((store / "audits.toml").read_text(), audits)
                    if command == ["cargo", "vet", "check", "--output-format=json"]:
                        return sm.CommandResult(255, VET_CHECK_REPORT, "")
                    self.assertEqual(command, ["cargo", "vet", "--locked", "--frozen", "--output-format=json"])
                    locked_calls += 1
                    if locked_calls == 2 and outcome in ("accepted", "final-gap"):
                        self.assertIn('[[audits.example]]', audits)
                        self.assertIn('delta = "0.9.0 -> 1.0.0"', audits)
                    for name in originals:
                        (store / name).write_text("# Disposable rewrite\n")
                    if outcome == "error":
                        return sm.CommandResult(1, "", "store error")
                    if outcome == "exception":
                        raise sm.MaintenanceError("command timed out")
                    if outcome == "final-gap" or (outcome == "accepted" and locked_calls == 1):
                        return sm.CommandResult(1, VET_LOCKED_FAILURE, "")
                    return sm.CommandResult(0, VET_SUCCESS, "")

                with mock.patch.object(sm, "contained_repo_command", side_effect=contained), \
                     mock.patch.object(sm, "AzureAI") as ai, \
                     mock.patch.object(sm, "safe_vet_decision", return_value=True) as decide:
                    if outcome in ("final-gap", "error", "exception"):
                        message = {"final-gap": "still reports uncovered", "error": "without parseable", "exception": "timed out"}[outcome]
                        with self.assertRaisesRegex(sm.MaintenanceError, message):
                            sm.phase_vet_dependencies(mock.Mock(), state, runner)
                        self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout, initial_head)
                    else:
                        sm.phase_vet_dependencies(mock.Mock(), state, runner)
                        if outcome == "accepted":
                            self.assertEqual(runner.git(["diff", "--name-only", "HEAD^", "HEAD"]).stdout,
                                             "supply-chain/audits.toml\n")
                            self.assertEqual(state.load()["vet_accepted"], [sm.asdict(sm.VetItem("example", "0.9.0", "1.0.0"))])
                        else:
                            self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout, initial_head)
                        self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")
                    if outcome in ("covered", "error", "exception"):
                        ai.assert_not_called()
                        decide.assert_not_called()
                    else:
                        self.assertEqual(decide.call_args.args[2], sm.VetItem("example", "0.9.0", "1.0.0"))
                for name in ("config.toml", "imports.lock"):
                    self.assertEqual((root / "supply-chain" / name).read_text(), originals[name])
                self.assertTrue(calls)
                self.assertTrue(all(not path.exists() for path in calls))

    def test_final_validation_rejects_locked_vet_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            (root / "supply-chain").mkdir(parents=True)
            (root / "supply-chain/audits.toml").write_text("# Current audits\n")
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock(root=root)
            stores = []
            def contained(_runner, command, **kwargs):
                if command[:2] == ["cargo", "vet"]:
                    self.assertEqual(command, ["cargo", "vet", "--locked", "--frozen", "--output-format=json"])
                    self.assertFalse(kwargs["network"])
                    stores.append(kwargs["vet_store"])
                    return sm.CommandResult(1, VET_LOCKED_FAILURE, "")
                return sm.CommandResult(0, "", "")
            with mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "contained_repo_command", side_effect=contained), \
                 self.assertRaisesRegex(sm.MaintenanceError, "final gate reports uncovered"):
                sm.phase_validate(mock.Mock(), state, runner)
            self.assertNotIn("cargo-vet: passed", state.load()["gate_results"])
            self.assertEqual(len(stores), 1)
            self.assertFalse(stores[0].exists())

    def test_vet_review_material_uses_a_disposable_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            (root / "supply-chain").mkdir(parents=True)
            audits = root / "supply-chain/audits.toml"
            audits.write_text("# Original audits\n")
            runner = mock.Mock(root=root)
            ai = mock.Mock()
            ai.call.return_value = {"decision": True}
            stores = []
            def contained(_runner, command, **kwargs):
                self.assertEqual(command, [
                    "cargo", "vet", "diff", "example", "0.9.0", "1.0.0", "--mode=local",
                ])
                self.assertTrue(kwargs["network"])
                self.assertTrue(kwargs["cache_rw"])
                self.assertFalse(kwargs["source_rw"])
                stores.append(kwargs["vet_store"])
                (stores[-1] / "audits.toml").write_text("# Tool rewrite\n")
                return sm.CommandResult(0, "Review material", "")
            with mock.patch.object(sm, "contained_repo_command", side_effect=contained), \
                 mock.patch.object(sm, "cache_crate_source", return_value=root), \
                 mock.patch.object(sm, "crate_source_context", return_value=b"verified source"):
                self.assertTrue(sm._vet_decision(
                    ai, runner, sm.VetItem("example", "0.9.0", "1.0.0"), Path(tmp) / "vet-sources",
                ))
            ai.call.assert_called_once()
            filename = ai.call.call_args.kwargs["attachment"][0]
            self.assertRegex(filename, r"^[A-Za-z0-9_.-]{1,100}$")
            self.assertEqual(audits.read_text(), "# Original audits\n")
            self.assertFalse(stores[0].exists())

    def test_git_delta_is_rejected_before_review(self):
        git_version = "1.0.0@git:" + "a" * 40
        ai = mock.Mock()
        self.assertFalse(sm._vet_decision(
            ai, mock.Mock(), sm.VetItem("example", "0.9.0", git_version), Path("state/vet-sources"),
        ))
        ai.call.assert_not_called()

    def test_full_audit_is_rejected_before_review(self):
        ai = mock.Mock()
        self.assertFalse(sm._vet_decision(
            ai, mock.Mock(), sm.VetItem("example", None, "1.0.0"), Path("state/vet-sources"),
        ))
        ai.call.assert_not_called()

    def test_vet_fallback_uses_locked_json_for_each_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            (root / "supply-chain").mkdir(parents=True)
            (root / "supply-chain/audits.toml").write_text("# Audits\n")
            runner = mock.Mock(root=root)
            parent = "a" * 40
            def git(argv, **kwargs):
                if argv == ["show", "-s", "--format=%s", "HEAD"]:
                    return sm.CommandResult(0, "deps(rust): bump the all-cargo-updates group\n", "")
                if argv == ["rev-parse", "HEAD^"]:
                    return sm.CommandResult(0, parent, "")
                return sm.CommandResult(0, "", "")
            runner.git.side_effect = git
            state = sm.State(Path(tmp) / "state")
            state.save({
                "started_at": NOW.isoformat(),
                "dependency_updates": [{"crate": "example", "old": "0.9.0", "new": "1.0.1"}],
                "dependency_candidates": {"example@0.9.0": ["1.0.1", "1.0.0"]},
            })
            stores = []
            def contained(_runner, command, **kwargs):
                if command == ["cargo", "vet", "check", "--output-format=json"]:
                    self.assertTrue(kwargs["network"])
                    return sm.CommandResult(255, VET_CHECK_REPORT, "")
                self.assertEqual(command, ["cargo", "vet", "--locked", "--frozen", "--output-format=json"])
                self.assertFalse(kwargs["network"])
                self.assertFalse(kwargs["source_rw"])
                self.assertFalse(kwargs["cache_rw"])
                stores.append(kwargs["vet_store"])
                return sm.CommandResult(1, VET_LOCKED_FAILURE, "")
            with mock.patch.object(sm, "contained_repo_command", side_effect=contained), \
                 mock.patch.object(sm, "contained_cargo_update", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "cargo_metadata", return_value={"packages": []}), \
                 mock.patch.object(sm, "direct_registry_packages", return_value=[]), \
                 mock.patch.object(sm, "snapshot_worktree", return_value="baseline"), \
                 mock.patch.object(sm, "restore_worktree") as restore, \
                 mock.patch.object(sm, "safe_vet_decision", return_value=False) as decide:
                accepted, rejected = sm._fallback_after_vet_rejection(
                    state, runner, mock.Mock(), {sm.VetItem("example", None, "1.0.1")}, "# Audits\n",
                )
            self.assertEqual(accepted, [])
            self.assertEqual(rejected, [sm.asdict(sm.VetItem("example", "0.9.0", "1.0.0"))])
            self.assertEqual(decide.call_args.args[2], sm.VetItem("example", "0.9.0", "1.0.0"))
            restore.assert_called_once_with(runner, "baseline")
            self.assertEqual(len(stores), 1)
            self.assertFalse(stores[0].exists())

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
            "docs(parser): clarify", "refactor!: API", "style: rustfmt", "chore(deps): bump x",
            "i18n: add German", "l10n: add French", "feat(i18n): add Spanish",
        ]
        for subject in subjects:
            with self.subTest(subject=subject):
                self.assertIsNotNone(sm.prefilter_commit(subject, ["src/a.rs"]))

    def test_ambiguous_fix_security_ci_and_revert_are_not_title_filtered(self):
        for subject in ("fix: prevent panic", "security: harden parser", "ci: repair packaging", "Revert bad fix", "Update parser", "test: correct a regression"):
            with self.subTest(subject=subject):
                self.assertIsNone(sm.prefilter_commit(subject, ["src/a.rs"]))

    def test_path_and_author_filters(self):
        self.assertEqual(sm.prefilter_commit("Update stuff", ["Cargo.lock"]), "dependency metadata only")
        for paths in ([".github/workflows/ci.yml"], [".github/workflows/stable-package-target.yml"],
                      ["src/a.rs", ".github/workflows/ci.yml"]):
            self.assertEqual(sm.prefilter_commit("Repair testing", paths), "CI change requires manual backport")
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
            clean_vet = sm.CommandResult(0, VET_SUCCESS, "")
            with mock.patch.object(sm, "contained_repo_command", return_value=clean_vet), self.assertRaisesRegex(
                sm.MaintenanceError, "unexpected files changed",
            ):
                sm.phase_vet_dependencies(mock.Mock(), state, runner)

    def test_refresh_commits_only_the_import_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            root = Path(tmp) / "source"
            (root / "supply-chain").mkdir(parents=True)
            runner = mock.Mock(root=root)
            def git(argv, **kwargs):
                if argv == ["status", "--porcelain"]:
                    return sm.CommandResult(0, "", "")
                if argv == ["diff", "--name-only"]:
                    return sm.CommandResult(0, "supply-chain/imports.lock\n", "")
                if argv in (["add", "--", "supply-chain/imports.lock"], ["commit", "-m", "chore: refresh cargo vet metadata"]):
                    return sm.CommandResult(0, "", "")
                if argv == ["restore", "--source=HEAD", "--worktree", "--", "supply-chain/config.toml", "supply-chain/audits.toml"]:
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)
            runner.git.side_effect = git
            with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, VET_SUCCESS, "")), \
                 mock.patch.object(sm, "cargo_metadata", return_value={"packages": []}):
                sm.phase_refresh_vet_imports(mock.Mock(), state, runner)
            runner.git.assert_any_call(["add", "--", "supply-chain/imports.lock"])
            runner.git.assert_any_call(["commit", "-m", "chore: refresh cargo vet metadata"])

    def test_refresh_rejects_unexpected_output(self):
        runner = mock.Mock()
        runner.git.side_effect = [
            sm.CommandResult(0, "", ""),
            sm.CommandResult(0, "", ""),
            sm.CommandResult(0, "Cargo.toml\n", ""),
        ]
        with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, VET_SUCCESS, "")), \
             self.assertRaisesRegex(sm.MaintenanceError, "unexpected path"):
            sm.phase_refresh_vet_imports(mock.Mock(), mock.Mock(), runner)

    def test_refresh_preserves_policy_and_audits_with_real_git(self):
        for outcome in ("success", "unexpected", "gaps", "failure", "exception"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "source"
                (root / "supply-chain").mkdir(parents=True)
                originals = {
                    "supply-chain/config.toml": "# Keep exemptions and policy\n",
                    "supply-chain/audits.toml": "# Keep local audit history\n",
                    "supply-chain/imports.lock": "# Old imported audits\n",
                    "Cargo.toml": "# Manifest\n",
                }
                for path, content in originals.items():
                    (root / path).write_text(content)
                runner = sm.Runner(root)
                runner.git(["init"])
                runner.git(["config", "user.name", "Maintenance test"])
                runner.git(["config", "user.email", "maintenance-test@example.invalid"])
                runner.git(["add", "."])
                runner.git(["commit", "-m", "Initial metadata"])
                initial_head = runner.git(["rev-parse", "HEAD"]).stdout
                state = sm.State(Path(tmp) / "state")

                def contained(_runner, command, **kwargs):
                    if command == ["cargo", "vet", "regenerate", "imports"]:
                        for path in originals:
                            if path != "Cargo.toml" or outcome == "unexpected":
                                (root / path).write_text("# Regenerated\n")
                    else:
                        self.assertEqual(command, ["cargo", "vet", "--locked", "--frozen", "--output-format=json"])
                        self.assertFalse(kwargs["network"])
                        self.assertFalse(kwargs["source_rw"])
                        self.assertFalse(kwargs["cache_rw"])
                        store = kwargs["vet_store"]
                        self.assertNotIn(root, store.parents)
                        for path in ("supply-chain/config.toml", "supply-chain/audits.toml"):
                            self.assertEqual((root / path).read_text(), originals[path])
                            self.assertEqual((store / Path(path).name).read_text(), originals[path])
                        self.assertEqual((store / "imports.lock").read_text(), "# Regenerated\n")
                        for name in ("config.toml", "audits.toml", "imports.lock"):
                            (store / name).write_text("# Baseline store rewrite\n")
                        if outcome == "gaps":
                            return sm.CommandResult(1, VET_LOCKED_FAILURE, "")
                        if outcome == "failure":
                            return sm.CommandResult(1, "", "store error")
                        if outcome == "exception":
                            raise sm.MaintenanceError("command timed out")
                    return sm.CommandResult(0, VET_SUCCESS, "")

                with mock.patch.object(sm, "contained_repo_command", side_effect=contained) as command, \
                     mock.patch.object(sm, "cargo_metadata", return_value={"packages": [
                         {"name": name, "version": "1.0.0", "id": name,
                          "source": "registry+https://github.com/rust-lang/crates.io-index"}
                         for name in ("example", "covered-crate")
                     ]}):
                    if outcome != "success":
                        errors = {
                            "unexpected": "unexpected path", "gaps": "pre-existing unvetted",
                            "failure": "without parseable requirements", "exception": "command timed out",
                        }
                        with self.assertRaisesRegex(sm.MaintenanceError, errors[outcome]):
                            sm.phase_refresh_vet_imports(mock.Mock(), state, runner)
                        self.assertEqual(command.call_count, 1 if outcome == "unexpected" else 2)
                        self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout, initial_head)
                        if outcome == "gaps":
                            value = state.load()
                            self.assertEqual(value["post_import_unvetted"], [
                                {"crate": "example", "old": None, "new": "1.0.0"},
                            ])
                            self.assertEqual(value["post_import_covered_count"], 1)
                            self.assertEqual(value["already_covered"], [
                                {"crate": "covered-crate", "version": "1.0.0"},
                            ])
                    else:
                        sm.phase_refresh_vet_imports(mock.Mock(), state, runner)
                        self.assertEqual(command.call_count, 2)
                        self.assertEqual(
                            runner.git(["diff", "--name-only", "HEAD^", "HEAD"]).stdout,
                            "supply-chain/imports.lock\n",
                        )
                        self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")
                for path in ("supply-chain/config.toml", "supply-chain/audits.toml"):
                    self.assertEqual((root / path).read_text(), originals[path])
                self.assertEqual((root / "supply-chain/imports.lock").read_text(), "# Regenerated\n")
                self.assertEqual(list(state.directory.glob("vet-baseline-*")), [])

    def test_conflicting_backport_is_aborted_without_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            sha, head = "a" * 40, "b" * 40
            state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
            runner = mock.Mock()
            def git(argv, **kwargs):
                if argv in (["diff", "--quiet"], ["diff", "--cached", "--quiet"]):
                    return sm.CommandResult(0, "", "")
                if argv == ["branch", "--show-current"]:
                    return sm.CommandResult(0, "stable-4.x\n", "")
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
            output = io.StringIO()
            with mock.patch.object(sm, "AzureAI", side_effect=AssertionError("AI must not resolve conflicts")), \
                 mock.patch.object(sm, "_commit_record", return_value={"paths": ["src/a.rs"]}), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")) as build, \
                 mock.patch.object(sm.sys, "stderr", output):
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
            build.assert_called_once_with(runner)
            self.assertEqual(state.load()["backports_applied"], [])
            self.assertEqual(state.load()["backports_conflict_skipped"], [sha])
            self.assertIn(f"backport-debug: sha={sha} result=conflict-skipped", output.getvalue())
            self.assertIn("backport-summary: phase=apply applied=0 skipped=1", output.getvalue())

    def test_invalid_dependabot_transplant_is_reset_without_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            commit, head, pre_head = "a" * 40, "a" * 40, "c" * 40
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
                if argv == ["rev-list", "--reverse", f"{commit}^..{head}"]:
                    return sm.CommandResult(0, commit + "\n", "")
                if argv == ["diff-tree", "--no-commit-id", "--name-only", "-r", commit]:
                    return sm.CommandResult(0, ".github/workflows/ci.yml\n", "")
                if argv == ["diff-tree", "--no-commit-id", "--summary", "-r", commit]:
                    return sm.CommandResult(0, "", "")
                if argv == ["show", "--format=", "--unified=1", commit]:
                    return sm.CommandResult(0, files[0]["patch"], "")
                if argv in (["cherry-pick", "--abort"], ["reset", "--hard", pre_head]):
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)
            runner.git.side_effect = git
            with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                 mock.patch.object(sm, "github_paginated", side_effect=lambda url, **kw:
                                   [{"sha": commit}] if url.endswith("/commits") else [pr]), \
                 mock.patch.object(sm, "_pr_files", return_value=files), \
                 mock.patch.object(sm, "transplant_action_refs", side_effect=sm.MaintenanceError("invalid immutable diff")) as transplant, \
                 mock.patch.object(sm, "AzureAI", side_effect=AssertionError("AI must not resolve conflicts")):
                sm.phase_import_dependabot(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(state.load()["dependabot_imported"], [])
            self.assertEqual(state.load()["dependabot_skipped"], [{
                "number": 17, "reason": "validation or import failure",
                "stage": "ref-transplant", "diagnostic": "unclassified-error"}])
            transplant.assert_called_once_with(runner, files, commit, head)
            runner.git.assert_any_call(["reset", "--hard", pre_head])


class MarkerConflictAndAITests(unittest.TestCase):
    SHA = "a" * 40

    def test_http_status_and_transport_diagnostics_do_not_echo_secrets(self):
        secret = "credential-model-content"
        failures = [
            (sm.urllib.error.HTTPError("https://host/" + secret, 429, secret, {}, None), "http-status-429"),
            (sm.urllib.error.URLError(secret), "transport-error"),
            (sm.urllib.error.URLError(TimeoutError(secret)), "transport-timeout"),
        ]
        for failure, reason in failures:
            with self.subTest(reason=reason), mock.patch.object(sm.urllib.request, "urlopen", side_effect=failure):
                with self.assertRaises(sm.MaintenanceError) as caught:
                    sm.http_json("https://example.invalid")
                self.assertEqual(sm.diagnostic_reason(caught.exception), reason)
                self.assertNotIn(secret, str(caught.exception))

    def test_http_json_normalizes_invalid_utf8(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = bytes([0xff])
        with mock.patch.object(sm.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(sm.MaintenanceError, "invalid JSON") as caught:
                sm.http_json("https://example.invalid")
        self.assertEqual(sm.diagnostic_reason(caught.exception), "invalid-json")

    def test_http_throttling_preserves_only_validated_retry_and_quota_headers(self):
        headers = sm.email.message.Message()
        headers["Retry-After-Ms"] = "61000"
        headers["Retry-After"] = "90"
        headers["X-Ratelimit-Limit-Tokens"] = "150000"
        headers["x-ratelimit-remaining-tokens"] = "0"
        headers["x-ratelimit-limit-requests"] = "60"
        headers["x-ratelimit-remaining-requests"] = "secret-do-not-log"
        headers["x-private-header"] = "secret-do-not-log"
        failure = sm.urllib.error.HTTPError("https://secret-do-not-log", 429, "secret-do-not-log", headers, None)
        with mock.patch.object(sm.urllib.request, "urlopen", side_effect=failure):
            with self.assertRaises(sm.HTTPStatusError) as caught:
                sm.http_json("https://example.invalid")
        error = caught.exception
        self.assertEqual(error.status, 429)
        self.assertEqual(error.retry_after, 61)
        self.assertEqual(error.rate_limits, {"limit_tokens": 150000, "remaining_tokens": 0, "limit_requests": 60})
        self.assertNotIn("secret-do-not-log", str(error))
        for raw in ("-1", "NaN", "inf", "999999999999999", "secret-do-not-log", "1\n::error::secret"):
            with self.subTest(raw=raw):
                error = sm.HTTPStatusError(429, {"retry-after-ms": raw, "retry-after": raw,
                                               "x-ratelimit-limit-tokens": raw})
                self.assertIsNone(error.retry_after)
                self.assertEqual(error.rate_limits, {})
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60)
        error = sm.HTTPStatusError(429, {"retry-after": sm.email.utils.format_datetime(future, usegmt=True)})
        self.assertGreater(error.retry_after, 55)
        self.assertLessEqual(error.retry_after, 60)

    def test_obsolete_http_retry_dates_are_utc_and_honored(self):
        now = dt.datetime(2026, 10, 5, 16, 0, tzinfo=dt.timezone.utc)

        class Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return now.astimezone(tz) if tz else now.replace(tzinfo=None)

        ai = object.__new__(sm.AzureAI)
        ai.key, ai.model, ai.url = "key", "model", "https://example.invalid"
        for raw in ("Mon, 05 Oct 2026 16:02:00 GMT", "Monday, 05-Oct-26 16:02:00 GMT",
                    "Mon Oct  5 16:02:00 2026"):
            with self.subTest(raw=raw), mock.patch.object(sm.dt, "datetime", Clock):
                error = sm.HTTPStatusError(429, {"retry-after": raw})
                self.assertEqual(error.retry_after, 120)
                with mock.patch.object(sm, "http_json", side_effect=[error, {"output_text": '{"decision":true}'}]), \
                     mock.patch.object(sm.time, "sleep") as sleep, \
                     mock.patch.object(sm.sys, "stderr", io.StringIO()):
                    self.assertEqual(ai.call("instructions", "data", sm.BOOL_SCHEMA, "result"), {"decision": True})
                sleep.assert_called_once_with(120)
        with mock.patch.object(sm.dt, "datetime", Clock):
            self.assertEqual(sm.HTTPStatusError(429, {"retry-after": "Sun Nov  6 08:49:37 1994"}).retry_after, 0)

    def test_azure_throttling_waits_for_headers_or_minute_window_and_keeps_request(self):
        ai = object.__new__(sm.AzureAI)
        ai.key, ai.model, ai.url = "secret-do-not-log", "model", "https://example.invalid"
        data = "x" * 1033558
        for headers, expected in (({"retry-after-ms": "61000"}, 61), ({"retry-after": "65.5"}, 65.5), ({}, 60)):
            with self.subTest(headers=headers):
                failure = sm.HTTPStatusError(429, headers)
                output = io.StringIO()
                with mock.patch.object(sm, "http_json", side_effect=[failure, {"output_text": '{"decision":true}'}]) as request, \
                     mock.patch.object(sm.time, "sleep") as sleep, \
                     mock.patch.object(sm.secrets, "randbelow", return_value=0), \
                     mock.patch.object(sm.sys, "stderr", output):
                    self.assertEqual(ai.call("instructions", data, sm.BOOL_SCHEMA, "result"), {"decision": True})
                sleep.assert_called_once_with(expected)
                self.assertEqual(request.call_count, 2)
                self.assertEqual(request.call_args_list[0].kwargs["body"], request.call_args_list[1].kwargs["body"])
                self.assertIn("input_bytes=1033558 reason=http-status-429", output.getvalue())
                self.assertNotIn("secret-do-not-log", output.getvalue())
        output = io.StringIO()
        failure = sm.HTTPStatusError(429, {"x-ratelimit-limit-tokens": "150000", "x-ratelimit-remaining-tokens": "0"})
        with mock.patch.object(sm, "http_json", side_effect=failure) as request, \
             mock.patch.object(sm.time, "sleep") as sleep, \
             mock.patch.object(sm.secrets, "randbelow", return_value=10), \
             mock.patch.object(sm.sys, "stderr", output), \
             self.assertRaisesRegex(sm.MaintenanceError, "bounded retries"):
            ai.call("instructions", data, sm.BOOL_SCHEMA, "result")
        self.assertEqual(request.call_count, sm.MAX_AI_ATTEMPTS)
        self.assertEqual(sleep.call_args_list, [mock.call(70), mock.call(130)])
        self.assertEqual(sum(line.startswith("azure-debug:") for line in output.getvalue().splitlines()), sm.MAX_AI_ATTEMPTS)
        self.assertIn("limit_tokens=150000 remaining_tokens=0", output.getvalue())

    def test_azure_does_not_retry_before_an_excessive_server_wait(self):
        ai = object.__new__(sm.AzureAI)
        ai.key, ai.model, ai.url = "key", "model", "https://example.invalid"
        output = io.StringIO()
        with mock.patch.object(sm, "http_json", side_effect=sm.HTTPStatusError(429, {"retry-after": "301"})) as request, \
             mock.patch.object(sm.time, "sleep") as sleep, \
             mock.patch.object(sm.sys, "stderr", output):
            with self.assertRaisesRegex(sm.MaintenanceError, "bounded wait budget") as caught:
                ai.call("instructions", "data", sm.BOOL_SCHEMA, "result")
        self.assertEqual(sm.diagnostic_reason(caught.exception), "azure-retry-wait-too-long")
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()
        self.assertIn("retry_after_s=301", output.getvalue())

    def test_azure_failure_diagnostics_are_bounded_and_sanitized(self):
        ai = object.__new__(sm.AzureAI)
        secret = "credential-model-content"
        ai.key, ai.model, ai.url = secret, secret, "https://host/" + secret
        failures = [
            (sm.HTTPStatusError(400), "http-request", "http-status-400"),
            (sm.MaintenanceError(secret), "http-request", "unclassified-error"),
            ({"output_text": secret}, "json-parse", "invalid-json"),
            ({"output_text": '{"decision":"' + secret + '"}'}, "schema-validation", "schema-boolean"),
            ({"output": []}, "structured-output", "missing-structured-output"),
        ]
        for response, stage, reason in failures:
            effect = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
            output = io.StringIO()
            with self.subTest(reason=reason), mock.patch.object(sm, "http_json", **effect), \
                 mock.patch.object(sm.time, "sleep"), mock.patch.object(sm.sys, "stderr", output):
                with self.assertRaises(sm.MaintenanceError):
                    ai.call(secret, secret, sm.BOOL_SCHEMA, secret)
            lines = output.getvalue().splitlines()
            self.assertEqual(sum(line.startswith("azure-debug:") for line in lines), sm.MAX_AI_ATTEMPTS)
            self.assertIn("stage=" + stage, lines[-1])
            self.assertIn("reason=" + reason, lines[-1])
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn("https://", output.getvalue())

    def test_azure_malformed_output_arrays_fail_as_missing_structured_output(self):
        ai = object.__new__(sm.AzureAI)
        ai.key, ai.model, ai.url = "key", "model", "https://example.invalid"
        responses = [
            {"output": None},
            {"output": [{"content": None}]},
        ]
        for response in responses:
            output = io.StringIO()
            with self.subTest(response=response), mock.patch.object(
                sm, "http_json", return_value=response
            ), mock.patch.object(sm.time, "sleep"), mock.patch.object(sm.sys, "stderr", output):
                with self.assertRaisesRegex(sm.MaintenanceError, "bounded retries"):
                    ai.call("instructions", "data", sm.BOOL_SCHEMA, "result")
            lines = output.getvalue().splitlines()
            self.assertEqual(sum(line.startswith("azure-debug:") for line in lines), sm.MAX_AI_ATTEMPTS)
            self.assertIn("stage=structured-output", lines[-1])
            self.assertIn("reason=missing-structured-output", lines[-1])

    def test_relevance_failures_defer_one_commit_and_continue_with_diagnostics(self):
        for stage, failure in [
            ("stable-context", sm.MaintenanceError("stable branch context exceeds bounded AI input")),
            ("azure-call", sm.MaintenanceError("Azure failed after bounded retries")),
        ]:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                state = sm.State(Path(tmp) / "state")
                state.save({"branch": "stable-4.x", "cutoff": "a" * 40, "main_head": "b" * 40})
                later = "d" * 40
                runner = mock.Mock()
                runner.git.side_effect = [sm.CommandResult(0, self.SHA + "\n" + later + "\n", ""),
                                          sm.CommandResult(0, "patch", ""), sm.CommandResult(0, "patch", "")]
                record = {"subject": "Fix bug", "paths": ["src/a.rs"], "author": "Maintainer", "parents": 1}
                ai = mock.Mock()
                ai.call.side_effect = ([{"decision": True}] * 3 if stage == "stable-context" else
                                       [{"decision": True}, failure, {"decision": True}, {"decision": True}])
                context_effect = {"side_effect": [failure, "stable"]} if stage == "stable-context" else {"return_value": "stable"}
                output = io.StringIO()
                with mock.patch.object(sm, "_commit_record", return_value=record), \
                     mock.patch.object(sm, "AzureAI", return_value=ai), \
                     mock.patch.object(sm, "stable_path_context", **context_effect), \
                     mock.patch.object(sm.sys, "stderr", output):
                    sm.phase_classify_backports(mock.Mock(), state, runner)
                self.assertIn("stage=" + stage, output.getvalue())
                self.assertIn("reason=" + sm.diagnostic_reason(failure), output.getvalue())
                self.assertEqual(state.load()["backport_candidates"], [later])
                self.assertEqual(state.load()["backport_review_required"], [{
                    "sha": self.SHA, "check": "stable-relevance", "stage": stage,
                    "reason": sm.diagnostic_reason(failure),
                }])

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

    def test_backport_classification_failure_preserves_earlier_and_later_backports(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            cutoff, main = "a" * 40, "b" * 40
            earlier, failed, later = "c" * 40, "d" * 40, "e" * 40
            state.save({"branch": "stable-4.x", "cutoff": cutoff, "main_head": main})
            runner = mock.Mock()

            def git(argv, **kwargs):
                if argv in (["diff", "--quiet"], ["diff", "--cached", "--quiet"]):
                    return sm.CommandResult(0, "", "")
                if argv == ["branch", "--show-current"]:
                    return sm.CommandResult(0, "stable-4.x\n", "")
                if argv == ["rev-list", "--topo-order", "--reverse", f"{cutoff}..{main}"]:
                    return sm.CommandResult(0, "\n".join([earlier, failed, later]) + "\n", "")
                if argv[:2] == ["show", "--format=fuller"]:
                    return sm.CommandResult(0, "patch", "")
                if argv[:2] == ["log", "-1"]:
                    return sm.CommandResult(0, "", "")
                if argv == ["rev-parse", "HEAD"]:
                    return sm.CommandResult(0, cutoff + "\n", "")
                if argv[:2] == ["cherry-pick", "-x"]:
                    self.assertIn(argv[2], [earlier, later])
                    return sm.CommandResult(0, "", "")
                raise AssertionError(argv)

            runner.git.side_effect = git
            record = {
                "subject": "Fix stable bug", "body": "", "author": "Maintainer",
                "parents": 1, "paths": ["src/a.rs"],
            }
            ai = mock.Mock()
            secret = "credential-do-not-log"
            ai.call.side_effect = [{"decision": True}, {"decision": True},
                                   sm.MaintenanceError(secret), {"decision": True}, {"decision": True}]
            output = io.StringIO()
            with mock.patch.object(sm, "_commit_record", return_value=record), \
                 mock.patch.object(sm, "AzureAI", return_value=ai), \
                 mock.patch.object(sm, "stable_path_context", return_value="stable"), \
                 mock.patch.object(sm.sys, "stderr", output):
                sm.phase_classify_backports(mock.Mock(), state, runner)
            value = state.load()
            self.assertEqual(value["cutoff"], cutoff)
            self.assertEqual(value["backport_candidates"], [earlier, later])
            self.assertEqual(value["backport_review_required"], [{
                "sha": failed, "check": "bug-fix", "stage": "azure-call", "reason": "unclassified-error",
            }])
            for sha in (earlier, later):
                for check in ("bug-fix", "stable-relevance"):
                    self.assertIn(f"backport-debug: sha={sha} check={check} decision=true", output.getvalue())
            self.assertNotIn(f"backport-debug: sha={failed}", output.getvalue())
            self.assertIn("backport-summary: phase=classify candidates=3 selected=2 skipped=0 manual_review=1", output.getvalue())
            with mock.patch.object(sm.sys, "stderr", output), \
                 mock.patch.object(sm, "_commit_record", return_value=record), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")) as build:
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(build.call_count, 3)  # Baseline and both attempted picks.
            self.assertEqual(state.load()["backports_applied"], [earlier, later])
            for sha in (earlier, later):
                self.assertIn(f"backport-debug: sha={sha} result=applied", output.getvalue())
            self.assertIn("backport-summary: phase=apply applied=2 skipped=0", output.getvalue())
            body = sm.build_pr_body(state.load())
            self.assertIn("Backports requiring manual review: 1", body)
            self.assertIn(failed, body)
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, output.getvalue())
            summary = io.StringIO()
            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}), mock.patch.object(sm.sys, "stdout", summary):
                sm.phase_report(mock.Mock(), state, runner)
            self.assertIn(failed, summary.getvalue())
            self.assertIn("Backport Review Required: 1", summary.getvalue())
            self.assertNotIn(secret, summary.getvalue())

    def test_negative_backport_decisions_are_logged_without_untrusted_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": "d" * 40, "main_head": "e" * 40})
            prefiltered, not_bug, not_relevant = (letter * 40 for letter in "abc")
            runner = mock.Mock()
            runner.git.side_effect = [sm.CommandResult(0, "\n".join([prefiltered, not_bug, not_relevant]), ""),
                                      sm.CommandResult(0, "patch-secret", ""), sm.CommandResult(0, "patch-secret", "")]
            record = {"subject": "Fix subject-secret", "body": "body-secret", "paths": ["src/path-secret.rs"],
                      "author": "author-secret", "parents": 1}
            ai = mock.Mock()
            ai.call.side_effect = [{"decision": False}, {"decision": True}, {"decision": False}]
            output = io.StringIO()
            with mock.patch.object(sm, "_commit_record", return_value=record), \
                 mock.patch.object(sm, "prefilter_commit", side_effect=["prefilter-secret", None, None]), \
                 mock.patch.object(sm, "AzureAI", return_value=ai), \
                 mock.patch.object(sm, "stable_path_context", return_value="stable-secret"), \
                 mock.patch.object(sm.sys, "stderr", output):
                sm.phase_classify_backports(mock.Mock(), state, runner)
            log = output.getvalue()
            self.assertIn(f"backport-debug: sha={not_bug} check=bug-fix decision=false", log)
            self.assertNotIn(f"sha={not_bug} check=stable-relevance", log)
            self.assertIn(f"backport-debug: sha={not_relevant} check=bug-fix decision=true", log)
            self.assertIn(f"backport-debug: sha={not_relevant} check=stable-relevance decision=false", log)
            self.assertNotIn(f"sha={prefiltered}", log)
            self.assertIn("backport-summary: phase=classify candidates=3 selected=0 skipped=3 manual_review=0", log)
            self.assertNotIn("secret", log)
            self.assertEqual(state.load()["backport_candidates"], [])
            self.assertEqual(state.load()["backport_review_required"], [])

    def test_unavailable_ai_defers_candidates_without_aborting_or_reinitializing(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            cutoff, main = "a" * 40, "b" * 40
            state.save({"branch": "stable-4.x", "cutoff": cutoff, "main_head": main})
            commits = ["c" * 40, "d" * 40]
            runner = mock.Mock()
            runner.git.return_value = sm.CommandResult(0, "\n".join(commits), "")
            record = {"subject": "Fix bug", "paths": ["src/a.rs"], "author": "Maintainer", "parents": 1}
            with mock.patch.object(sm, "_commit_record", return_value=record), \
                 mock.patch.object(sm, "AzureAI", side_effect=sm.MaintenanceError("secret")) as factory, \
                 mock.patch.object(sm.sys, "stderr", io.StringIO()):
                sm.phase_classify_backports(mock.Mock(), state, runner)
            factory.assert_called_once_with()
            value = state.load()
            self.assertEqual(value["backport_candidates"], [])
            self.assertEqual([row["sha"] for row in value["backport_review_required"]], commits)
            self.assertTrue(all(row["stage"] == "azure-initialization" for row in value["backport_review_required"]))

    def test_invalid_ai_decisions_are_deferred_in_both_backport_checks(self):
        for check in ("bug-fix", "stable-relevance"):
            for invalid in (None, {"decision": "yes"}, {"decision": True, "extra": "secret"}):
                with self.subTest(check=check, invalid=invalid), tempfile.TemporaryDirectory() as tmp:
                    state = sm.State(Path(tmp) / "state")
                    state.save({"branch": "stable-4.x", "cutoff": "a" * 40, "main_head": "b" * 40})
                    runner = mock.Mock()
                    runner.git.side_effect = [sm.CommandResult(0, self.SHA + "\n", ""), sm.CommandResult(0, "patch", "")]
                    record = {"subject": "Fix bug", "paths": ["src/a.rs"], "author": "Maintainer", "parents": 1}
                    ai = mock.Mock()
                    ai.call.side_effect = [invalid] if check == "bug-fix" else [{"decision": True}, invalid]
                    with mock.patch.object(sm, "_commit_record", return_value=record), \
                         mock.patch.object(sm, "AzureAI", return_value=ai), \
                         mock.patch.object(sm, "stable_path_context", return_value="stable"), \
                         mock.patch.object(sm.sys, "stderr", io.StringIO()) as output:
                        sm.phase_classify_backports(mock.Mock(), state, runner)
                    value = state.load()
                    self.assertEqual(value["backport_candidates"], [])
                    self.assertEqual(value["backport_review_required"][0]["check"], check)
                    self.assertEqual(value["backport_review_required"][0]["stage"], "schema-validation")
                    self.assertNotIn(f"backport-debug: sha={self.SHA} check={check}", output.getvalue())

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


class MaintenanceHistoryTests(unittest.TestCase):
    def repository(self, root):
        root.mkdir()
        runner = sm.Runner(root)
        runner.git(["init", "-b", "main"])
        runner.git(["config", "user.name", "Maintenance test"])
        runner.git(["config", "user.email", "maintenance-test@example.invalid"])
        (root / "Cargo.toml").write_text('[workspace.package]\nversion = "4.0.5"\n')
        (root / "Cargo.lock").write_text("# lock\n")
        workflow = root / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("jobs:\n  test:\n    steps:\n      - uses: a/b@" + "a" * 40 + "\n")
        self.commit(runner, "Branch point")
        runner.git(["branch", "stable-4.x"])
        runner.git(["remote", "add", "origin", str(root)])
        return runner

    def commit(self, runner, subject):
        runner.git(["add", "."])
        runner.git(["commit", "-m", subject])
        return runner.git(["rev-parse", "HEAD"]).stdout.strip()

    def test_failed_backport_build_restores_earlier_work_and_continues(self):
        for failure in ("missing-import", "timeout", "capture-error"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                root = runner.root
                (root / "common.py").write_text("def existing_helper(): return 1\n")
                (root / "cli.py").write_text("from common import existing_helper\nassert existing_helper() > 0\n")
                baseline = self.commit(runner, "Buildable baseline")
                runner.git(["branch", "-f", "stable-4.x", baseline])
                (root / "common.py").write_text("def existing_helper(): return 2\n")
                earlier = self.commit(runner, "Earlier independent fix")
                (root / "cli.py").write_text("from common import resolve_hsm_type\n")
                broken = self.commit(runner, "Fix requiring an absent helper")
                (root / "later.txt").write_text("Later independent fix\n")
                later = self.commit(runner, "Later independent fix")
                runner.git(["checkout", "stable-4.x"])
                state = sm.State(Path(tmp) / "state")
                state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": later,
                            "backport_candidates": [earlier, broken, later]})
                snapshots = []
                def build(current):
                    self.assertIs(current, runner)
                    head = runner.git(["rev-parse", "HEAD"]).stdout.strip()
                    snapshots.append(head)
                    bad_import = "resolve_hsm_type" in (root / "cli.py").read_text()
                    if bad_import and failure != "missing-import":
                        if failure == "timeout":
                            raise sm.CommandCaptureError("command timed out", "timeout", sm.CommandResult(-9, "", "secret"))
                        raise sm.MaintenanceError("secret capture failure")
                    # Real subprocess import check reproduces a missing helper;
                    # Cargo/container execution is tested separately.
                    return runner.run([sys.executable, "-B", "-c", "import cli"], check=False)
                output = io.StringIO()
                with mock.patch.object(sm, "locked_build", side_effect=build), \
                     mock.patch.object(sm.sys, "stderr", output):
                    sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
                value = state.load()
                self.assertEqual(len(snapshots), 4)  # Baseline, good, bad, later.
                self.assertEqual(value["backports_applied"], [earlier, later])
                self.assertEqual(value["backports_conflict_skipped"], [])
                self.assertEqual(value["backports_deferred"], [broken])
                self.assertEqual(value["backports_build_failed"][0]["sha"], broken)
                self.assertEqual((root / "common.py").read_text(), "def existing_helper(): return 2\n")
                self.assertNotIn("resolve_hsm_type", (root / "cli.py").read_text())
                self.assertTrue((root / "later.txt").is_file())
                self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")
                history = runner.git(["log", "--format=%H"]).stdout.splitlines()
                self.assertNotIn(snapshots[2], history)
                self.assertIn(snapshots[1], history)
                self.assertIn(f"sha={broken} result=build-skipped", output.getvalue())
                self.assertNotIn("secret", output.getvalue())
                self.assertEqual(sm.maintenance_main_through(value), baseline)
                self.assertIn("Backports reverted after build failure: 1", sm.build_pr_body(value))
                self.assertIn("Backports Build Failed", "\n".join(sm.sanitized_state_details(value)))

    def test_backport_baseline_failure_does_not_mutate_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            (runner.root / "fix.txt").write_text("candidate\n")
            candidate = self.commit(runner, "Candidate")
            runner.git(["checkout", "stable-4.x"])
            before = runner.git(["rev-parse", "HEAD"]).stdout
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "backport_candidates": [candidate]})
            with mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(101, "", "")), \
                 self.assertRaisesRegex(sm.MaintenanceError, "baseline build failed"):
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout, before)
            self.assertFalse((runner.root / "fix.txt").exists())
            self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")

    def test_backport_entry_guards_preserve_edits_and_reject_wrong_checkout(self):
        for case in ("unstaged", "staged", "wrong-branch", "detached"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                notes = runner.root / "notes.txt"
                notes.write_text("original\n")
                baseline = self.commit(runner, "Tracked file baseline")
                runner.git(["branch", "-f", "stable-4.x", baseline])
                (runner.root / "fix.txt").write_text("independent candidate\n")
                candidate = self.commit(runner, "Candidate touching another path")
                runner.git(["checkout", "stable-4.x"])
                if case in ("unstaged", "staged"):
                    notes.write_text("local edits must survive\n")
                    if case == "staged":
                        runner.git(["add", "notes.txt"])
                elif case == "wrong-branch":
                    runner.git(["checkout", "-b", "unrelated"])
                else:
                    runner.git(["checkout", "--detach", baseline])
                state = sm.State(Path(tmp) / "state")
                original_state = {"branch": "stable-4.x", "backport_candidates": [candidate]}
                state.save(original_state)
                head = runner.git(["rev-parse", "HEAD"]).stdout
                diff = runner.git(["diff", "--binary"]).stdout
                staged = runner.git(["diff", "--cached", "--binary"]).stdout
                contents = notes.read_bytes()
                with mock.patch.object(sm, "locked_build") as build, \
                     mock.patch.object(runner, "git", wraps=runner.git) as git, \
                     self.assertRaises(sm.MaintenanceError):
                    sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
                build.assert_not_called()
                self.assertFalse(any(call.args[0][0] in ("cherry-pick", "reset") for call in git.call_args_list))
                self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout, head)
                self.assertEqual(runner.git(["diff", "--binary"]).stdout, diff)
                self.assertEqual(runner.git(["diff", "--cached", "--binary"]).stdout, staged)
                self.assertEqual(notes.read_bytes(), contents)
                self.assertEqual(state.load(), original_state)
                self.assertFalse((runner.root / "fix.txt").exists())

    def test_already_present_backport_does_not_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "backport_candidates": ["a" * 40]})
            runner = mock.Mock()
            runner.git.side_effect = lambda argv, **kwargs: sm.CommandResult(
                0, "stable-4.x\n" if argv == ["branch", "--show-current"] else "b" * 40 + "\n", "",
            )
            with mock.patch.object(sm, "locked_build", side_effect=AssertionError("no new attempt")):
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(state.load()["backports_applied"], [])
            self.assertEqual(state.load()["backports_deferred"], [])

    def test_recent_direct_backport_does_not_hide_older_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            runner = self.repository(root)
            base = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            (root / "missed.rs").write_text("older bug fix\n")
            missed = self.commit(runner, "Fix older bug")
            (root / "picked.rs").write_text("directly backported fix\n")
            picked = self.commit(runner, "Fix newer bug")
            runner.git(["checkout", "stable-4.x"])
            runner.git(["cherry-pick", picked])
            (root / "stable-only").write_text("recent stable work\n")
            self.commit(runner, "Recent direct stable change")
            state = sm.State(Path(tmp) / "state")
            sm.phase_initialize(mock.Mock(branch="stable-4.x"), state, runner)
            value = state.load()
            self.assertEqual(value["cutoff"], base)
            candidates = runner.git(["rev-list", f"{value['cutoff']}..{value['main_head']}"]).stdout.splitlines()
            self.assertIn(missed, candidates)
            self.assertIn(picked, value["backports_already_present"])

    def test_main_dependabot_import_excludes_unrelated_main_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            runner = self.repository(root)
            (root / "main-feature.rs").write_text("not a stable backport\n")
            self.commit(runner, "Main feature")
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(workflow.read_text() + "# unrelated main-only workflow change\n")
            absent = root / ".github/workflows/main-only.yml"
            absent.write_text("uses: a/b@" + "a" * 40 + "\n")
            self.commit(runner, "Main-only workflow")
            runner.git(["checkout", "-b", "dependabot-action"])
            path = root / ".github/workflows/ci.yml"
            path.write_text(path.read_text().replace("a" * 40, "b" * 40))
            absent.write_text(absent.read_text().replace("a" * 40, "b" * 40))
            head = self.commit(runner, "Update pinned action")
            patch = runner.git(["show", "--format=", "--unified=1", head]).stdout
            pr = {
                "number": 17, "user": {"login": "dependabot[bot]"},
                "base": {"ref": "main", "repo": {"full_name": "o/r"}},
                "head": {"sha": head, "repo": {"full_name": "o/r"}},
            }
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            files = [{"filename": name, "status": "modified", "patch": patch}
                     for name in (".github/workflows/ci.yml", ".github/workflows/main-only.yml")]
            with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                 mock.patch.object(sm, "github_paginated", side_effect=lambda url, **kw:
                                   [{"sha": head}] if url.endswith("/commits") else [pr]), \
                 mock.patch.object(sm, "_pr_files", return_value=files):
                sm.phase_import_dependabot(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(state.load()["dependabot_imported"], [17])
            self.assertIn("b" * 40, path.read_text())
            self.assertFalse((root / "main-feature.rs").exists())
            self.assertNotIn("main-only", path.read_text())
            self.assertFalse(absent.exists())

    def test_cargo_dependabot_is_explicitly_delegated_to_audited_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = sm.State(Path(tmp) / "state")
            runner = mock.Mock()
            pr = {"number": 18, "user": {"login": "dependabot[bot]"},
                  "base": {"ref": "stable-4.x", "repo": {"full_name": "o/r"}},
                  "head": {"sha": "b" * 40, "repo": {"full_name": "o/r"}}}
            with mock.patch.object(sm, "github_repository", return_value="o/r"), \
                 mock.patch.object(sm, "github_paginated", return_value=[pr]), \
                 mock.patch.object(sm, "_pr_files", return_value=[{"filename": "Cargo.lock"}]):
                sm.phase_import_dependabot(mock.Mock(branch="stable-4.x"), state, runner)
            runner.git.assert_not_called()
            self.assertEqual(state.load()["dependabot_skipped"], [
                {"number": 18, "reason": "Cargo handled by audited dependency phase", "intentional": True}])

    def test_release_keeps_unresolved_backports_eligible(self):
        for pending in ({"backport_review_required": [{"sha": "b" * 40}]}, {"backports_deferred": ["b" * 40]}, {}):
            with self.subTest(pending=pending), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "source"
                runner = self.repository(root)
                initial = runner.git(["rev-parse", "HEAD"]).stdout.strip()
                (root / "fix.rs").write_text("fixed\n")
                main = self.commit(runner, "Backported fix")
                state = sm.State(Path(tmp) / "state")
                state.save({"original_head": initial, "cutoff": initial, "main_head": main, **pending})
                with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, "", "")):
                    sm.phase_release(mock.Mock(), state, runner)
                marker = sm.marker_sha(runner.git(["log", "-1", "--format=%B"]).stdout)
                self.assertEqual(marker, initial if pending else main)

    def test_import_refresh_does_not_create_a_version_only_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            runner = self.repository(root)
            initial = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            (root / "supply-chain").mkdir()
            (root / "supply-chain/imports.lock").write_text("refreshed audits\n")
            refreshed = self.commit(runner, "Refresh imported audits")
            state = sm.State(Path(tmp) / "state")
            state.save({"original_head": initial, "cutoff": initial, "main_head": refreshed})
            with mock.patch.object(sm, "contained_repo_command", side_effect=AssertionError("no release generation")):
                sm.phase_release(mock.Mock(), state, runner)
            self.assertTrue(state.load()["metadata_only"])
            self.assertNotIn("version", state.load())
            self.assertEqual(runner.git(["rev-parse", "HEAD^"]).stdout.strip(), refreshed)
            self.assertEqual(runner.git(["diff", "--name-only", "HEAD^..HEAD"]).stdout, "")
            self.assertEqual(sm.marker_sha(runner.git(["log", "-1", "--format=%B"]).stdout), refreshed)
            self.assertIn('version = "4.0.5"', (root / "Cargo.toml").read_text())

    def test_metadata_cutoff_is_recovered_after_regular_and_squash_merges(self):
        for pending_key in (None, "backport_review_required", "backports_deferred"):
            for squash in (False, True):
                with self.subTest(pending=pending_key, squash=squash), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "source"
                    runner = self.repository(root)
                    initial = runner.git(["rev-parse", "HEAD"]).stdout.strip()
                    (root / "pending-fix.rs").write_text("main bug fix\n")
                    main = self.commit(runner, "Fix pending bug")
                    runner.git(["checkout", "stable-4.x"])
                    runner.git(["checkout", "-b", "maintenance-fixture"])
                    (root / "supply-chain").mkdir()
                    (root / "supply-chain/imports.lock").write_text("refreshed audits\n")
                    self.commit(runner, "Refresh imported audits")
                    value = {"original_head": initial, "cutoff": initial, "main_head": main,
                             "branch": "stable-4.x"}
                    if pending_key:
                        value[pending_key] = [{"sha": main}] if pending_key == "backport_review_required" else [main]
                    state = sm.State(Path(tmp) / "state")
                    state.save(value)
                    with mock.patch.object(sm, "contained_repo_command", side_effect=AssertionError("no release generation")):
                        sm.phase_release(mock.Mock(), state, runner)
                    through = initial if pending_key else main
                    self.assertEqual(state.load()["main_through"], through)
                    self.assertEqual(sm.marker_sha(runner.git(["log", "-1", "--format=%B"]).stdout), through)
                    body = sm.build_pr_body(state.load())
                    self.assertEqual(sm.marker_sha(body), through)
                    # Stale cached progress must never override pending work.
                    self.assertEqual(sm.marker_sha(sm.build_pr_body({**state.load(), "main_through": main})), through)
                    runner.git(["checkout", "stable-4.x"])
                    if squash:
                        runner.git(["merge", "--squash", "maintenance-fixture"])
                        runner.git(["commit", "-m", "Merge audit-only maintenance", "-m", body])
                    else:
                        runner.git(["merge", "--no-ff", "maintenance-fixture", "-m", "Merge audit-only maintenance"])
                    following = sm.State(Path(tmp) / "following-state")
                    sm.phase_initialize(mock.Mock(branch="stable-4.x"), following, runner)
                    self.assertEqual(following.load()["cutoff"], through)
                    candidates = runner.git(["rev-list", f"{through}..{main}"]).stdout.splitlines()
                    self.assertEqual(candidates, [main] if pending_key else [])
                    self.assertIn('version = "4.0.5"', (root / "Cargo.toml").read_text())


class SequentialMaintenanceTests(unittest.TestCase):
    repository = MaintenanceHistoryTests.repository
    commit = MaintenanceHistoryTests.commit

    def test_backport_patch_treats_inventory_paths_literally(self):
        for name in (":(exclude)**", "Cargo.*", "ordinary.rs"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                (runner.root / name).write_text("literal filename marker\n")
                (runner.root / "value.rs").write_text("actual source change marker\n")
                lock = runner.root / "Cargo.lock"
                lock.write_text(lock.read_text() + "generated metadata marker\n")
                sha = self.commit(runner, "Fix source with unusual filename")
                record = sm._commit_record(runner, sha)
                self.assertIn(name, record["paths"])
                patch = sm.backport_patch(runner, record)
                self.assertIn("+literal filename marker", patch)
                self.assertIn("+actual source change marker", patch)
                self.assertNotIn("generated metadata marker", patch)

    def test_skewed_merge_history_replays_prerequisite_before_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            source = runner.root / "value.rs"
            source.write_text("pub fn value() -> u32 { 0 }\n")
            baseline = self.commit(runner, "Existing functionality")
            runner.git(["branch", "-f", "stable-4.x", baseline])
            def dated(subject, year):
                date = f"{year}-01-01T00:00:00+0000"
                with mock.patch.dict(runner.env, {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}):
                    return self.commit(runner, subject)
            source.write_text("pub fn value() -> u32 { 1 }\n")
            prerequisite = dated("Fix prerequisite", 2030)
            (runner.root / "left.txt").write_text("left fix\n")
            left = dated("Fix independent left", 2040)
            runner.git(["checkout", "-b", "skewed-side", prerequisite])
            source.write_text("pub fn value() -> u32 { 2 }\n")
            child = dated("Fix child", 2000)
            (runner.root / "right.txt").write_text("right fix\n")
            right = dated("Fix independent right", 2010)
            runner.git(["checkout", "main"])
            with mock.patch.dict(runner.env, {"GIT_COMMITTER_DATE": "2050-01-01T00:00:00+0000"}):
                runner.git(["merge", "--no-ff", "skewed-side", "-m", "Merge skewed history"])
            main = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            chronological = runner.git(["rev-list", "--reverse", f"{baseline}..{main}"]).stdout.splitlines()
            self.assertLess(chronological.index(child), chronological.index(prerequisite))
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": main})
            ai = mock.Mock()
            def decision(instructions, data, schema, name):
                if name == "stable_relevance_decision" and "Fix child" in data:
                    self.assertEqual(source.read_text(), "pub fn value() -> u32 { 1 }\n")
                    self.assertIn("pub fn value() -> u32 { 1 }", data)
                return {"decision": True, "reason": "bug-fix"}
            ai.call.side_effect = decision
            with mock.patch.object(sm, "AzureAI", return_value=ai), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "format_backport"), mock.patch.object(sm.sys, "stderr", io.StringIO()):
                sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
            applied = state.load()["backports_applied"]
            self.assertLess(applied.index(prerequisite), applied.index(child))
            self.assertEqual(set(applied), {prerequisite, child, left, right})
            self.assertEqual(source.read_text(), "pub fn value() -> u32 { 2 }\n")

    def test_repair_rejects_manifest_and_audit_policy_edits(self):
        for path in ("Cargo.toml", "src/member/Cargo.toml", "src/member/Cargo.lock", ".cargo/audit.toml", "source-only"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                source = runner.root / "value.rs"
                source.write_text("old\n")
                policy = runner.root / ("Cargo.toml" if path == "source-only" else path)
                policy.parent.mkdir(parents=True, exist_ok=True)
                original = policy.read_text() if policy.exists() else "policy = 'stable'\n"
                policy.write_text(original)
                baseline = self.commit(runner, "Existing feature and policy")
                runner.git(["branch", "-f", "stable-4.x", baseline])
                source.write_text("fixed on main\n")
                policy.write_text(original + "# main metadata change\n")
                sha = self.commit(runner, "Fix existing feature with metadata")
                runner.git(["checkout", "stable-4.x"])
                source.write_text("stable variant\n")
                pre_head = self.commit(runner, "Stable variant")
                source.write_text("fixed stable variant\n")
                if path != "source-only":
                    if path == ".cargo/audit.toml":
                        policy.write_text(original + "[advisories]\nignore = ['RUSTSEC-2000-0001']\n")
                    elif path.endswith("Cargo.toml"):
                        policy.write_text(original + "[features]\nunreviewed = []\n")
                    else:
                        policy.write_text(original + "# unreviewed lockfile change\n")
                patch = runner.git(["diff"]).stdout
                runner.git(["reset", "--hard", pre_head])
                state = sm.State(Path(tmp) / "state")
                state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
                ai = mock.Mock()
                ai.call.side_effect = lambda instructions, data, schema, name: (
                    {"decision": True, "patch": patch} if name == "backport_conflict_repair" else {"decision": True})
                with mock.patch.object(sm, "AzureAI", return_value=ai), \
                     mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")) as build, \
                     mock.patch.object(sm, "format_backport") as fmt:
                    sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner, adaptive=True)
                self.assertEqual(policy.read_text(), original)
                if path == "source-only":
                    self.assertEqual(state.load()["backports_applied"], [sha])
                    self.assertEqual(source.read_text(), "fixed stable variant\n")
                    self.assertEqual(build.call_count, 2)
                    fmt.assert_called_once()
                else:
                    self.assertEqual(state.load()["backports_deferred"], [sha])
                    self.assertEqual(source.read_text(), "stable variant\n")
                    self.assertEqual(build.call_count, 1)
                    fmt.assert_not_called()
                    self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout.strip(), pre_head)
                    self.assertEqual(ai.call.call_count, sm.MAX_BACKPORT_REPAIR_ATTEMPTS)

    def test_repair_rejects_hidden_protected_preimage_in_patch_headers(self):
        for section_path in ("Cargo.toml", "value.rs"):
            with self.subTest(section_path=section_path), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                policy = runner.root / "Cargo.toml"
                source = runner.root / "value.rs"
                policy.write_text("original manifest\n")
                source.write_text("original source\n")
                baseline = self.commit(runner, "Existing policy and source")
                runner.git(["branch", "-f", "stable-4.x", baseline])
                policy.write_text("main manifest\n")
                source.write_text("main source\n")
                sha = self.commit(runner, "Fix existing source with metadata")
                runner.git(["checkout", "stable-4.x"])
                patch = (f"diff --git a/{section_path} b/value.rs\n"
                         "--- a/Cargo.toml\n+++ b/value.rs\n@@ -1 +1 @@\n"
                         "-original manifest\n+new source\n")
                inventory = runner.git(["apply", "--numstat", "-"], input_text=patch).stdout
                self.assertEqual(inventory, "1\t1\tvalue.rs\n")
                runner.git(["apply", "--check", "--index", "-"], input_text=patch)
                ai = mock.Mock(); ai.call.return_value = {"decision": True, "patch": patch}
                self.assertFalse(sm.repair_backport(runner, sha, baseline, ai))
                self.assertEqual(policy.read_text(), "original manifest\n")
                self.assertEqual(source.read_text(), "original source\n")
                self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout.strip(), baseline)
                self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")
                self.assertEqual(ai.call.call_count, sm.MAX_BACKPORT_REPAIR_ATTEMPTS)

    def test_followup_sees_applied_and_formatted_predecessor(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            source = runner.root / "value.rs"
            source.write_text("pub fn value() -> u32 { 0 }\n")
            baseline = self.commit(runner, "Existing functionality")
            runner.git(["branch", "-f", "stable-4.x", baseline])
            source.write_text("pub fn value() -> u32 { 1 }\n")
            first = self.commit(runner, "Fix existing value")
            source.write_text("pub fn value() -> u32 { 2 }\n")
            second = self.commit(runner, "Fix follow-up value")
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": second})
            ai = mock.Mock(); calls = []
            def decision(instructions, data, schema, name):
                calls.append(name)
                self.assertIn("untrusted", instructions)
                if name == "backport_conflict_repair":
                    head = runner.git(["rev-parse", "HEAD"]).stdout.strip()
                    source.write_text("pub fn value() -> u32 {\n    2\n}\n")
                    patch = runner.git(["diff"]).stdout
                    runner.git(["reset", "--hard", head])
                    return {"decision": True, "patch": patch}
                if name == "backport_repair_scope":
                    return {"decision": True}
                if name == "stable_relevance_decision" and "Fix follow-up value" in data:
                    self.assertIn("pub fn value() -> u32 {\n    1\n}", data)
                return {"decision": True, "reason": "bug-fix"}
            ai.call.side_effect = decision
            def format_command(current, command, **kwargs):
                self.assertEqual(command, ["cargo", "fmt", "--all"])
                number = "1" if "{ 1 }" in source.read_text() else "2"
                source.write_text("pub fn value() -> u32 {\n    " + number + "\n}\n")
                return sm.CommandResult(0, "", "")
            with mock.patch.object(sm, "AzureAI", return_value=ai), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")) as build, \
                 mock.patch.object(sm, "contained_repo_command", side_effect=format_command), \
                 mock.patch.object(sm.sys, "stderr", io.StringIO()):
                sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
            self.assertEqual(calls, ["bug_fix_decision", "stable_relevance_decision"] * 2 +
                             ["backport_conflict_repair", "backport_repair_scope"])
            self.assertEqual(build.call_count, 3)  # One baseline, then each commit.
            value = state.load()
            self.assertEqual(value["backports_applied"], [first, second])
            self.assertEqual(value["backports_deferred"], [])
            self.assertEqual(runner.git(["rev-list", "--count", baseline + "..HEAD"]).stdout.strip(), "2")
            messages = runner.git(["log", "--format=%B", baseline + "..HEAD"]).stdout
            for sha in (first, second):
                self.assertIn("(cherry picked from commit " + sha + ")", messages)
            self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")
            sm.phase_report(mock.Mock(branch="stable-4.x"), state, runner)
            report = (state.directory / "report.md").read_text()
            self.assertIn("Fix follow-up value", report)
            self.assertEqual(len(json.loads((state.directory / "report.json").read_text())["outcomes"]), 2)

    def test_new_feature_labeled_fix_is_skipped_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            (runner.root / "new-provider.rs").write_text("new provider\n")
            feature = self.commit(runner, "fix: support a new provider edge case")
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": feature})
            ai = mock.Mock(); ai.call.return_value = {"decision": False, "reason": "new-feature"}
            with mock.patch.object(sm, "AzureAI", return_value=ai), mock.patch.object(sm, "locked_build") as build:
                sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
            build.assert_not_called()
            self.assertFalse((runner.root / "new-provider.rs").exists())
            self.assertEqual(state.load()["backport_outcomes"][0]["outcome"], "intentional-skip")
            self.assertEqual(state.load()["backport_skipped"][0]["reason"], "new-feature")

    def test_uncertain_relevance_remains_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            (runner.root / "fix.rs").write_text("fix\n")
            sha = self.commit(runner, "Fix existing behavior")
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": sha})
            ai = mock.Mock(); ai.call.side_effect = [
                {"decision": True, "reason": "bug-fix"}, {"decision": False, "reason": "uncertain"}]
            with mock.patch.object(sm, "AzureAI", return_value=ai), mock.patch.object(sm, "locked_build") as build:
                sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
            build.assert_not_called()
            self.assertEqual(sm.maintenance_main_through(state.load()), baseline)
            self.assertEqual(state.load()["backport_outcomes"][0]["outcome"], "pending")

    def test_conflict_repair_is_scoped_verified_built_and_formatted(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            source = runner.root / "value.rs"
            source.write_text("old\n")
            baseline = self.commit(runner, "Existing feature")
            source.write_text("fixed on main\n")
            sha = self.commit(runner, "Fix existing feature")
            runner.git(["checkout", "stable-4.x"])
            source.write_text("stable variant\n")
            pre_head = self.commit(runner, "Stable variant")
            source.write_text("fixed stable variant\n")
            patch = runner.git(["diff"]).stdout
            runner.git(["reset", "--hard", pre_head])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
            ai = mock.Mock(); ai.call.side_effect = [{"decision": True, "patch": patch}, {"decision": True}]
            with mock.patch.object(sm, "AzureAI", return_value=ai), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")) as build, \
                 mock.patch.object(sm, "format_backport") as fmt:
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner, adaptive=True)
            self.assertEqual(source.read_text(), "fixed stable variant\n")
            self.assertEqual(state.load()["backports_adapted"], [sha])
            self.assertEqual(build.call_count, 2)
            fmt.assert_called_once_with(runner, pre_head)
            self.assertIn(sha, runner.git(["log", "-1", "--format=%B"]).stdout)
            self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")

    def test_repair_cannot_touch_other_files_or_create_symlinks(self):
        for malicious in ("other-path", "symlink"):
            with self.subTest(malicious=malicious), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                source = runner.root / "value.rs"
                source.write_text("old\n")
                baseline = self.commit(runner, "Baseline")
                source.write_text("main fix\n"); sha = self.commit(runner, "Fix existing behavior")
                runner.git(["checkout", "stable-4.x"])
                source.write_text("stable\n"); pre_head = self.commit(runner, "Stable variant")
                source.write_text("bad\n"); patch = runner.git(["diff"]).stdout
                runner.git(["reset", "--hard", pre_head])
                if malicious == "other-path":
                    patch = patch.replace("value.rs", "Cargo.toml")
                else:
                    patch = patch.replace("index ", "old mode 100644\nnew mode 120000\nindex ", 1)
                state = sm.State(Path(tmp) / "state")
                state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
                ai = mock.Mock(); ai.call.return_value = {"decision": True, "patch": patch}
                with mock.patch.object(sm, "AzureAI", return_value=ai), \
                     mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                     mock.patch.object(sm, "format_backport") as fmt:
                    sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner, adaptive=True)
                fmt.assert_not_called()
                self.assertEqual(source.read_text(), "stable\n")
                self.assertEqual(state.load()["backports_deferred"], [sha])
                self.assertEqual(ai.call.call_count, sm.MAX_BACKPORT_REPAIR_ATTEMPTS)
                self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout.strip(), pre_head)

    def test_format_failure_reverts_only_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            (runner.root / "fix.rs").write_text("fix\n"); sha = self.commit(runner, "Fix")
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
            with mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "format_backport", side_effect=sm.MaintenanceError("formatter failed")):
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner, adaptive=True)
            self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout.strip(), baseline)
            self.assertEqual(state.load()["backports_deferred"], [sha])
            self.assertEqual(state.load()["backports_repair_failed"][0]["reason"], "format-failed")

    def test_formatter_drift_cannot_be_amended_into_backport(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            unrelated = runner.root / "unrelated.rs"
            unrelated.write_text("fn unrelated() {} // existing formatting drift\n")
            baseline = self.commit(runner, "Existing stable code")
            runner.git(["branch", "-f", "stable-4.x", baseline])
            (runner.root / "earlier.txt").write_text("earlier accepted fix\n")
            earlier = self.commit(runner, "Earlier independent fix")
            candidate = runner.root / "fix.rs"
            candidate.write_text("fn fix() {}\n")
            rejected = self.commit(runner, "Attempt triggering unrelated rustfmt drift")
            (runner.root / "later.txt").write_text("later independent fix\n")
            later = self.commit(runner, "Later independent fix")
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "backport_candidates": [earlier, rejected, later]})
            def formatter(current, command, **kwargs):
                if candidate.exists():
                    candidate.write_text("fn fix() {\n}\n")
                    unrelated.write_text("fn unrelated() {\n}\n")
                return sm.CommandResult(0, "", "")
            with mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "contained_repo_command", side_effect=formatter):
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner, adaptive=True)
            value = state.load()
            self.assertEqual(value["backports_applied"], [earlier, later])
            self.assertEqual(value["backports_deferred"], [rejected])
            self.assertEqual(value["backports_repair_failed"][0]["reason"], "format-failed")
            self.assertFalse(candidate.exists())
            self.assertEqual(unrelated.read_text(), "fn unrelated() {} // existing formatting drift\n")
            self.assertTrue((runner.root / "earlier.txt").exists())
            self.assertTrue((runner.root / "later.txt").exists())
            self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")

    def test_formatter_preserves_canonical_literal_filenames(self):
        for name in ("src/café.rs", "src/tab\tname.rs", "src/line\nname.rs", ":(exclude)**.rs"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
                source = runner.root / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("fn fix() {}\n")
                self.commit(runner, "Fix existing source")
                def formatter(*args, **kwargs):
                    source.write_text("fn fix() {\n}\n")
                    return sm.CommandResult(0, "", "")
                with mock.patch.object(sm, "contained_repo_command", side_effect=formatter):
                    sm.format_backport(runner, baseline)
                self.assertEqual(runner.git(["status", "--porcelain"]).stdout, "")
                self.assertEqual(runner.git(["show", f"HEAD:{name}"]).stdout, "fn fix() {\n}\n")

    def test_independent_report_counts_pending_without_sequential_outcomes(self):
        sha = "b" * 40
        cases = (
            ({"backport_review_required": [{"sha": sha}]}, 1),
            ({"backports_deferred": [sha]}, 1),
            ({"backport_review_required": [{"sha": sha}, {"sha": "c" * 40}],
              "backports_deferred": [sha]}, 2),
            ({"backports_applied": [sha]}, 0),
            ({"backport_inflight": sha}, 0),
        )
        for fields, expected in cases:
            for outcomes in (None, []):
                with self.subTest(fields=fields, outcomes=outcomes), tempfile.TemporaryDirectory() as tmp:
                    state = sm.State(Path(tmp) / "state")
                    value = {"branch": "stable-4.x", **fields}
                    if outcomes is not None:
                        value["backport_outcomes"] = outcomes
                    state.save(value)
                    with mock.patch.object(sm.sys, "stdout", io.StringIO()):
                        sm.phase_report(mock.Mock(branch="stable-4.x"), state, mock.Mock())
                    report = json.loads((state.directory / "report.json").read_text())
                    self.assertEqual(report["pending"], expected)
                    self.assertEqual(report["interrupted"], "backport_inflight" in fields)
                    markdown = (state.directory / "report.md").read_text()
                    self.assertIn("pending work remains" if expected or report["interrupted"]
                                  else "examined backlog accounted for", markdown)

    def test_ci_backports_require_review_before_ai_build_or_mutation(self):
        payloads = (
            "    permissions: {contents: write}\n",
            "    env: {KEY: '${{ secrets.STABLE_MAINTENANCE_APP_PRIVATE_KEY }}'}\n",
            "    environment: production\n    runs-on: self-hosted\n",
            "    uses: owner/repo/.github/workflows/job.yml@main\n    secrets: inherit\n",
            "    steps:\n      - uses: attacker/action@main\n",
            "    steps:\n      - run: curl https://example.invalid\n",
            "    permissions: &grant {contents: write}\n    env: *grant\n",
            "    steps:\n      - run: cargo fmt --check\n",
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
                workflow = runner.root / ".github/workflows/ci.yml"
                workflow.write_text("name: CI\npermissions: {contents: read}\njobs:\n  fmt:\n" + payload)
                sha = self.commit(runner, "Fix test job")
                runner.git(["checkout", "stable-4.x"])
                original_workflow = workflow.read_text()
                state = sm.State(Path(tmp) / "state")
                state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": sha})
                with mock.patch.object(sm, "AzureAI") as ai, mock.patch.object(sm, "locked_build") as build:
                    sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
                ai.assert_not_called(); build.assert_not_called()
                self.assertEqual(state.load()["backport_outcomes"][0]["outcome"], "intentional-skip")
                self.assertEqual(state.load()["backport_skipped"][0]["reason"], "CI change requires manual backport")
                with mock.patch.object(sm, "AzureAI") as ai:
                    sm.phase_classify_backports(mock.Mock(branch="stable-4.x"), state, runner, candidates=[sha])
                ai.assert_not_called()
                value = state.load(); value["backport_candidates"] = [sha]; state.save(value)
                with mock.patch.object(sm, "locked_build") as build, mock.patch.object(sm, "format_backport") as fmt:
                    sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner, adaptive=True)
                build.assert_not_called(); fmt.assert_not_called()
                self.assertEqual(state.load()["backports_deferred"], [sha])
                self.assertEqual(workflow.read_text(), original_workflow)
                self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout.strip(), baseline)
                ai = mock.Mock()
                self.assertFalse(sm.repair_backport(runner, sha, baseline, ai))
                ai.call.assert_not_called()

    def test_ci_admission_sees_quoted_paths_and_both_sides_of_renames(self):
        for case in ("quoted-name", "renamed-out"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                runner = self.repository(Path(tmp) / "repo")
                workflow = runner.root / ".github/workflows/wé.yml"
                workflow.write_text("name: existing\n")
                baseline = self.commit(runner, "Existing workflow")
                runner.git(["branch", "-f", "stable-4.x", baseline])
                if case == "quoted-name":
                    workflow.write_text("name: changed\n")
                    (runner.root / "fix.rs").write_text("fn fix() {}\n")
                else:
                    workflow.rename(runner.root / "source.rs")
                sha = self.commit(runner, "Fix existing behavior")
                self.assertIn(".github/workflows/wé.yml", sm._commit_record(runner, sha)["paths"])
                runner.git(["checkout", "stable-4.x"])
                state = sm.State(Path(tmp) / "state")
                state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
                with mock.patch.object(sm, "locked_build") as build:
                    sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
                build.assert_not_called()
                self.assertEqual(state.load()["backports_deferred"], [sha])
                self.assertEqual(workflow.read_text(), "name: existing\n")

    def test_independent_apply_rejects_ci_added_by_parentless_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            runner.git(["checkout", "--orphan", "root-fixture"])
            workflow = runner.root / ".github/workflows/unreviewed.yml"
            workflow.write_text("name: unreviewed\n")
            sha = self.commit(runner, "Fix via root commit")
            record = sm._commit_record(runner, sha)
            self.assertEqual(record["parents"], 0)
            self.assertIn(".github/workflows/unreviewed.yml", record["paths"])
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "backport_candidates": [sha]})
            with mock.patch.object(sm, "locked_build") as build:
                sm.phase_apply_backports(mock.Mock(branch="stable-4.x"), state, runner)
            build.assert_not_called()
            self.assertEqual(state.load()["backports_deferred"], [sha])
            self.assertFalse(workflow.exists())
            self.assertEqual(runner.git(["rev-parse", "HEAD"]).stdout.strip(), baseline)

    def test_container_manifest_translation_preserves_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); child = root / "src/common/Cargo.toml"
            child.parent.mkdir(parents=True); child.write_text("[dependencies]\nfoo = { workspace = true }\n")
            (root / "Cargo.toml").write_text('[workspace.dependencies]\nfoo = "1.2.0"\n')
            for path, valid in (("/workspace/src/common/Cargo.toml", True), ("/etc/Cargo.toml", False),
                                ("/workspace/../Cargo.toml", False)):
                metadata = {"workspace_members": ["member"], "packages": [{"id": "member", "manifest_path": path},
                    {"id": "foo", "name": "foo", "version": "1.2.0", "source": "registry+https://github.com/rust-lang/crates.io-index"}],
                    "resolve": {"nodes": [{"id": "member", "deps": [{"name": "foo", "pkg": "foo"}]}]}}
                with mock.patch.object(sm, "contained_repo_command", return_value=sm.CommandResult(0, json.dumps(metadata), "")):
                    if valid:
                        mapped = sm.cargo_metadata(sm.Runner(root))
                        target = sm.direct_registry_packages(mapped)[0]
                        sm.update_direct_dependency_manifests(root, mapped, "foo", "1.2.1", target)
                        self.assertIn('foo = "1.2.1"', (root / "Cargo.toml").read_text())
                    else:
                        with self.assertRaises(sm.MaintenanceError):
                            sm.cargo_metadata(sm.Runner(root))

    def test_zero_retry_delay_with_empty_quota_waits_a_window(self):
        ai = object.__new__(sm.AzureAI)
        ai.key, ai.model, ai.url = "key", "model", "https://example.invalid"
        error = sm.HTTPStatusError(429, {"retry-after": "0", "x-ratelimit-remaining-tokens": "0"})
        with mock.patch.object(sm, "http_json", side_effect=[error, {"output_text": '{"decision":true}'}]), \
             mock.patch.object(sm.time, "sleep") as sleep, mock.patch.object(sm.secrets, "randbelow", return_value=0):
            ai.call("instructions", "data", sm.BOOL_SCHEMA, "result")
        sleep.assert_called_once_with(60)

    def test_sequential_build_failure_keeps_earlier_work_and_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            commits = []
            for name in ("earlier", "broken", "later"):
                (runner.root / (name + ".rs")).write_text(name + "\n")
                commits.append(self.commit(runner, "Fix " + name))
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": commits[-1]})
            ai = mock.Mock(); ai.call.return_value = {"decision": True, "reason": "bug-fix"}
            def build(current):
                return sm.CommandResult(101 if (runner.root / "broken.rs").exists() else 0, "", "")
            with mock.patch.object(sm, "AzureAI", return_value=ai), mock.patch.object(sm, "locked_build", side_effect=build), \
                 mock.patch.object(sm, "format_backport"), mock.patch.object(sm.sys, "stderr", io.StringIO()):
                sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
            value = state.load()
            self.assertEqual(value["backports_applied"], [commits[0], commits[2]])
            self.assertEqual(value["backports_deferred"], [commits[1]])
            self.assertEqual([row["outcome"] for row in value["backport_outcomes"]], ["applied", "pending", "applied"])
            self.assertEqual(sm.maintenance_main_through(value), baseline)
            self.assertFalse((runner.root / "broken.rs").exists())

    def test_interrupted_commit_preserves_completed_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            baseline = runner.git(["rev-parse", "HEAD"]).stdout.strip()
            (runner.root / "earlier.rs").write_text("earlier\n"); first = self.commit(runner, "Fix earlier")
            (runner.root / "later.rs").write_text("later\n"); later = self.commit(runner, "Fix later")
            runner.git(["checkout", "stable-4.x"])
            state = sm.State(Path(tmp) / "state")
            state.save({"branch": "stable-4.x", "cutoff": baseline, "main_head": later})
            ai = mock.Mock(); ai.call.return_value = {"decision": True, "reason": "bug-fix"}
            apply = sm.phase_apply_backports
            def fail_later(args, current_state, current_runner, **kwargs):
                if current_state.load()["backport_candidates"] == [later]:
                    raise sm.MaintenanceError("interrupted")
                return apply(args, current_state, current_runner, **kwargs)
            with mock.patch.object(sm, "AzureAI", return_value=ai), \
                 mock.patch.object(sm, "phase_apply_backports", side_effect=fail_later), \
                 mock.patch.object(sm, "locked_build", return_value=sm.CommandResult(0, "", "")), \
                 mock.patch.object(sm, "format_backport"), self.assertRaisesRegex(sm.MaintenanceError, "interrupted"):
                sm.phase_backports(mock.Mock(branch="stable-4.x"), state, runner)
            value = state.load()
            self.assertEqual(value["backports_applied"], [first])
            self.assertEqual(value["backport_inflight"], later)
            self.assertEqual(sm.maintenance_main_through(value), baseline)

    def test_backport_context_omits_generated_metadata_and_labels_excerpts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.repository(Path(tmp) / "repo")
            (runner.root / "Cargo.nix").write_text("generated baseline\n")
            source = runner.root / "value.rs"
            source.write_text("pub fn value() -> u32 { 0 }\n")
            self.commit(runner, "Existing source")
            (runner.root / "Cargo.nix").write_text("generated-line\n" * 100000)
            source.write_text("pub fn value() -> u32 { 1 }\n")
            sha = self.commit(runner, "Fix source with regenerated Nix")
            patch = sm.backport_patch(runner, sm._commit_record(runner, sha))
            self.assertNotIn("generated-line", patch)
            self.assertIn("pub fn value()", patch)
            text = "irrelevant line\n" * 5000 + "pub fn value() -> u32 { 0 }\n" + "more irrelevant\n" * 5000
            excerpt = sm.source_excerpt(text, patch, 2048)
            self.assertIn("EXCERPTS ONLY", excerpt)
            self.assertIn("pub fn value() -> u32 { 0 }", excerpt)
            self.assertLessEqual(len(excerpt.encode()), 2048)


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
                if key[0] == "cherry":
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


