"""Package smoke contracts without root, containers, credentials, or tenant writes."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import package_smoke as smoke
import package_smoke_guest as guest
import package_smoke_results as results


class MatrixTests(unittest.TestCase):
    def test_all_current_package_targets_and_provenance(self):
        sha = smoke.packages.resolve("HEAD")
        matrix = smoke.matrix(sha, 123, 2)
        specs = [json.loads(entry["spec"]) for entry in matrix["include"]]
        makefile = smoke.packages.source_text(sha, "Makefile")
        targets = set()
        for group in ("DEB", "RPM", "SLE"):
            targets.update(smoke.re.search(r"^" + group + r"_TARGETS\s*:=\s*(.+)$", makefile, smoke.re.M)[1].split())
        dists, _ = smoke.packages.generator_config(smoke.packages.source_text(sha, "scripts/gen_dockerfiles.py"))
        expected = {(target, arch) for target in targets for arch in ("amd64", "arm64")
                    if arch == "amd64" or dists[target].get("arm64", True)}
        self.assertEqual({(s["distro"], s["architecture"]) for s in specs}, expected)
        self.assertEqual(len(specs), len(expected))
        for spec in specs:
            self.assertEqual(spec["source_sha"], sha)
            self.assertEqual(spec["channel"], "smoke")
            self.assertTrue(smoke.CORE.issubset(spec["expected"]))
            self.assertTrue(all("ci123.2" in p["version"] for p in spec["expected_packages"]))
            self.assertNotIn("cargo", smoke.containerfile(spec))
            self.assertNotIn("DynamicUser=", smoke.containerfile(spec))

    def test_workflow_only_runs_on_requested_stable_branches(self):
        workflow = (smoke.ROOT / ".github/workflows/package-smoke.yml").read_text()
        triggers = workflow.split("permissions:", 1)[0]
        self.assertEqual(smoke.re.findall(r"^  (\w+):$", triggers, smoke.re.M), ["pull_request", "push"])
        self.assertEqual(smoke.re.findall(r"branches: \[(.+)\]", triggers),
                         ["stable-2.x, stable-3.x, stable-4.x"] * 2)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("pull_request_target", workflow)



class ProbeTests(unittest.TestCase):
    def test_status_success_requires_response_not_just_exit_code(self):
        self.assertFalse(guest.working(subprocess.CompletedProcess([], 0, "", "connection failed")))
        self.assertFalse(guest.working(subprocess.CompletedProcess([], 0, "not working!\n", "")))
        self.assertFalse(guest.working(subprocess.CompletedProcess([], 1, "working!\n", "")))
        self.assertTrue(guest.working(subprocess.CompletedProcess([], 0, "Donation banner\nworking!\n", "")))

    def test_wait_is_bounded_and_preserves_reason(self):
        with patch.object(guest.time, "monotonic", side_effect=[0, 1, 3]), patch.object(guest.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "Timed out waiting for test"):
                guest.wait_for("test", lambda: False, seconds=2)

    def test_nss_compares_short_upn_numeric_and_id(self):
        record = "tux:x:12345:54321:Test User:/home/tux:/bin/bash\n"
        def call(*args, **kwargs):
            if args[:2] == ("getent", "passwd"):
                output = "root:x:0:0:root:/root:/bin/bash\n" if args[2] == "root" else record
            elif args[:2] == ("id", "-u"):
                output = "12345\n"
            elif args[:2] == ("id", "-g"):
                output = "54321\n"
            else:
                output = "uid=12345(tux) gid=54321(tux)\n"
            return subprocess.CompletedProcess(args, 0, output, "")
        with patch.object(guest, "command", side_effect=call), patch.object(guest.Path, "read_text", return_value="root:x:0:0::/:/bin/sh\n"):
            self.assertEqual(guest.identities()[2:4], ["12345", "54321"])
        def inconsistent(*args, **kwargs):
            result = call(*args, **kwargs)
            if args == ("id", "-g", "tux"):
                result.stdout = "0\n"
            return result
        with patch.object(guest, "command", side_effect=inconsistent), patch.object(guest.Path, "read_text", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "GID differs"):
                guest.identities()

    def test_initialized_state_snapshot_detects_lost_machine_key(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, dbpath = root / "himmelblau.conf", root / "cache.db"
            config.write_text("[global]\ndomain = himmelblau-idm.org\n")
            (root / "package-smoke-sentinel").write_text("preserved")
            with sqlite3.connect(str(dbpath)) as db:
                db.execute("CREATE TABLE hsm_int_t (key TEXT PRIMARY KEY, value BLOB)")
                db.executemany("INSERT INTO hsm_int_t VALUES (?, ?)", [("mk", b"machine"), ("hmac", b"hmac")])
            with patch.object(guest, "CONFIG", config), patch.object(guest, "DB", dbpath), \
                 patch.object(guest, "STATE", root), patch.object(guest, "identities", return_value=["tux", "x", "12345", "54321"]):
                before = guest.state_snapshot()
                self.assertEqual(before, guest.state_snapshot())
                with sqlite3.connect(str(dbpath)) as db:
                    db.execute("UPDATE hsm_int_t SET value=? WHERE key='mk'", (b"recreated",))
                self.assertNotEqual(before["keys"], guest.state_snapshot()["keys"])


class BaselineTests(unittest.TestCase):
    spec = {"tag": "4.0.7", "distro": "ubuntu24.04", "format": "deb", "architecture": "amd64", "rpm": "x86_64"}
    metadata = b"Package: himmelblau\nVersion: 4.0.7-ubuntu24.04\nArchitecture: amd64\nFilename: ./core.deb\nSHA256: abc\n\nPackage: nss-himmelblau\nVersion: 4.0.7-ubuntu24.04\nArchitecture: amd64\nFilename: ./nss.deb\nSHA256: def\n"

    def setUp(self):
        cloudsmith = patch.object(smoke, "cloudsmith_baselines", return_value={})
        cloudsmith.start()
        self.addCleanup(cloudsmith.stop)

    def test_public_repository_pair_and_architecture(self):
        def read(url):
            return self.metadata if url.endswith("Packages") else b'<a href="ubuntu24.04/">target</a>'
        with patch.object(smoke, "metadata_bytes", side_effect=read):
            rows = list(smoke.baseline_candidates(self.spec, {(4, 0, 7)}))
        self.assertEqual(len(rows), 1)
        self.assertEqual({r["name"] for r in rows[0]}, smoke.CORE)
        arm = dict(self.spec, architecture="arm64")
        with patch.object(smoke, "metadata_bytes", side_effect=read):
            self.assertEqual(list(smoke.baseline_candidates(arm, {(4, 0, 7)})), [])

    def test_absence_skips_but_outage_fails(self):
        for code in (404, 503):
            error = urllib.error.HTTPError("https://example.invalid", code, "error", {}, None)
            with patch.object(smoke, "metadata_bytes", side_effect=error):
                if code == 404:
                    self.assertEqual(list(smoke.baseline_candidates(self.spec, {(4, 0, 7)})), [])
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        list(smoke.baseline_candidates(self.spec, {(4, 0, 7)}))

    def test_missing_metadata_inside_existing_repository_fails(self):
        error = urllib.error.HTTPError("https://example.invalid", 404, "missing", {}, None)
        with patch.object(smoke, "metadata_bytes", side_effect=[b'<a href="ubuntu24.04/">target</a>', error]):
            with self.assertRaises(urllib.error.HTTPError):
                list(smoke.baseline_candidates(self.spec, {(4, 0, 7)}))

    def test_rpm_metadata_selects_native_architecture(self):
        import gzip
        primary = b'''<metadata xmlns="http://linux.duke.edu/metadata/common">
          <package><name>himmelblau</name><arch>aarch64</arch><version ver="4.0.7" rel="1"/>
          <checksum type="sha256">abc</checksum><location href="core.rpm"/></package>
          <package><name>nss-himmelblau</name><arch>aarch64</arch><version ver="4.0.7" rel="1"/>
          <checksum type="sha256">def</checksum><location href="nss.rpm"/></package></metadata>'''
        repomd = b'''<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">
          <location href="repodata/primary.xml.gz"/></data></repomd>'''
        def read(url):
            if url.endswith("repomd.xml"):
                return repomd
            if url.endswith("primary.xml.gz"):
                return gzip.compress(primary)
            return b'<a href="fedora43/">target</a>'
        spec = dict(self.spec, distro="fedora43", format="rpm", architecture="arm64", rpm="aarch64")
        with patch.object(smoke, "metadata_bytes", side_effect=read):
            self.assertEqual(len(list(smoke.baseline_candidates(spec, {(4, 0, 7)}))), 1)
        with patch.object(smoke, "metadata_bytes", side_effect=read):
            self.assertEqual(list(smoke.baseline_candidates(dict(spec, architecture="amd64", rpm="x86_64"), {(4, 0, 7)})), [])

    def test_corrupt_download_fails(self):
        import io
        row = {"cdn_url": "https://example.invalid/core.deb", "checksum_sha256": "0" * 64,
               "name": "himmelblau", "version": "4.0.7-ubuntu24.04"}
        with tempfile.TemporaryDirectory() as tmp, patch.object(smoke.urllib.request, "urlopen", return_value=io.BytesIO(b"corrupt")):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                smoke.download_baseline([row], Path(tmp) / "baseline", "deb")


class CloudsmithTests(unittest.TestCase):
    def test_new_publisher_metadata_supports_verified_baselines(self):
        spec = {"tag": "4.0.7", "distro": "ubuntu24.04", "format": "deb", "architecture": "amd64",
                "rpm": "x86_64", "destination": "ubuntu/noble", "expected": sorted(smoke.CORE)}
        rows = [{"name": name, "version": "4.0.7-ubuntu24.04", "format": "deb",
                 "distro": {"slug": "ubuntu"}, "distro_version": {"slug": "noble"},
                 "architectures": [{"name": "amd64"}], "is_sync_completed": True,
                 "cdn_url": "https://example.invalid/" + name + ".deb", "checksum_sha256": "a" * 64}
                for name in sorted(smoke.CORE)]
        with patch.object(smoke, "metadata_bytes", return_value=json.dumps(rows).encode()):
            found = smoke.cloudsmith_baselines(spec, {(4, 0, 7)})
        self.assertEqual(found[(4, 0, 7)], rows)
        self.assertTrue(all("checksum_sha256" in row for row in found[(4, 0, 7)]))

    def test_unprovisioned_repository_is_absent_but_outage_fails(self):
        spec = {"tag": "4.0.7", "format": "deb", "destination": "ubuntu/noble"}
        absent = urllib.error.HTTPError("https://example.invalid", 404, "missing", {}, None)
        with patch.object(smoke, "metadata_bytes", side_effect=absent):
            self.assertEqual(smoke.cloudsmith_baselines(spec, set()), {})
        outage = urllib.error.HTTPError("https://example.invalid", 503, "outage", {}, None)
        with patch.object(smoke, "metadata_bytes", side_effect=outage):
            with self.assertRaises(urllib.error.HTTPError):
                smoke.cloudsmith_baselines(spec, set())


class ResultTests(unittest.TestCase):
    def test_required_result_rejects_missing_failed_and_unknown_skips(self):
        matrix = {"include": [{"spec": json.dumps({"distro": "debian13", "architecture": "amd64"})}]}
        jobs = {name: {"result": "success"} for name in ("prepare", "build", "smoke")}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                results.validate(matrix, jobs, root)
            folder = root / "smoke-results-debian13-amd64"
            folder.mkdir()
            path = folder / "result.json"
            for payload in [{"fresh": "failed", "upgrade": "passed"},
                            {"fresh": "passed", "upgrade": "not-run"},
                            {"fresh": "passed", "upgrade": "skipped", "reason": "network error"}]:
                path.write_text(json.dumps(payload))
                with self.assertRaises(ValueError):
                    results.validate(matrix, jobs, root)
            path.write_text(json.dumps({"fresh": "passed", "upgrade": "skipped",
                                        "reason": "No older compatible released daemon/NSS package pair"}))
            results.validate(matrix, jobs, root)
            with self.assertRaises(ValueError):
                results.validate(matrix, dict(jobs, build={"result": "skipped"}), root)
            with self.assertRaises(ValueError):
                results.validate({"include": []}, jobs, root)


class HarnessTests(unittest.TestCase):
    def test_failure_records_result_and_always_cleans_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = smoke.Harness({"distro": "debian13", "architecture": "amd64", "family": "deb",
                                     "image": "debian:13", "runtime_prep": []}, Path(tmp) / "artifacts", Path(tmp) / "logs")
            def boot(mode):
                harness.containers.append("partial-" + mode)
                raise RuntimeError("boot failed")
            with patch.object(smoke.packages, "validate_artifacts", return_value=[]), \
                 patch.object(harness, "run", return_value=0) as run, patch.object(harness, "boot", side_effect=boot), \
                 patch.object(harness, "collect") as collect:
                with self.assertRaisesRegex(RuntimeError, "boot failed"):
                    harness.smoke()
            collect.assert_called_once_with("partial-fresh")
            self.assertIn("rm", run.call_args.args[0])
            self.assertEqual(json.loads((harness.diagnostics / "result.json").read_text())["fresh"], "failed")

    def test_cleanup_attempts_all_containers_after_one_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = smoke.Harness({"distro": "debian13", "architecture": "amd64"}, Path(tmp), Path(tmp) / "logs")
            harness.containers = ["fresh", "upgrade"]
            with patch.object(harness, "collect"), patch.object(harness, "run", side_effect=[1, 0]) as remove:
                with self.assertRaisesRegex(RuntimeError, "cleanup failed: fresh"):
                    harness.cleanup()
                self.assertEqual(remove.call_count, 2)

    def test_upgrade_asserts_preservation_before_lifecycle_commands(self):
        spec = {"distro": "debian13", "architecture": "amd64", "family": "deb", "format": "deb",
                "image": "debian:13", "runtime_prep": []}
        with tempfile.TemporaryDirectory() as tmp:
            harness = smoke.Harness(spec, Path(tmp), Path(tmp) / "logs")
            baseline = [{"name": "himmelblau"}, {"name": "nss-himmelblau"}]
            with patch.object(smoke.packages, "validate_artifacts", return_value=[]), \
                 patch.object(harness, "run", return_value=0), patch.object(harness, "boot", side_effect=["fresh", "upgrade"]), \
                 patch.object(harness, "install") as install, patch.object(harness, "guest") as guest_calls, \
                 patch.object(smoke, "released_versions", return_value={(4, 0, 7)}), \
                 patch.object(smoke, "baseline_candidates", return_value=[baseline]), \
                 patch.object(harness, "older", return_value=True), \
                 patch.object(smoke, "download_baseline", return_value=baseline):
                harness.smoke()
            phases = [call.args[1] for call in guest_calls.call_args_list if call.args[0] == "upgrade"]
            self.assertEqual(phases, ["configure", "start-baseline", "snapshot", "preserved", "lifecycle"])
            self.assertEqual(install.call_count, 3)
            self.assertEqual(json.loads((harness.diagnostics / "result.json").read_text())["upgrade"], "passed")

    def test_manifest_checksum_and_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = {"format": "deb", "source_sha": "a" * 40, "expected": ["himmelblau"],
                    "expected_packages": [{"name": "himmelblau", "version": "1.0-1", "architectures": ["amd64"]}]}
            record = {"name": "himmelblau", "version": "1.0-1", "architecture": "amd64",
                      "filename": "core.deb", "sha256": "0" * 64}
            (root / "core.deb").write_bytes(b"changed")
            (root / "manifest.json").write_text(json.dumps({"spec": spec, "packages": [record]}))
            with self.assertRaisesRegex(ValueError, "integrity"):
                smoke.packages.validate_artifacts(root, spec)
            with self.assertRaisesRegex(ValueError, "provenance"):
                smoke.packages.validate_artifacts(root, dict(spec, source_sha="b" * 40))


if __name__ == "__main__":
    unittest.main()
