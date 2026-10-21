#!/usr/bin/env python3
"""Build existing distro packages and test them under a real Podman systemd."""

import argparse
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

import release_automation as releases

import nightly_packages
import stable_packages as packages

ROOT = Path(__file__).resolve().parents[2]
CORE = {"himmelblau", "nss-himmelblau"}
UNITS = ["himmelblaud.service", "himmelblaud-tasks.service",
         "himmelblaud.socket", "himmelblaud-tasks.socket", "himmelblaud-broker.socket",
         "himmelblau-hsm-pin-init.service"]


def matrix(sha, run_id, attempt):
    # The publisher already derives distro and architecture coverage from source.
    result = nightly_packages.matrix(sha, "20000101", str(run_id))
    dists, _ = packages.generator_config(packages.source_text(sha, "scripts/gen_dockerfiles.py"))
    for entry in result["include"]:
        spec = json.loads(entry["spec"])
        cfg = dists[spec["distro"]]
        spec["channel"] = "smoke"
        suffix = f"ci{run_id}.{attempt}"
        spec["deb_revision_append"] = f"+{suffix}"
        spec["rpm_package_release"] = f"1.{suffix}"
        for package in spec["expected_packages"]:
            package["version"] = (f"{spec['tag']}-{spec['distro']}+{suffix}" if spec["format"] == "deb"
                                  else f"{spec['tag']}-1.{suffix}")
        spec["family"] = cfg["family"]
        spec["image"] = ("registry.suse.com/bci/bci-base:15.7" if spec["distro"] == "sle15sp7"
                         else cfg["image"])
        # Podman must not prompt for a registry when Docker's config uses short names.
        registry, separator, _ = spec["image"].partition("/")
        if not separator or not ("." in registry or ":" in registry or registry == "localhost"):
            spec["image"] = "docker.io/" + spec["image"]
        if cfg.get("scc"):
            raise ValueError(f"Secret-dependent target needs an explicit coverage decision: {spec['distro']}")
        # Reuse public repository setup, without the compiler/development bootstrap.
        spec["runtime_prep"] = [line.removeprefix("RUN ") for line in cfg.get("extra_prep", [])
                                if "python39" not in line and "rawhide" != spec["distro"]]
        if not CORE.issubset(spec["expected"]):
            raise ValueError("Daemon and NSS artifacts are required")
        entry["spec"] = json.dumps(spec, separators=(",", ":"))
    return result


def containerfile(spec):
    family = spec["family"]
    if family == "deb":
        install = ("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
                   "systemd systemd-sysv dbus ca-certificates python3 libnss-systemd coreutils procps")
    elif family == "rpm":
        install = "dnf -y install systemd dbus ca-certificates python3 glibc-common coreutils procps-ng && dnf clean all"
    elif family == "zypper":
        install = ("zypper --non-interactive --gpg-auto-import-keys refresh && "
                   "zypper --non-interactive install --no-recommends systemd dbus-1 ca-certificates "
                   "python3 glibc coreutils procps && zypper clean --all")
    else:
        raise ValueError(f"Unsupported runtime family: {family}")
    prep = "".join(f"RUN {line}\n" for line in spec["runtime_prep"])
    return (f"FROM {spec['image']}\n{prep}RUN {install}\n"
            "RUN mkdir -p /home /etc/krb5.conf.d /var/lib/systemd && "
            "rm -f /etc/machine-id /var/lib/dbus/machine-id /usr/sbin/policy-rc.d && "
            "touch /etc/machine-id\n"
            "STOPSIGNAL SIGRTMIN+3\nCMD [\"/usr/lib/systemd/systemd\"]\n")


def request_json(url):
    headers = {"User-Agent": "himmelblau-package-smoke", "Accept": "application/json"}
    if url.startswith("https://api.github.com/") and os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
                return json.load(response)
        except (OSError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def released_versions():
    versions = set()
    for page in range(1, 101):
        rows = request_json(f"https://api.github.com/repos/himmelblau-idm/himmelblau/releases?per_page=100&page={page}")
        for row in rows:
            tag = row["tag_name"]
            if not row["draft"] and not row["prerelease"] and re.fullmatch(r"\d+\.\d+\.\d+", tag):
                versions.add(tuple(map(int, tag.split("."))))
        if len(rows) < 100:
            return versions
    raise RuntimeError("Release pagination exceeded limit")


def metadata_bytes(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404 or error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
        except OSError:
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)


def cloudsmith_baselines(spec, released):
    """New publishers use Cloudsmith; older releases remain on the public package host."""
    found = {}
    for major, repository in packages.REPOSITORIES.items():
        if major > int(spec["tag"].split(".")[0]):
            continue
        rows = []
        for page in range(1, 101):
            query = urllib.parse.urlencode({"query": f"format:{spec['format']} distribution:{spec['destination']}",
                                            "page_size": 100, "page": page})
            try:
                batch = json.loads(metadata_bytes(f"https://api.cloudsmith.io/v1/packages/{repository}/?{query}"))
            except urllib.error.HTTPError as error:
                if error.code == 404 and page == 1:
                    break  # The public repository has not been provisioned.
                raise
            rows.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise RuntimeError("Cloudsmith pagination exceeded limit")
        for version in released:
            selected = []
            for name in sorted(CORE):
                matches = [row for row in rows if row.get("name") == name
                           and packages.release_version(row) == version
                           and packages.target_package(row, spec)
                           and packages.serves_architecture(row, spec, spec["architecture"])
                           and row.get("is_sync_completed") and not row.get("is_sync_failed")]
                if len(matches) > 1:
                    raise ValueError(f"Ambiguous released baseline: {name}, {version}")
                if not matches:
                    break
                selected.extend(matches)
            if len(selected) == len(CORE):
                found[version] = selected
    return found


def baseline_candidates(spec, released):
    """Read the existing public release repositories; absence is distinct from outage."""
    current = tuple(map(int, spec["tag"].split(".")))
    cloudsmith = cloudsmith_baselines(spec, released)
    for version in sorted((v for v in released if v <= current), reverse=True):
        if version in cloudsmith:
            yield cloudsmith[version]
            continue
        tag = ".".join(map(str, version))
        root = releases.package_url(tag, spec["format"], "")
        try:
            index = metadata_bytes(root).decode()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue  # This published release has no repository in this format.
            raise
        directory = spec["distro"] + ("-arm64" if spec["format"] == "deb" and spec["architecture"] == "arm64" else "")
        if directory + "/" not in releases.parse_index_links(index):
            continue
        base = urllib.parse.urljoin(root, directory + "/")
        if spec["format"] == "deb":
            text = metadata_bytes(base + "Packages").decode()
            rows = []
            for paragraph in re.split(r"\n\s*\n", text.strip()):
                fields = dict(line.split(": ", 1) for line in paragraph.splitlines()
                              if line and not line[0].isspace() and ": " in line)
                if fields.get("Architecture") not in (spec["architecture"], "all"):
                    continue
                filename = releases.safe_metadata_path(fields.get("Filename", "").removeprefix("./"))
                if filename:
                    rows.append({"name": fields.get("Package"), "version": fields.get("Version"),
                                 "cdn_url": urllib.parse.urljoin(base, filename),
                                 "checksum_sha256": fields.get("SHA256")})
        else:
            repomd = metadata_bytes(base + "repodata/repomd.xml").decode()
            href = releases.safe_metadata_path(releases.rpm_primary_href(repomd))
            if not href:
                raise ValueError("Unsafe RPM metadata location")
            primary = metadata_bytes(urllib.parse.urljoin(base, href))
            if href.endswith(".gz"):
                primary = gzip.decompress(primary)
            rows = []
            for artifact in releases.parse_rpm_primary(primary, base, tag, spec["distro"], "himmelblau-idm/himmelblau"):
                if artifact.kind not in ("rpm:" + spec["rpm"], "rpm:noarch"):
                    continue
                rows.append({"name": artifact.name, "version": artifact.version,
                             "cdn_url": artifact.artifact_url,
                             "checksum_sha256": artifact.digest.removeprefix("sha256:")})
        selected = []
        for name in sorted(CORE):
            matches = [row for row in rows if row["name"] == name
                       and packages.release_version(row) == version]
            if len(matches) > 1:
                raise ValueError(f"Ambiguous released baseline: {name}, {version}")
            if not matches:
                break
            selected.extend(matches)
        if len(selected) == len(CORE):
            yield selected


def download_baseline(rows, directory, fmt):
    directory.mkdir()
    records = []
    for index, row in enumerate(rows):
        url, checksum = row["cdn_url"], row["checksum_sha256"]
        if not url.startswith("https://") or not re.fullmatch(r"[a-fA-F0-9]{64}", checksum):
            raise ValueError("Invalid release download metadata")
        path = directory / f"baseline-{index}.{fmt}"
        with urllib.request.urlopen(url, timeout=60) as response, path.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
        if packages.digest(path).lower() != checksum.lower():
            raise ValueError("Release package checksum mismatch")
        records.append({"name": row["name"], "version": row["version"], "filename": path.name})
    return records


class Harness:
    def __init__(self, spec, artifacts, diagnostics):
        self.spec, self.artifacts, self.diagnostics = spec, artifacts.resolve(), diagnostics.resolve()
        self.prefix = f"himmelblau-smoke-{spec['distro']}-{spec['architecture']}"
        self.containers = []
        self.image = self.prefix + ":runtime"
        self.diagnostics.mkdir(parents=True, exist_ok=True)

    def run(self, command, *, timeout=120, check=True):
        print("+", " ".join(map(str, command)), flush=True)
        with (self.diagnostics / "commands.log").open("a") as log:
            log.write("+ " + " ".join(map(str, command)) + "\n")
            log.flush()
            result = subprocess.run(list(map(str, command)), stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"Command failed ({result.returncode}); see commands.log: {command}")
        return result.returncode

    def exec(self, container, *args, timeout=120, check=True):
        return self.run(["podman", "exec", container, *args], timeout=timeout, check=check)

    def guest(self, container, phase, *args, timeout=300):
        return self.exec(container, "python3", "/smoke/package_smoke_guest.py", phase, *args, timeout=timeout)

    def boot(self, mode):
        name = self.prefix + "-" + mode
        self.containers.append(name)  # Register before run, including partial failures.
        self.run(["podman", "run", "--detach", "--name", name, "--privileged", "--systemd=always",
                  "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/tmp", "--tmpfs", "/run/lock",
                  "--volume", f"{self.artifacts}:/packages:ro",
                  "--volume", f"{ROOT / '.github/scripts'}:/smoke:ro", self.image])
        self.guest(name, "boot", timeout=150)
        return name

    def install(self, container, records, directory="/packages"):
        paths = [f"{directory}/{p['filename']}" for p in records if p["name"] in CORE]
        if len(paths) != len(CORE):
            raise ValueError("Missing daemon/NSS package")
        family = self.spec["family"]
        if family == "deb":
            self.exec(container, "apt-get", "update", timeout=900)
            command = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
                       "-o", "Dpkg::Options::=--force-confold", *paths]
        elif family == "rpm":
            command = ["dnf", "install", "-y", *paths]
        else:
            command = ["zypper", "--non-interactive", "--no-gpg-checks", "install", *paths]
        self.exec(container, *command, timeout=900)
        self.guest(container, "versions", family, json.dumps([p for p in records if p["name"] in CORE]))

    def older(self, container, rows):
        expected = {p["name"]: p["version"] for p in self.spec["expected_packages"]}
        for row in rows:
            # Validate before passing strings to rpm's Lua expression.
            if not re.fullmatch(r"[A-Za-z0-9.+~_-]+", row["version"]):
                raise ValueError("Invalid baseline package version")
            if self.spec["format"] == "deb":
                command = ["dpkg", "--compare-versions", row["version"], "lt", expected[row["name"]]]
                not_older = 1
            else:
                expression = f'%{{lua: if rpm.vercmp("{row["version"]}", "{expected[row["name"]]}") < 0 then print("older") else print("not-older") end}}'
                # Have the guest assert rpm's result, rather than its unconditional zero exit status.
                command = ["python3", "/smoke/package_smoke_guest.py", "rpm-older", expression]
                not_older = 3  # Keep a valid false result distinct from guest/runtime failures.
            code = self.exec(container, *command, check=False)
            if code == not_older:
                return False
            if code:
                raise RuntimeError("Native package version comparison failed")
        return True

    def collect(self, container):
        for label, command in [
            ("container", ["podman", "inspect", container]),
            ("logs", ["podman", "logs", container]),
            ("journal", ["podman", "exec", container, "journalctl", "--no-pager", "-b", "-n", "2000"]),
            ("himmelblau-journal", ["podman", "exec", container, "journalctl", "--no-pager", "-b",
                                    *[arg for unit in UNITS for arg in ("--unit", unit)]]),
            ("failed", ["podman", "exec", container, "systemctl", "--no-pager", "--failed"]),
            *[(label, ["podman", "exec", container, "systemctl", "--no-pager", verb, *UNITS])
              for label, verb in [("status", "status"), ("properties", "show"), ("units", "cat")]],
        ]:
            try:
                with (self.diagnostics / f"{container}-{label}.log").open("w") as stream:
                    subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                print(f"Diagnostic collection failed: {error}", flush=True)

    def cleanup(self):
        failures = []
        for container in self.containers:
            self.collect(container)
            try:
                if self.run(["podman", "rm", "--force", "--time", "10", container], check=False, timeout=45):
                    failures.append(container)
            except (OSError, subprocess.TimeoutExpired) as error:
                failures.append(f"{container}: {error}")
        if failures:
            raise RuntimeError("Container cleanup failed: " + ", ".join(failures))

    def smoke(self):
        records = packages.validate_artifacts(self.artifacts, self.spec)
        result = {"fresh": "failed", "upgrade": "not-run"}
        try:
            context = self.diagnostics / "image"
            context.mkdir()
            (context / "Containerfile").write_text(containerfile(self.spec))
            self.run(["podman", "build", "--tag", self.image, context], timeout=900)
            fresh = self.boot("fresh")
            self.install(fresh, records)
            self.guest(fresh, "configure")
            self.guest(fresh, "start")
            self.guest(fresh, "lifecycle", timeout=600)
            result["fresh"] = "passed"
            # Discovery is independent of the fresh test; an outage cannot become a skip.
            upgrade = self.boot("upgrade")
            baseline = next((rows for rows in baseline_candidates(self.spec, released_versions())
                             if self.older(upgrade, rows)), None)
            if baseline is None:
                result.update(upgrade="skipped", reason="No older compatible released daemon/NSS package pair")
                return
            directory = self.diagnostics / "baseline"
            old_records = download_baseline(baseline, directory, self.spec["format"])
            self.run(["podman", "cp", directory, f"{upgrade}:/baseline"])
            self.install(upgrade, old_records, "/baseline")
            self.guest(upgrade, "configure")
            self.guest(upgrade, "start-baseline")
            self.guest(upgrade, "snapshot")
            result["baseline"] = old_records
            result["upgrade"] = "failed"
            self.install(upgrade, records)
            # Do not start/restart here: package scripts must preserve running service state.
            self.guest(upgrade, "preserved")
            self.guest(upgrade, "lifecycle", timeout=600)
            result["upgrade"] = "passed"
        finally:
            (self.diagnostics / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            packages.summary(f"{self.spec['distro']} / {self.spec['architecture']}: {json.dumps(result)}")
            primary_failure = sys.exc_info()[0] is not None
            try:
                self.cleanup()
            except Exception as error:
                if not primary_failure:
                    raise
                print(f"Cleanup also failed (preserving original failure): {error}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "build", "smoke"])
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--diagnostics", type=Path, default=Path("diagnostics"))
    args = parser.parse_args()
    if args.command == "prepare":
        sha = packages.resolve("HEAD")
        packages.output("matrix", json.dumps(matrix(sha, int(os.environ["GITHUB_RUN_ID"]),
                                                   int(os.environ["GITHUB_RUN_ATTEMPT"])), separators=(",", ":")))
    else:
        spec = json.loads(os.environ["TARGET_SPEC"])
        if packages.resolve("HEAD") != spec["source_sha"]:
            raise ValueError("Checkout does not match matrix source SHA")
        if args.command == "build":
            packages.build(Path.cwd(), args.artifacts, spec)
        else:
            Harness(spec, args.artifacts, args.diagnostics).smoke()


if __name__ == "__main__":
    main()
