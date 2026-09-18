#!/usr/bin/env python3
"""Small release-only adapter around the unchanged self-build containers."""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request


REPOSITORIES = {3: "himmelblau/himmelblau-3", 4: "himmelblau/himmelblau-4"}
DESTINATIONS = {
    "ubuntu22.04": "ubuntu/jammy", "ubuntu24.04": "ubuntu/noble",
    "ubuntu25.10": "ubuntu/questing", "ubuntu26.04": "ubuntu/resolute",
    "debian12": "debian/bookworm", "debian13": "debian/trixie",
    "rocky8": "el/8", "rocky9": "el/9", "rocky10": "el/10",
    "fedora42": "fedora/42", "fedora43": "fedora/43", "fedora44": "fedora/44",
    "amzn2023": "amzn/2023", "tumbleweed": "opensuse/tumbleweed",
    "sle15sp6": "opensuse/15.6", "sle15sp7": "sles/15", "sle16": "opensuse/16.0",
}
# TODO: Enable Rawhide once Cloudsmith supports a distinct Fedora Rawhide index.
EXCLUDED = {"rawhide"}
ARCHITECTURES = {
    "amd64": {"runner": "ubuntu-24.04", "platform": "linux/amd64", "rpm": "x86_64"},
    "arm64": {"runner": "ubuntu-24.04-arm", "platform": "linux/arm64", "rpm": "aarch64"},
}


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def git(*args):
    return run("git", *args)


def ancestor(older, newer):
    result = subprocess.run(["git", "merge-base", "--is-ancestor", older, newer], check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("Cannot check commit ancestry")
    return result.returncode == 0


def resolve(revision):
    # Full-history checkout creates remote-tracking branches, not local branches.
    for candidate in [revision, f"refs/remotes/origin/{revision}"]:
        result = subprocess.run(["git", "rev-parse", "--verify", "--end-of-options",
                                 f"{candidate}^{{commit}}"], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
    raise ValueError("Requested revision does not resolve to a repository commit")


def source_text(commit, path):
    return git("show", f"{commit}:{path}")


def version(commit):
    return tomllib.loads(source_text(commit, "Cargo.toml"))["workspace"]["package"]["version"]


def output(name, value):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(f"{name}={value}\n")


def summary(text):
    print(text)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(text + "\n")


def generator_config(text):
    # Inspect literal configuration without executing source code in the prepare job.
    values = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"DISTS", "PACKAGES"}:
                    values[target.id] = ast.literal_eval(node.value)
    return values["DISTS"], values["PACKAGES"]


def matrix(tag, revision="", distro="all", architecture="all"):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Expected an existing stable tag in MAJOR.MINOR.PATCH form")
    major = int(tag.split(".")[0])
    if major not in REPOSITORIES:
        raise ValueError(f"Stable major {major} is not approved for publication")
    tag_sha = resolve(f"refs/tags/{tag}")
    source_sha = resolve(revision or f"refs/tags/{tag}")
    branch = resolve(f"refs/remotes/origin/stable-{major}.x")
    if not ancestor(tag_sha, source_sha) or not ancestor(source_sha, branch):
        raise ValueError("Source must descend from the release tag and belong to its stable branch")
    if version(tag_sha) != tag or version(source_sha) != tag:
        raise ValueError("Tag and source Cargo workspace versions must both match the release tag")
    if architecture not in {"all", *ARCHITECTURES}:
        raise ValueError("Architecture must be all, amd64 or arm64")
    dists, packages = generator_config(source_text(source_sha, "scripts/gen_dockerfiles.py"))
    makefile = source_text(source_sha, "Makefile")
    targets = []
    for group in ["DEB", "RPM", "SLE"]:
        match = re.search(rf"^{group}_TARGETS\s*:=\s*(.+)$", makefile, re.MULTILINE)
        if not match:
            raise ValueError(f"Cannot find {group}_TARGETS in source Makefile")
        targets.extend(match[1].split())
    if distro != "all" and (distro not in targets or distro in EXCLUDED):
        raise ValueError(f"Unsupported or excluded distro: {distro}")
    if EXCLUDED.intersection(targets):
        print("::warning::Rawhide is excluded: Cloudsmith has no Fedora Rawhide destination (TODO)")
    selected = [t for t in targets if t not in EXCLUDED and distro in {"all", t}]
    entries = []
    for target in selected:
        cfg = dists[target]
        fmt = "deb" if cfg["family"] == "deb" else "rpm"
        if cfg["family"] not in {"deb", "rpm", "zypper"} or target not in DESTINATIONS:
            raise ValueError(f"No approved native Cloudsmith destination for {target}")
        expected = []
        for crate, path, _ in packages:
            if crate == "selinux" and (fmt == "deb" or not cfg.get("selinux")):
                continue
            if crate == "apparmor" and fmt == "rpm" and not cfg.get("apparmor"):
                continue
            metadata = tomllib.loads(source_text(source_sha, f"{path}/Cargo.toml"))["package"]
            section = "deb" if fmt == "deb" else "generate-rpm"
            expected.append(metadata.get("metadata", {}).get(section, {}).get("name", metadata["name"].replace("_", "-")))
        for arch, info in ARCHITECTURES.items():
            if architecture not in {"all", arch} or (arch == "arm64" and not cfg.get("arm64", True)):
                continue
            spec = {"tag": tag, "tag_sha": tag_sha, "source_sha": source_sha,
                    "repository": REPOSITORIES[major], "distro": target,
                    "destination": DESTINATIONS[target], "format": fmt,
                    "architecture": arch, "scc": bool(cfg.get("scc")),
                    "expected": expected, **info}
            entries.append({"spec": json.dumps(spec, separators=(",", ":"))})
    if not entries:
        raise ValueError("No supported targets remain after applying the filters")
    return {"include": entries}


def prepare():
    tag = os.environ.get("RELEASE_TAG", "")
    manual = os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
    if not manual and (not re.fullmatch(r"[34]\.[0-9]+\.[0-9]+", tag)):
        output("enabled", "false")
        summary("Skipping release outside approved stable majors 3 and 4.")
        return
    result = matrix(tag,
                    os.environ.get("REQUESTED_REVISION", "") if manual else "",
                    (os.environ.get("REQUESTED_DISTRO") or "all") if manual else "all",
                    (os.environ.get("REQUESTED_ARCHITECTURE") or "all") if manual else "all")
    output("matrix", json.dumps(result, separators=(",", ":")))
    output("tooling_sha", resolve("HEAD"))
    output("enabled", "true")
    first = json.loads(result["include"][0]["spec"])
    summary(f"Release `{tag}` (tag commit `{first['tag_sha']}`), source `{first['source_sha']}`; {len(result['include'])} build targets.")


def tag_version():
    tag = version("HEAD")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("Invalid Cargo release version")
    major = int(tag.split(".")[0])
    if os.environ.get("GITHUB_REF_NAME") != f"stable-{major}.x" or major not in REPOSITORIES:
        raise ValueError("Cargo version does not match an approved stable branch")
    head = resolve("HEAD")
    exists = subprocess.run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"], check=False)
    if exists.returncode == 0:
        previous = resolve(f"refs/tags/{tag}")
        if not ancestor(previous, head):
            raise ValueError(f"Conflicting release tag {tag}; refusing to move it")
        dispatch = previous == head
        summary(f"Tag {tag} already exists; {'retrying dispatch' if dispatch else 'version unchanged, no new release'}.")
    elif exists.returncode == 1:
        subprocess.run(["git", "tag", tag, head], check=True)
        subprocess.run(["git", "push", "origin", f"refs/tags/{tag}"], check=True)
        dispatch = True
    else:
        raise RuntimeError("Cannot check release tag")
    output("tag", tag)
    output("dispatch", str(dispatch and major in REPOSITORIES and
                           os.environ.get("GITHUB_REF_NAME") == f"stable-{major}.x" and
                           bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tag))).lower())


def package_metadata(image, source, path, spec):
    command = ["docker", "run", "--rm", "--platform", spec["platform"],
               "--network", "none", "-v", f"{source}:/himmelblau:ro"]
    inside = "/himmelblau/" + str(path.relative_to(source))
    if spec["format"] == "deb":
        command += ["--entrypoint", "dpkg-deb", image, "--field", inside,
                    "Package", "Version", "Architecture"]
        fields = dict(line.split(": ", 1) for line in run(*command).splitlines())
        name, ver, arch = (fields[k] for k in ["Package", "Version", "Architecture"])
        upstream = ver.split("-", 1)[0]
        allowed = {spec["architecture"], "all"}
    else:
        command += ["--entrypoint", "rpm", image, "-qp", "--qf",
                    "%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n%{EPOCHNUM}\n", inside]
        name, ver, arch, epoch = run(*command).splitlines()
        if epoch != "0":
            raise ValueError("Unexpected package epoch")
        upstream = ver.rsplit("-", 1)[0]
        allowed = {spec["rpm"], "noarch"}
    if upstream != spec["tag"] or arch not in allowed:
        raise ValueError(f"Unexpected version or architecture in {path.name}: {ver}, {arch}")
    return {"name": name, "version": ver, "architecture": arch}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build(source, artifacts, spec):
    source, artifacts = source.resolve(), artifacts.resolve()
    if run("git", "rev-parse", "HEAD", cwd=source) != spec["source_sha"]:
        raise ValueError("Build checkout does not match resolved source")
    image = f"himmelblau-stable-{spec['distro']}-{spec['architecture']}"
    (source / "target").mkdir(exist_ok=True)
    (source / "packaging").mkdir(exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="stable-package-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        temporary = Path(temporary)
        subprocess.run(["python3", "scripts/gen_dockerfiles.py", "--only", spec["distro"],
                        "--out", str(temporary / "images")], cwd=source, check=True)
        # Default Dockerfiles are architecture-neutral; compile on the native runner.
        command = ["docker", "build", "--platform", spec["platform"], "--progress", "plain",
                   "-t", image, "-f", str(temporary / "images" / f"Dockerfile.{spec['distro']}")]
        if spec["scc"]:
            email, regcode = os.environ.get("SCC_EMAIL", ""), os.environ.get("SCC_REGCODE", "")
            if not email or not regcode:
                raise ValueError("SUSE builds require SCC_EMAIL and SCC_REGCODE secrets")
            secret = temporary / "scc_regcode"
            with open(secret, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                stream.write(f"email={shlex.quote(email)}\nregcode={shlex.quote(regcode)}\n")
            command += ["--secret", f"id=scc_regcode,src={secret}"]
        try:
            subprocess.run(command + [str(source)], check=True, env={**os.environ, "DOCKER_BUILDKIT": "1"})
            subprocess.run(["docker", "run", "--rm", "--platform", spec["platform"],
                            "--security-opt", "label=disable", "-v", f"{source}:/himmelblau",
                            "-v", f"{source / 'target'}:/himmelblau/target", image], check=True)
            directory = source / "target" / ("debian" if spec["format"] == "deb" else "generate-rpm")
            records = []
            for path in sorted(directory.glob(f"*.{spec['format']}")):
                record = package_metadata(image, source, path, spec)
                filename = path.name if spec["format"] == "deb" else f"{path.stem}-{spec['distro']}.rpm"
                shutil.copyfile(path, artifacts / filename)
                records.append({**record, "filename": filename, "sha256": digest(artifacts / filename)})
            names = [p["name"] for p in records]
            if sorted(names) != sorted(spec["expected"]):
                raise ValueError(f"Incomplete or unexpected package set: expected {spec['expected']}, got {names}")
            (artifacts / "manifest.json").write_text(json.dumps({"spec": spec, "packages": records}, indent=2) + "\n")
            summary(f"Built `{spec['distro']}` / `{spec['architecture']}` for `{spec['tag']}` from `{spec['source_sha']}`: {len(records)} packages.")
        finally:
            subprocess.run(["docker", "image", "rm", "-f", image], check=False, stdout=subprocess.DEVNULL)


def api_packages(repository, fmt, tag):
    # Include untagged packages, but avoid scanning the repository's entire history.
    packages, page = [], 1
    while True:
        query = urllib.parse.urlencode({"query": f"format:{fmt} version:{tag}-*", "page_size": 100, "page": page})
        request = urllib.request.Request(f"https://api.cloudsmith.io/v1/packages/{repository}/?{query}",
                                         headers={"X-Api-Key": os.environ["CLOUDSMITH_API_KEY"]})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    rows = json.load(response)
                break
            except urllib.error.HTTPError as exc:
                if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                    raise RuntimeError(f"Cloudsmith package lookup failed (HTTP {exc.code}); no credentials logged") from None
                time.sleep(2 ** attempt)
            except urllib.error.URLError:
                if attempt == 2:
                    raise RuntimeError("Cloudsmith package lookup failed; no credentials logged") from None
                time.sleep(2 ** attempt)
        packages.extend(rows)
        if len(rows) < 100:
            return packages
        page += 1


def existing_identity(remote, local, spec):
    distro, release = spec["destination"].split("/")
    architectures = {a["name"] for a in remote.get("architectures", [])}
    return (remote.get("format") == spec["format"] and remote.get("name") == local["name"] and
            remote.get("version") == local["version"] and remote.get("epoch") in (None, 0, "0") and
            (remote.get("distro") or {}).get("slug") == distro and
            (remote.get("distro_version") or {}).get("slug") == release and
            local["architecture"] in architectures)


def upload_plan(records, remote_packages, spec):
    missing, pending = [], False
    markers = {f"release-{spec['tag']}", f"source-{spec['source_sha']}"}
    for local in records:
        matches = [remote for remote in remote_packages if existing_identity(remote, local, spec)]
        if len(matches) > 1:
            raise ValueError(f"Multiple existing packages match {local['name']}; refusing publication")
        if not matches:
            missing.append(local)
            continue
        remote = matches[0]
        tags = {tag for values in remote.get("tags", {}).values() for tag in values}
        if not markers.issubset(tags):
            raise ValueError(f"Existing {local['name']} {local['version']} comes from another or unknown source; no packages replaced")
        if remote.get("is_sync_failed"):
            raise ValueError(f"Existing {local['name']} failed Cloudsmith synchronization; DevOps must resolve it")
        pending |= not remote.get("is_sync_completed", False)
    return missing, pending


def validate_artifacts(artifacts, spec):
    manifest = json.loads((artifacts / "manifest.json").read_text())
    if manifest["spec"] != spec:
        raise ValueError("Artifact provenance does not match this target")
    records = manifest["packages"]
    if sorted(p["name"] for p in records) != sorted(spec["expected"]):
        raise ValueError("Artifact package set is incomplete or unexpected")
    filenames = {"manifest.json"}
    for record in records:
        name = record["filename"]
        if Path(name).name != name or not name.endswith(f".{spec['format']}") or name in filenames:
            raise ValueError("Unsafe or duplicate artifact filename")
        path = artifacts / name
        if path.is_symlink() or not path.is_file() or digest(path) != record["sha256"]:
            raise ValueError(f"Artifact integrity check failed: {name}")
        filenames.add(name)
    if {p.name for p in artifacts.iterdir()} != filenames:
        raise ValueError("Unexpected files in package artifact")
    return records


def publish(artifacts, spec):
    if not os.environ.get("CLOUDSMITH_API_KEY"):
        raise ValueError("CLOUDSMITH_API_KEY is missing; the workflow supplies it from CLOUDSMITH_PACKAGE_PUBLISHER")
    records = validate_artifacts(artifacts, spec)
    for attempt in range(30):
        missing, pending = upload_plan(records, api_packages(spec["repository"], spec["format"], spec["tag"]), spec)
        if not pending:
            break
        if attempt == 29:
            raise RuntimeError("Existing Cloudsmith packages did not synchronize within five minutes")
        time.sleep(10)
    tags = f"release-{spec['tag']},source-{spec['source_sha']},distro-{spec['distro']}"
    for record in missing:
        subprocess.run(["cloudsmith", "push", spec["format"],
                        f"{spec['repository']}/{spec['destination']}",
                        str(artifacts / record["filename"]), "--no-republish", "--tags", tags], check=True)
    # Check the resulting identities and synchronization even after an interrupted prior run.
    remaining, pending = upload_plan(records, api_packages(spec["repository"], spec["format"], spec["tag"]), spec)
    if remaining or pending:
        raise RuntimeError("Cloudsmith verification did not find the complete synchronized package set")
    summary(f"Published `{spec['distro']}` / `{spec['architecture']}` to `{spec['repository']}/{spec['destination']}`: {len(missing)} uploaded, {len(records) - len(missing)} already present; source `{spec['source_sha']}`.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "tag", "build", "publish"])
    parser.add_argument("--source", type=Path, default=Path("source"))
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare()
        elif args.command == "tag":
            tag_version()
        else:
            spec = json.loads(os.environ["TARGET_SPEC"])
            if args.command == "build":
                build(args.source, args.artifacts, spec)
            else:
                publish(args.artifacts, spec)
    except (ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Stable package operation failed: {exc}\n")


if __name__ == "__main__":
    main()
