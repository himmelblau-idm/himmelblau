#!/usr/bin/env python3
"""Build, sign and publish stable/nightly DDIs without build-host."""

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tarfile
import time
import urllib.request

import ddi_image as image
import nightly_packages as nightly
import stable_packages as packages


SCRIPTS = Path(__file__).resolve().parent
NIGHTLY_REPOSITORY = "himmelblau/v_4"
NIGHTLY_TIMESTAMP_FORMAT = "%Y-%m-%d.%H%M%S%f"
CHECKSUM_FILES = {
    "SHA256SUMS": ("sysupdate-checksums", "text/plain"),
    "SHA256SUMS.gpg": ("sysupdate-signature", "application/pgp-signature"),
}


def matrix(channel, tag="", revision="", distro="all", architecture="all", timestamp=None,
           shared_packages=None):
    shared = ([json.loads(entry["spec"]) for entry in shared_packages["include"]]
              if shared_packages is not None else [])
    if shared_packages is not None and not shared:
        raise ValueError("The native package matrix must not be empty")
    if channel == "stable":
        package_matrix = packages.matrix(tag, revision)
        first = json.loads(package_matrix["include"][0]["spec"])
        source_sha, tag_sha, repository = first["source_sha"], first["tag_sha"], first["repository"]
        label, upstream = tag, tag
    elif channel == "nightly":
        if tag or revision:
            raise ValueError("Nightly DDIs always use main, without a tag or revision override")
        source_sha = tag_sha = packages.resolve(
            shared[0]["source_sha"] if shared else "refs/remotes/origin/main"
        )
        upstream = packages.version(source_sha)
        if not re.fullmatch(r"\d+\.\d+\.\d+", upstream):
            raise ValueError("Nightly source must have a MAJOR.MINOR.PATCH workspace version")
        repository = NIGHTLY_REPOSITORY
        build_time = (dt.datetime.strptime(timestamp, NIGHTLY_TIMESTAMP_FORMAT) if timestamp
                      else dt.datetime.now(dt.timezone.utc))
        if shared:
            nightly_date, run_number, short_sha = nightly.build_key(shared[0]["nightly_id"])
            if short_sha != source_sha[:12] or not packages.ancestor(source_sha, "refs/remotes/origin/main"):
                raise ValueError("Native nightly packages must come from the resolved main source")
            if build_time.strftime("%Y%m%d") != nightly_date:
                raise ValueError("DDI timestamp must use the native package build's UTC date")
            package_matrix = nightly.matrix(source_sha, nightly_date, run_number)
        else:
            package_matrix = packages.source_matrix(upstream, tag_sha, source_sha, repository)
        label = f"{build_time.strftime(NIGHTLY_TIMESTAMP_FORMAT)}-{source_sha[:12]}"
    else:
        raise ValueError("Channel must be stable or nightly")
    if architecture not in {"all", *packages.ARCHITECTURES}:
        raise ValueError("Architecture must be all, amd64 or arm64")

    dists, _ = packages.generator_config(packages.source_text(source_sha, "scripts/gen_dockerfiles.py"))
    makefile = packages.source_text(source_sha, "Makefile")
    targets = []
    for group in ("DEB", "RPM", "SLE", "ARCH"):
        match = re.search(rf"^{group}_TARGETS\s*:=\s*(.+)$", makefile, re.MULTILINE)
        if match:
            targets.extend(match[1].split())
    if distro != "all" and distro not in targets:
        raise ValueError(f"Unsupported DDI distro: {distro}")
    fedora_targets = [t for t in targets if re.fullmatch(r"fedora\d+", t)]
    if not fedora_targets:
        raise ValueError("A supported, released Fedora target is required for portable DDIs")
    fedora = max(fedora_targets, key=lambda target: int(target.removeprefix("fedora")))
    native_packages = {
        (spec["distro"], spec["architecture"]): spec
        for entry in package_matrix["include"]
        for spec in [json.loads(entry["spec"])]
    }
    for spec in shared:
        if native_packages.get((spec["distro"], spec["architecture"])) != spec:
            raise ValueError("Native package spec does not match the resolved DDI source")
    entries = {}
    for target in targets:
        if distro not in ("all", target):
            continue
        cfg = dists[target]
        for arch, info in packages.ARCHITECTURES.items():
            if architecture not in ("all", arch):
                continue
            package = native_packages.get((target, arch))
            if package is None and (cfg["family"] != "arch" or arch != "amd64"):
                continue
            entries[(target, arch)] = {
                "channel": channel, "version": label, "upstream": upstream,
                "source_sha": source_sha, "tag_sha": tag_sha, "repository": repository,
                "distro": target, "architecture": arch, "fedora": fedora,
                "scc": bool(cfg.get("scc")), "package": package,
                "kinds": ["sysext"], **info,
            }
    if not entries:
        raise ValueError("No supported DDI targets remain after applying the filters")
    for arch in {entry["architecture"] for entry in entries.values()}:
        package = native_packages.get((fedora, arch))
        if package is None:
            raise ValueError(f"The latest Fedora target does not support {arch}")
        entry = entries.setdefault((fedora, arch), {
            "channel": channel, "version": label, "upstream": upstream,
            "source_sha": source_sha, "tag_sha": tag_sha, "repository": repository,
            "distro": fedora, "architecture": arch, "fedora": fedora,
            "scc": False, "package": package, "kinds": [], **packages.ARCHITECTURES[arch],
        })
        entry["kinds"].append("portable")
    return {"include": [{"spec": json.dumps(entry, separators=(",", ":"))}
                        for _, entry in sorted(entries.items())]}


def prepare():
    shared = json.loads(value) if (value := os.environ.get("DDI_PACKAGE_MATRIX")) else None
    result = matrix(
        os.environ["DDI_CHANNEL"], os.environ.get("RELEASE_TAG", ""),
        os.environ.get("REQUESTED_REVISION", ""),
        os.environ.get("REQUESTED_DISTRO") or "all",
        os.environ.get("REQUESTED_ARCHITECTURE") or "all",
        timestamp=os.environ.get("DDI_TIMESTAMP"),
        shared_packages=shared,
    )
    publish_targets = {
        (spec["distro"], spec["architecture"])
        for entry in shared["include"] for spec in [json.loads(entry["spec"])]
    } if shared is not None else set()
    native, direct = [], []
    for entry in result["include"]:
        spec = json.loads(entry["spec"])
        target = {
            "spec": json.dumps(spec["package"], separators=(",", ":")) if spec["package"] is not None else "",
            "ddi_spec": entry["spec"],
            "publish_packages": (spec["distro"], spec["architecture"]) in publish_targets,
        }
        if spec["package"] is None:
            direct.append(target)
        else:
            native.append(target)
    packages.output("matrix", json.dumps({"include": native + direct}, separators=(",", ":")))
    packages.output("tooling_sha", packages.resolve("HEAD"))
    packages.summary(f"Selected {len(native)} native package targets with DDIs and {len(direct)} direct DDI targets.")


def expected_images(spec):
    arch = image.ARCHITECTURES[spec["architecture"]][0]
    result = []
    for kind in spec["kinds"]:
        if kind == "portable":
            filename = f"himmelblaud_{spec['version']}-{arch}.raw"
            name = f"himmelblau-{spec['channel']}-portable-{arch}"
        elif kind == "sysext":
            filename = f"himmelblau_{spec['version']}-{spec['distro']}-{arch}.sysext.raw"
            name = f"himmelblau-{spec['channel']}-{spec['distro']}-{arch}-sysext"
        else:
            raise ValueError(f"Invalid DDI kind: {kind}")
        result.append({"kind": kind, "filename": filename, "name": name, "version": spec["version"]})
    return result


def update_source(spec, record):
    return f"https://dl.cloudsmith.io/public/{spec['repository']}/raw/names/{record['name']}/files"


def format_checksums(checksums):
    lines = []
    for filename, digest in sorted(checksums.items()):
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*\.raw", filename)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("Invalid sysupdate image filename or SHA256 digest")
        lines.append(f"{digest} *{filename}\n")
    if not lines:
        raise ValueError("A sysupdate manifest must contain at least one image")
    return "".join(lines).encode("ascii")


def write_checksums(directory, checksums, signing):
    manifest = directory / "SHA256SUMS"
    manifest.write_bytes(format_checksums(checksums))
    manifest.chmod(0o644)
    image.sign_detached(manifest, directory / "SHA256SUMS.gpg", signing)


def remote_plan(spec, expected_hashes=None):
    remotes = packages.api_packages(spec["repository"], "raw", spec["version"])
    missing, pending = [], False
    for record in expected_images(spec):
        matches = [
            remote for remote in remotes
            if remote.get("format") == "raw" and remote.get("name") == record["name"]
            and remote.get("version") == record["version"]
        ]
        if len(matches) > 1:
            raise ValueError(f"Duplicate Cloudsmith DDI: {record['name']}")
        if not matches:
            missing.append(record)
        elif matches[0].get("is_sync_failed"):
            raise ValueError(f"Cloudsmith DDI synchronization failed: {record['name']}")
        else:
            remote = matches[0]
            if remote.get("filename") != record["filename"]:
                raise ValueError(f"Cloudsmith DDI filename does not match: {record['name']}")
            if (remote.get("is_sync_completed") and expected_hashes
                    and record["name"] in expected_hashes
                    and remote.get("checksum_sha256") != expected_hashes[record["name"]]):
                raise ValueError(f"Cloudsmith DDI checksum does not match: {record['name']}")
            pending |= not matches[0].get("is_sync_completed", False)
    return missing, pending


def missing_images(spec, expected_hashes=None):
    packages.require_api_key()
    for attempt in range(30):
        missing, pending = remote_plan(spec, expected_hashes)
        if not pending:
            return missing
        if attempt == 29:
            raise RuntimeError("Cloudsmith DDIs did not synchronize within five minutes")
        time.sleep(10)


def preflight(spec):
    missing = missing_images(spec)
    packages.output("build_required", str(bool(missing)).lower())
    packages.summary(
        f"DDI preflight `{spec['channel']}/{spec['version']}` "
        f"`{spec['distro']}/{spec['architecture']}`: {len(missing)} missing images."
    )


def validate_files(directory, spec, *, signed):
    images = {
        record["filename"] if signed else record["filename"] + ".tar"
        for record in expected_images(spec)
    }
    expected = images | set(CHECKSUM_FILES) if signed else images
    if not directory.is_dir() or {p.name for p in directory.iterdir()} != expected:
        raise ValueError("Incomplete or unexpected DDI artifact set")
    for name in expected:
        path = directory / name
        minimum = 1 if name in CHECKSUM_FILES else 4096
        if path.is_symlink() or not path.is_file() or path.stat().st_size < minimum:
            raise ValueError(f"Invalid DDI artifact: {name}")
        if name in CHECKSUM_FILES:
            continue
        elif signed:
            with path.open("rb") as stream:
                stream.seek(512)
                if stream.read(8) != b"EFI PART":
                    raise ValueError(f"Incorrect DDI artifact format: {name}")
        elif not tarfile.is_tarfile(path):
            raise ValueError(f"Incorrect DDI artifact format: {name}")
    if signed and (directory / "SHA256SUMS").read_bytes() != format_checksums({
        name: packages.digest(directory / name) for name in images
    }):
        raise ValueError("SHA256SUMS does not match the signed DDI artifacts")


def build(source, artifacts, spec, *, package_dir=None, container_cache_ref="",
          refresh_build_container=False):
    source, artifacts = source.resolve(), artifacts.resolve()
    if packages.run("git", "rev-parse", "HEAD", cwd=source) != spec["source_sha"]:
        raise ValueError("DDI checkout does not match resolved source")
    if packages.tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"] != spec["upstream"]:
        raise ValueError("DDI source version does not match the resolved target")
    artifacts.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="ddi-build-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        work = Path(temporary)
        if spec["package"] is not None:
            if package_dir is None:
                raise ValueError("Package-based DDIs require native build artifacts via --packages")
            package_dir = package_dir.resolve()
            records = packages.validate_artifacts(package_dir, spec["package"])
            required = {name for kind in spec["kinds"] for name in image.PAYLOAD_PACKAGES[kind]}
            selected = {r["name"]: r["filename"] for r in records
                        if r["name"] in required}
            if missing := required - selected.keys():
                raise ValueError(f"Missing DDI packages: {', '.join(sorted(missing))}")
            release = image.release_fields(json.loads((package_dir / "manifest.json").read_text())["os_release"])
            if not release.get("VERSION_ID"):
                raise ValueError("The package distro must supply VERSION_ID")
            request = {"spec": spec, "packages": selected, "release": release}
        else:
            package_dir = work / "packages"
            package_dir.mkdir()
            request = {"spec": spec}
        (work / "request.json").write_text(json.dumps(request))
        (source / "target").mkdir(exist_ok=True)
        builder_spec = {
            **spec, "channel": "ddi", "scc": False,
            "distro": spec["fedora"] if spec["package"] is not None else spec["distro"],
        }
        with packages.build_container(
            source, builder_spec, container_cache_ref=container_cache_ref,
            refresh_build_container=refresh_build_container,
        ) as builder:
            image.run([
                "docker", "run", "--rm", "--platform", spec["platform"],
                "--security-opt", "label=disable",
                "--volume", f"{SCRIPTS}:/tooling:ro",
                "--volume", f"{image.CONFIG}:/ddi:ro",
                "--volume", f"{source}:/source:ro",
                "--volume", f"{source / 'target'}:/source/target",
                "--volume", f"{package_dir}:/packages:ro",
                "--volume", f"{work / 'request.json'}:/request.json:ro",
                "--volume", f"{artifacts}:/output",
                builder, "python3", "/tooling/ddi.py", "stage", "--request", "/request.json",
            ])
    validate_files(artifacts, spec, signed=False)


def stage(request):
    spec = request["spec"]
    if spec["package"] is not None:
        # Older release generators do not include the cross-format extraction tools.
        image.run(["dnf", "--assumeyes", "--setopt=install_weak_deps=False",
                   "install", "dpkg", "cpio", "rpm", "openssl", "tar"])
    for record in expected_images(spec):
        root = Path("/") / ("root-" + record["kind"])
        if record["kind"] == "portable":
            image.stage_portable(
                {name: Path("/packages") / request["packages"][name]
                 for name in image.PAYLOAD_PACKAGES["portable"]},
                root, spec["fedora"], spec["architecture"], spec["version"],
            )
        else:
            if spec["package"] is None:
                image.stage_native(Path("/source"), root, spec["architecture"])
                release = image.release_fields(Path("/etc/os-release").read_text())
                if release["ID"] != spec["distro"]:
                    raise ValueError("Native sysext was built on the wrong distribution")
            else:
                image.stage_sysext(
                    {name: Path("/packages") / request["packages"][name]
                     for name in image.PAYLOAD_PACKAGES["sysext"]},
                    root, spec["architecture"],
                )
                release = request["release"]
            image.extension_release(root, release, record["filename"],
                                    f"{spec['version']}-{spec['distro']}", spec["architecture"])
        image.make_payload(root, Path("/output") / (record["filename"] + ".tar"))


def sign(artifacts, output, spec):
    artifacts, output = artifacts.resolve(), output.resolve()
    validate_files(artifacts, spec, signed=False)
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="ddi-payloads-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        roots = {}
        for record in expected_images(spec):
            root = Path(temporary) / record["kind"]
            image.extract_payload(artifacts / (record["filename"] + ".tar"), root)
            roots[record["kind"]] = root
        with image.signing_material(os.environ.get("RUNNER_TEMP")) as signing:
            for record in expected_images(spec):
                image.sign_image(roots[record["kind"]], output / record["filename"],
                                 spec["architecture"], signing, record["kind"])
            write_checksums(output, {
                record["filename"]: packages.digest(output / record["filename"])
                for record in expected_images(spec)
            }, signing)
    validate_files(output, spec, signed=True)


def publish(artifacts, spec):
    packages.require_api_key()
    validate_files(artifacts, spec, signed=True)
    uploaded = {}
    for record in missing_images(spec):
        tags = f"ddi,{record['kind']},channel-{spec['channel']},source-{spec['source_sha']},distro-{spec['distro']}"
        image.run([
            "cloudsmith", "push", "raw", spec["repository"], artifacts / record["filename"],
            "--name", record["name"], "--version", record["version"],
            "--content-type", "application/vnd.efi.img",
            "--no-republish", "--tags", tags,
        ], env=os.environ.copy())
        uploaded[record["name"]] = packages.digest(artifacts / record["filename"])
    if missing_images(spec, uploaded):
        raise RuntimeError("Cloudsmith verification did not find every signed DDI")
    packages.summary(f"Published raw-only DDIs for `{spec['channel']}/{spec['version']}` "
                     f"`{spec['distro']}/{spec['architecture']}` to `{spec['repository']}`.")


def catalog_checksums(spec, record, rows):
    checksums = {}
    for remote in rows:
        if remote.get("format") != "raw" or remote.get("name") != record["name"]:
            continue
        if remote.get("filename") in CHECKSUM_FILES:
            continue
        version = remote.get("version") or ""
        pattern = (r"\d+\.\d+\.\d+" if spec["channel"] == "stable"
                   else r"\d{4}-\d{2}-\d{2}(?:\.\d{12})?-[0-9a-f]+")
        if not re.fullmatch(pattern, version):
            raise ValueError(f"Invalid image version in sysupdate stream {record['name']}")
        expected = expected_images({**spec, "version": version, "kinds": [record["kind"]]})[0]
        filename = remote.get("filename")
        if filename != expected["filename"] or filename in checksums:
            raise ValueError(f"Unexpected or duplicate image in sysupdate stream {record['name']}")
        if remote.get("is_sync_failed") or not remote.get("is_sync_completed"):
            raise ValueError(f"Unsynchronized image in sysupdate stream {record['name']}")
        checksums[filename] = remote.get("checksum_sha256") or ""
    if record["filename"] not in checksums:
        raise ValueError(f"The current image is missing from sysupdate stream {record['name']}")
    format_checksums(checksums)
    return checksums


def verify_catalog_publication(spec, record, directory):
    expected = {name: (directory / name).read_bytes() for name in CHECKSUM_FILES}
    for attempt in range(30):
        rows = packages.api_packages(spec["repository"], "raw", package_name=record["name"])
        synchronized = True
        for name, (version, _) in CHECKSUM_FILES.items():
            matches = [row for row in rows if row.get("format") == "raw"
                       and row.get("name") == record["name"] and row.get("version") == version]
            if len(matches) > 1:
                raise ValueError(f"Duplicate sysupdate metadata: {record['name']}/{name}")
            if matches and matches[0].get("is_sync_failed"):
                raise ValueError(f"Sysupdate metadata synchronization failed: {record['name']}/{name}")
            synchronized &= bool(
                matches and matches[0].get("is_sync_completed")
                and matches[0].get("filename") == name
                and matches[0].get("checksum_sha256") == hashlib.sha256(expected[name]).hexdigest()
            )
        if synchronized:
            try:
                for name, content in expected.items():
                    request = urllib.request.Request(
                        f"{update_source(spec, record)}/{name}",
                        headers={"Cache-Control": "no-cache"},
                    )
                    with urllib.request.urlopen(request, timeout=30) as response:
                        if response.read(len(content) + 1) != content:
                            break
                else:
                    return
            except (OSError, http.client.HTTPException) as error:
                print(f"Sysupdate metadata is not available at its stable URL yet: {error}")
        if attempt == 29:
            raise RuntimeError(f"Sysupdate manifest/signature did not become available: {record['name']}")
        time.sleep(10)


def publish_checksums(spec):
    packages.require_api_key()
    streams = []
    for record in expected_images(spec):
        rows = packages.api_packages(spec["repository"], "raw", package_name=record["name"])
        streams.append((record, catalog_checksums(spec, record, rows)))
    with tempfile.TemporaryDirectory(prefix="sysupdate-publish-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        work = Path(temporary)
        with image.signing_material(work) as signing:
            for record, checksums in streams:
                directory = work / record["name"]
                directory.mkdir()
                write_checksums(directory, checksums, signing)
                # Publish the manifest last. During replacement clients reject
                # mismatched pairs rather than accepting unauthenticated data.
                for filename in ("SHA256SUMS.gpg", "SHA256SUMS"):
                    version, content_type = CHECKSUM_FILES[filename]
                    image.run([
                        "cloudsmith", "push", "raw", spec["repository"], directory / filename,
                        "--name", record["name"], "--version", version,
                        "--content-type", content_type, "--republish",
                        "--tags", f"ddi,sysupdate,channel-{spec['channel']}",
                    ], env=os.environ.copy())
                verify_catalog_publication(spec, record, directory)
                packages.summary(f"Published signed sysupdate manifest: `{update_source(spec, record)}` "
                                 f"({len(checksums)} versions).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "preflight", "build", "stage", "sign", "publish", "publish-checksums"))
    parser.add_argument("--source", type=Path, default=Path("source"))
    parser.add_argument("--packages", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--output", type=Path, default=Path("signed"))
    parser.add_argument("--request", type=Path)
    parser.add_argument("--container-cache-ref", default="")
    parser.add_argument("--refresh-build-container", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare()
        elif args.command == "stage":
            stage(json.loads(args.request.read_text()))
        else:
            spec = json.loads(os.environ["TARGET_SPEC"])
            if args.command == "preflight":
                preflight(spec)
            elif args.command == "build":
                build(args.source, args.artifacts, spec, package_dir=args.packages,
                      container_cache_ref=args.container_cache_ref,
                      refresh_build_container=args.refresh_build_container)
            elif args.command == "sign":
                sign(args.artifacts, args.output, spec)
            elif args.command == "publish-checksums":
                publish_checksums(spec)
            else:
                publish(args.artifacts, spec)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"DDI operation failed: {error}\n")


if __name__ == "__main__":
    main()
