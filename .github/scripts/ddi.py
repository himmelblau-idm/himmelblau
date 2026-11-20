#!/usr/bin/env python3
"""Build, sign and publish stable/nightly DDIs without build-host."""

import argparse
import datetime as dt
from functools import cmp_to_key
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
NIGHTLY_TIMESTAMP_FORMAT = "%Y-%m-%d.%H%M%S%f"
CHECKSUM_FILES = {
    "SHA256SUMS": "text/plain",
    "SHA256SUMS.gpg": "application/pgp-signature",
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
        repository = nightly.REPOSITORY
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
            tags = ["portable", spec["architecture"]]
        elif kind == "sysext":
            filename = f"himmelblau_{spec['version']}-{spec['distro']}-{arch}.sysext.raw"
            name = f"himmelblau-{spec['channel']}-{spec['distro']}-{arch}-sysext"
            tags = ["ddi", kind, spec["channel"], spec["architecture"], spec["distro"]]
        else:
            raise ValueError(f"Invalid DDI kind: {kind}")
        result.append({"kind": kind, "filename": filename, "name": name, "version": spec["version"], "tags": tags})
    return result


def update_source(spec, record):
    # Default filename-based package names share a directory when their Cloudsmith version is the stream ID.
    return f"https://dl.cloudsmith.io/public/{spec['repository']}/raw/versions/{record['name']}"


def install_sysupdate(root, spec):
    directory = root / "usr/lib/sysupdate.himmelblau.d"
    directory.mkdir(parents=True, exist_ok=True)
    template = (image.CONFIG / "sysupdate.transfer.in").read_text()
    records = expected_images({**spec, "version": "@v", "kinds": ["portable", "sysext"]})
    for index, record in enumerate(records, start=1):
        if record["kind"] == "portable":
            target = "/var/lib/himmelblau-ddi/himmelblaud.v"
        else:
            target = "/var/lib/extensions/himmelblau.sysext.raw.v"
        (directory / f"{index * 10}-{record['kind']}.transfer").write_text(template.format(
            version=spec["version"], source=update_source(spec, record),
            pattern=record["filename"], target=target,
        ))


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
    missing, pending = [], False
    for record in expected_images(spec):
        remotes = packages.api_packages(spec["repository"], "raw", record["name"])
        matches = [
            remote for remote in remotes
            if remote.get("format") == "raw" and remote.get("filename") == record["filename"]
            and remote.get("version") == record["name"]
        ]
        if len(matches) > 1:
            raise ValueError(f"Duplicate Cloudsmith DDI: {record['name']}")
        if not matches:
            missing.append(record)
        elif matches[0].get("is_sync_failed"):
            raise ValueError(f"Cloudsmith DDI synchronization failed: {record['name']}")
        else:
            remote = matches[0]
            if (remote.get("is_sync_completed")
                    and remote.get("cdn_url") != f"{update_source(spec, record)}/{record['filename']}"):
                raise ValueError(f"Cloudsmith DDI URL does not match its stream: {record['name']}")
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
            install_sysupdate(root, spec)
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
        tags = record["tags"]
        if record["kind"] == "sysext":
            tags = [*tags, f"source-{spec['source_sha']}"]
        image.run([
            "cloudsmith", "push", "raw", spec["repository"], artifacts / record["filename"],
            "--version", record["name"],
            "--content-type", "application/vnd.efi.img",
            "--no-republish", "--tags", ",".join(tags),
        ], env=os.environ.copy())
        uploaded[record["name"]] = packages.digest(artifacts / record["filename"])
    if missing_images(spec, uploaded):
        raise RuntimeError("Cloudsmith verification did not find every signed DDI")
    packages.summary(f"Published raw-only DDIs for `{spec['channel']}/{spec['version']}` "
                     f"`{spec['distro']}/{spec['architecture']}` to `{spec['repository']}`.")


def image_version(spec, record, filename):
    version_pattern = (r"\d+\.\d+\.\d+" if spec["channel"] == "stable"
                       else r"\d{4}-\d{2}-\d{2}(?:\.\d{12})?-[0-9a-f]+")
    template = expected_images({**spec, "version": "@v", "kinds": [record["kind"]]})[0]["filename"]
    prefix, suffix = template.split("@v")
    match = re.fullmatch(re.escape(prefix) + f"({version_pattern})" + re.escape(suffix), filename)
    if not match:
        raise ValueError(f"Unexpected image filename in sysupdate stream {record['name']}: {filename}")
    return match[1]


def catalog_checksums(spec, record, rows, *, require_current=True):
    checksums = {}
    for remote in rows:
        if remote.get("format") != "raw" or remote.get("version") != record["name"]:
            continue
        filename = remote.get("filename") or ""
        if filename in CHECKSUM_FILES:
            continue
        image_version(spec, record, filename)
        if filename in checksums:
            raise ValueError(f"Duplicate image in sysupdate stream {record['name']}")
        if remote.get("is_sync_failed") or not remote.get("is_sync_completed"):
            raise ValueError(f"Unsynchronized image in sysupdate stream {record['name']}")
        if remote.get("cdn_url") != f"{update_source(spec, record)}/{filename}":
            raise ValueError(f"Image URL is outside sysupdate stream {record['name']}: {filename}")
        checksums[filename] = remote.get("checksum_sha256") or ""
    if require_current and record["filename"] not in checksums:
        raise ValueError(f"The current image is missing from sysupdate stream {record['name']}")
    format_checksums(checksums)
    return checksums


def compare_versions(left, right):
    try:
        image.run(["systemd-analyze", "compare-versions", left, right], capture=True)
    except subprocess.CalledProcessError as error:
        if error.returncode == 11:
            return 1
        if error.returncode == 12:
            return -1
        raise
    return 0


def cleanup_plan(spec, rows):
    current = {record["name"]: record for record in expected_images(spec)}
    targets = {name: (spec, record, []) for name, record in current.items()}
    portable = expected_images({**spec, "kinds": ["portable"]})[0]["name"]
    arch = image.ARCHITECTURES[spec["architecture"]][0]
    sysext_pattern = rf"himmelblau-{re.escape(spec['channel'])}-([A-Za-z0-9][A-Za-z0-9._+-]*)-{re.escape(arch)}-sysext"
    for row in rows:
        if row.get("format") != "raw" or row.get("filename") in CHECKSUM_FILES:
            continue
        name = row.get("version") or ""
        if name == portable:
            target = {**spec, "kinds": ["portable"]}
        elif match := re.fullmatch(sysext_pattern, name):
            target = {**spec, "distro": match[1], "kinds": ["sysext"]}
        else:
            continue
        record = expected_images(target)[0]
        targets.setdefault(name, (target, record, []))[2].append(row)

    streams, unavailable = {}, []
    for name, (target, record, candidates) in targets.items():
        if name not in current and any(
            row.get("is_sync_failed") or not row.get("is_sync_completed") for row in candidates
        ):
            unavailable.extend(candidates)
            packages.summary(f"Skipping publication and cleanup for unsynchronized DDI stream `{name}`; "
                             "preserving all portable images.")
            continue
        checksums = catalog_checksums(target, record, candidates, require_current=name in current)
        versions = {filename: image_version(target, record, filename) for filename in checksums}
        streams[name] = (record, candidates, checksums, versions)
    ordered = sorted({version for _, _, _, versions in streams.values() for version in versions.values()},
                     key=cmp_to_key(compare_versions))
    rank = {version: index for index, version in enumerate(ordered)}
    portable_versions = set(streams[portable][3].values()) if portable in streams else set()
    keep = {}
    # An unavailable stream may still depend on any of the published portable versions.
    required_portables = set(portable_versions) if unavailable else set()
    for name, (record, _, _, versions) in streams.items():
        if record["kind"] == "portable":
            continue
        available = set(versions.values())
        managed = {version for version in available if spec["channel"] != "stable"
                   or int(version.split(".")[0]) == int(spec["version"].split(".")[0])}
        complete = managed & portable_versions
        if complete:
            latest = max(complete, key=rank.__getitem__)
            # Keep newer candidates until their shared portable image arrives.
            keep[name] = (available - managed) | {version for version in managed if rank[version] >= rank[latest]}
        else:
            keep[name] = available
            packages.summary(f"Retaining images in `{name}` until a matching portable image is synchronized.")
        required_portables.update(keep[name] & portable_versions)
    if portable_versions:
        managed = {version for version in portable_versions if spec["channel"] != "stable"
                   or int(version.split(".")[0]) == int(spec["version"].split(".")[0])}
        keep[portable] = (portable_versions - managed) | required_portables
        if managed:
            keep[portable].add(max(managed, key=rank.__getitem__))

    catalogs, deletions = [], []
    retained_ids = {row.get("slug_perm") for row in unavailable}
    for name, (record, candidates, checksums, versions) in streams.items():
        retained = {filename: digest for filename, digest in checksums.items() if versions[filename] in keep[name]}
        older = [row for row in candidates if row["filename"] not in retained]
        retained_ids.update(row.get("slug_perm") for row in candidates if row["filename"] in retained)
        # A previous portable upload may have succeeded before its catalog publication failed.
        if name in current or name == portable or older:
            catalogs.append((record, retained))
        for row in older:
            identifier = row.get("slug_perm")
            if not isinstance(identifier, str) or not identifier or row.get("is_deleteable") is not True:
                raise ValueError(f"Older DDI {row['filename']} cannot be safely deleted")
            deletions.append(row)
    identifiers = [row["slug_perm"] for row in deletions]
    if len(identifiers) != len(set(identifiers)) or retained_ids.intersection(identifiers):
        raise ValueError("Cloudsmith returned conflicting DDI identifiers; refusing cleanup")
    return catalogs, deletions


def verify_catalog_publication(spec, record, directory):
    expected = {name: (directory / name).read_bytes() for name in CHECKSUM_FILES}
    for attempt in range(30):
        rows = packages.api_packages(spec["repository"], "raw", record["name"])
        synchronized = True
        for name in CHECKSUM_FILES:
            matches = [row for row in rows if row.get("format") == "raw"
                       and row.get("filename") == name and row.get("version") == record["name"]]
            if len(matches) > 1:
                raise ValueError(f"Duplicate sysupdate metadata: {record['name']}/{name}")
            if matches and matches[0].get("is_sync_failed"):
                raise ValueError(f"Sysupdate metadata synchronization failed: {record['name']}/{name}")
            if (matches and matches[0].get("is_sync_completed")
                    and matches[0].get("cdn_url") != f"{update_source(spec, record)}/{name}"):
                raise ValueError(f"Sysupdate metadata URL does not match its stream: {record['name']}/{name}")
            synchronized &= bool(
                matches and matches[0].get("is_sync_completed")
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
    rows = packages.api_packages(spec["repository"], "raw")
    streams, deletions = cleanup_plan(spec, rows)
    with tempfile.TemporaryDirectory(prefix="sysupdate-publish-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        work = Path(temporary)
        with image.signing_material(work) as signing:
            for record, checksums in streams:
                directory = work / record["name"]
                directory.mkdir()
                write_checksums(directory, checksums, signing)
                tags = [*record["tags"], "sysupdate"]
                # Publish the manifest last. During replacement clients reject
                # mismatched pairs rather than accepting unauthenticated data.
                for filename in ("SHA256SUMS.gpg", "SHA256SUMS"):
                    image.run([
                        "cloudsmith", "push", "raw", spec["repository"], directory / filename,
                        "--version", record["name"],
                        "--content-type", CHECKSUM_FILES[filename], "--republish",
                        "--tags", ",".join(tags),
                    ], env=os.environ.copy())
                verify_catalog_publication(spec, record, directory)
                packages.summary(f"Published signed sysupdate manifest: `{update_source(spec, record)}` "
                                 f"({len(checksums)} versions).")
    # No image is removed until every affected catalog has been signed and verified.
    for row in deletions:
        packages.delete_package(spec["repository"], row["slug_perm"])
    packages.wait_for_deletions(spec["repository"], "raw", [row["slug_perm"] for row in deletions])
    packages.summary(f"Reconciled `{spec['channel']}/{spec['architecture']}` DDIs in "
                     f"`{spec['repository']}`: deleted {len(deletions)} older images.")


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
