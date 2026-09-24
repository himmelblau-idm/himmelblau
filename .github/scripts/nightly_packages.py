#!/usr/bin/env python3
"""Build, publish, and reconcile packages from the tip of main."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

import stable_packages as packages


REPOSITORY = "himmelblau/nightly"
NIGHTLY_TAG = "nightly"


def package_names(source_sha, fmt, cfg, base_version):
    _, definitions = packages.generator_config(
        packages.source_text(source_sha, "scripts/gen_dockerfiles.py")
    )
    names = []
    for crate, path, _ in definitions:
        if crate == "selinux" and (fmt == "deb" or not cfg.get("selinux")):
            continue
        if crate == "apparmor" and fmt == "rpm" and not cfg.get("apparmor"):
            continue
        metadata = tomllib.loads(
            packages.source_text(source_sha, f"{path}/Cargo.toml")
        )["package"]
        section = "deb" if fmt == "deb" else "generate-rpm"
        package = metadata.get("metadata", {}).get(section, {})
        name = package.get("name", metadata["name"].replace("_", "-"))
        if package.get("epoch", 0) != 0:
            raise ValueError("Unexpected package epoch")
        if package.get("version", base_version) != base_version:
            raise ValueError("Package version must match the workspace version")
        names.append(name)
    return names


def matrix(source_sha, nightly_date, run_number, distro="all", architecture="all"):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Nightly source must resolve to a full commit SHA")
    if not re.fullmatch(r"[0-9]{8}", nightly_date):
        raise ValueError("Nightly date must use YYYYMMDD")
    if not re.fullmatch(r"[1-9][0-9]*", str(run_number)):
        raise ValueError("GitHub run number must be a positive integer")
    if architecture not in {"all", *packages.ARCHITECTURES}:
        raise ValueError("Architecture must be all, amd64 or arm64")

    base_version = packages.version(source_sha)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", base_version):
        raise ValueError("Nightly workspace version must use MAJOR.MINOR.PATCH form")
    nightly_id = f"{nightly_date}.{run_number}.git{source_sha[:12]}"
    rpm_release = f"0.{nightly_id}"
    dists, _ = packages.generator_config(
        packages.source_text(source_sha, "scripts/gen_dockerfiles.py")
    )
    makefile = packages.source_text(source_sha, "Makefile")
    targets = []
    for group in ["DEB", "RPM", "SLE"]:
        match = re.search(rf"^{group}_TARGETS\s*:=\s*(.+)$", makefile, re.MULTILINE)
        if not match:
            raise ValueError(f"Cannot find {group}_TARGETS in source Makefile")
        targets.extend(match[1].split())
    if distro != "all" and distro not in targets:
        raise ValueError(f"Unsupported distro: {distro}")

    entries = []
    for target in [candidate for candidate in targets if distro in {"all", candidate}]:
        cfg = dists[target]
        fmt = "deb" if cfg["family"] == "deb" else "rpm"
        if cfg["family"] not in {"deb", "rpm", "zypper"}:
            raise ValueError(f"Unsupported package family for {target}")
        if target not in packages.DESTINATIONS:
            raise ValueError(f"No approved native Cloudsmith destination for {target}")
        names = package_names(source_sha, fmt, cfg, base_version)
        for arch, info in packages.ARCHITECTURES.items():
            if architecture not in {"all", arch}:
                continue
            if arch == "arm64" and not cfg.get("arm64", True):
                continue
            full_version = (
                f"{base_version}-{target}~{nightly_id}"
                if fmt == "deb"
                else f"{base_version}-{rpm_release}"
            )
            native = arch if fmt == "deb" else info["rpm"]
            independent = "all" if fmt == "deb" else "noarch"
            spec = {
                "channel": "nightly",
                "tag": base_version,
                "source_sha": source_sha,
                "nightly_id": nightly_id,
                "repository": REPOSITORY,
                "distro": target,
                "destination": packages.DESTINATIONS[target],
                "format": fmt,
                "architecture": arch,
                "supported_architectures": [
                    candidate
                    for candidate in packages.ARCHITECTURES
                    if candidate != "arm64" or cfg.get("arm64", True)
                ],
                "expected": names,
                "expected_packages": [
                    {
                        "name": name,
                        "version": full_version,
                        "architectures": [native, independent],
                    }
                    for name in names
                ],
                "deb_revision_append": f"~{nightly_id}",
                "rpm_package_release": rpm_release,
                "upload_tags": ",".join(
                    [
                        NIGHTLY_TAG,
                        f"source-{source_sha}",
                        f"nightly-{nightly_id}",
                        f"distro-{target}",
                    ]
                ),
                **info,
            }
            entries.append({"spec": json.dumps(spec, separators=(",", ":"))})
    if not entries:
        raise ValueError("No supported targets remain after applying the filters")
    return {"include": entries}


def user_tags(package):
    tags = package.get("tags", {})
    if isinstance(tags, dict):
        tags = tags.get("user", [])
    return set(tags if isinstance(tags, list) else [])


def nightly_ids(package):
    return {
        tag.removeprefix("nightly-")
        for tag in user_tags(package)
        if tag.startswith("nightly-")
    }


def target_package(package, spec):
    distro, release = spec["destination"].split("/", 1)
    return (
        package.get("format") == spec["format"]
        and package.get("epoch") in (None, 0, "0")
        and (package.get("distro") or {}).get("slug") == distro
        and (package.get("distro_version") or {}).get("slug") == release
    )


def expected_version(spec, nightly_id):
    if spec["format"] == "deb":
        return f"{spec['tag']}-{spec['distro']}~{nightly_id}"
    return f"{spec['tag']}-0.{nightly_id}"


def matching_build_packages(remote_packages, spec, nightly_id, name):
    source_tag = f"source-{spec['source_sha']}"
    build_tag = f"nightly-{nightly_id}"
    return [
        package
        for package in remote_packages
        if target_package(package, spec)
        and package.get("name") == name
        and package.get("version") == expected_version(spec, nightly_id)
        and source_tag in user_tags(package)
        and build_tag in user_tags(package)
        and packages.serves_architecture(package, spec, spec["architecture"])
    ]


def complete_build(remote_packages, spec, nightly_id, *, reject_duplicates=True):
    for name in spec["expected"]:
        matches = matching_build_packages(remote_packages, spec, nightly_id, name)
        if len(matches) > 1:
            if reject_duplicates:
                raise ValueError(
                    f"Multiple nightly packages match {name} for "
                    f"{spec['distro']} / {spec['architecture']}"
                )
            return False
        if (
            not matches
            or matches[0].get("is_sync_failed")
            or not matches[0].get("is_sync_completed", False)
        ):
            return False
    return True


def build_key(nightly_id):
    match = re.fullmatch(r"([0-9]{8})\.([1-9][0-9]*)\.git([0-9a-f]{12})", nightly_id)
    if not match:
        raise ValueError(f"Invalid nightly build identifier: {nightly_id}")
    return match.group(1), int(match.group(2)), match.group(3)


def complete_current_builds(remote_packages, spec):
    source_tag = f"source-{spec['source_sha']}"
    candidates = set()
    for package in remote_packages:
        if target_package(package, spec) and source_tag in user_tags(package):
            candidates.update(nightly_ids(package))
    return sorted(
        [
            nightly_id
            for nightly_id in candidates
            if complete_build(remote_packages, spec, nightly_id)
        ],
        key=build_key,
    )


def complete_for_architecture(remote_packages, spec, architecture):
    candidate = {**spec, "architecture": architecture}
    return bool(complete_current_builds(remote_packages, candidate))


def managed_build_ids(remote_packages, spec):
    identifiers = set()
    for package in remote_packages:
        if (
            target_package(package, spec)
            and NIGHTLY_TAG in user_tags(package)
            and packages.serves_architecture(package, spec, spec["architecture"])
        ):
            identifiers.update(nightly_ids(package))
    return identifiers


def reject_stale_run(remote_packages, spec):
    current = build_key(spec["nightly_id"])
    newer = [
        nightly_id
        for nightly_id in managed_build_ids(remote_packages, spec)
        if build_key(nightly_id) > current
    ]
    if newer:
        latest = max(newer, key=build_key)
        raise RuntimeError(
            f"A newer nightly `{latest}` already exists for "
            f"{spec['distro']} / {spec['architecture']}; refusing stale run"
        )


def cleanup_plan(remote_packages, spec):
    reject_stale_run(remote_packages, spec)
    complete = complete_current_builds(remote_packages, spec)
    if not complete:
        raise RuntimeError("Cloudsmith cleanup did not find a complete synchronized current nightly target")
    retained = complete[-1]
    coverage = {
        architecture: complete_for_architecture(remote_packages, spec, architecture)
        for architecture in spec["supported_architectures"]
    }
    independent = packages.independent_architecture(spec)
    deletions = []
    for package in remote_packages:
        if (
            not target_package(package, spec)
            or NIGHTLY_TAG not in user_tags(package)
            or not packages.serves_architecture(package, spec, spec["architecture"])
        ):
            continue
        retained_identity = (
            package.get("name") in spec["expected"]
            and package.get("version") == expected_version(spec, retained)
            and f"source-{spec['source_sha']}" in user_tags(package)
            and f"nightly-{retained}" in user_tags(package)
        )
        if retained_identity:
            continue
        architectures = packages.package_architectures(package)
        if independent in architectures:
            replacements = matching_build_packages(
                remote_packages, spec, retained, package.get("name")
            )
            independent_replacement = any(
                independent in packages.package_architectures(replacement)
                and replacement.get("is_sync_completed", False)
                and not replacement.get("is_sync_failed")
                for replacement in replacements
            )
            if not independent_replacement and not all(coverage.values()):
                continue
        identifier = package.get("slug_perm")
        if (
            not isinstance(identifier, str)
            or not identifier
            or package.get("is_deleteable") is not True
        ):
            raise ValueError(f"Older {package.get('name', 'package')} cannot be safely deleted")
        deletions.append(package)
    identifiers = [package["slug_perm"] for package in deletions]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Cloudsmith returned duplicate package identifiers; refusing cleanup")
    return retained, deletions


def inventory(spec):
    return packages.api_packages(
        spec["repository"], spec["format"], distribution=spec["destination"]
    )


def prepare():
    source_sha = packages.resolve("refs/remotes/origin/main")
    tooling_sha = packages.resolve("HEAD")
    if tooling_sha != source_sha:
        raise ValueError("Nightly tooling checkout must match the resolved main source")
    result = matrix(
        source_sha,
        os.environ.get("NIGHTLY_DATE", ""),
        os.environ.get("GITHUB_RUN_NUMBER", ""),
        os.environ.get("REQUESTED_DISTRO") or "all",
        os.environ.get("REQUESTED_ARCHITECTURE") or "all",
    )
    packages.require_api_key()
    cached = {}
    work = []
    for entry in result["include"]:
        spec = json.loads(entry["spec"])
        key = spec["format"], spec["destination"]
        if key not in cached:
            cached[key] = inventory(spec)
        remote = cached[key]
        complete = complete_current_builds(remote, spec)
        if not complete:
            work.append(f"{spec['distro']}/{spec['architecture']}: build")
            continue
        _, deletions = cleanup_plan(remote, spec)
        if deletions:
            work.append(f"{spec['distro']}/{spec['architecture']}: cleanup")
    packages.output("matrix", json.dumps(result, separators=(",", ":")))
    packages.output("tooling_sha", tooling_sha)
    packages.output("enabled", str(bool(work)).lower())
    if work:
        packages.summary(
            f"Nightly source `{source_sha}`; {len(result['include'])} selected targets, "
            f"{len(work)} requiring work."
        )
    else:
        packages.summary(
            f"Nightly source `{source_sha}` is already complete and reconciled for all "
            f"{len(result['include'])} selected targets; skipping."
        )


def preflight(spec):
    packages.require_api_key()
    remote = inventory(spec)
    reject_stale_run(remote, spec)
    complete = complete_current_builds(remote, spec)
    packages.output("build_required", str(not complete).lower())
    if complete:
        packages.summary(
            f"Cloudsmith nightly preflight `{spec['distro']}` / `{spec['architecture']}`: "
            f"source `{spec['source_sha']}` is already complete; skipping build and publication."
        )
    else:
        packages.summary(
            f"Cloudsmith nightly preflight `{spec['distro']}` / `{spec['architecture']}`: "
            f"building `{spec['nightly_id']}` from `{spec['source_sha']}`."
        )


def cleanup(spec):
    packages.require_api_key()
    remote = inventory(spec)
    retained, deletions = cleanup_plan(remote, spec)
    for package in deletions:
        packages.delete_package(spec["repository"], package["slug_perm"])
    packages.wait_for_deletions(
        spec["repository"],
        spec["format"],
        [package["slug_perm"] for package in deletions],
        spec["destination"],
    )
    packages.summary(
        f"Reconciled nightly `{spec['distro']}` / `{spec['architecture']}` in "
        f"`{spec['repository']}/{spec['destination']}`: retained `{retained}`, "
        f"deleted {len(deletions)} older packages."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "preflight", "build", "publish", "cleanup"])
    parser.add_argument("--source", type=Path, default=Path("source"))
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--container-cache-ref", default="")
    parser.add_argument("--refresh-build-container", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare()
            return
        spec = json.loads(os.environ["TARGET_SPEC"])
        if args.command == "preflight":
            preflight(spec)
        elif args.command == "build":
            packages.build(
                args.source,
                args.artifacts,
                spec,
                container_cache_ref=args.container_cache_ref,
                refresh_build_container=args.refresh_build_container,
            )
        elif args.command == "publish":
            packages.publish(args.artifacts, spec)
        else:
            cleanup(spec)
    except (ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Nightly package operation failed: {exc}\n")


if __name__ == "__main__":
    main()
