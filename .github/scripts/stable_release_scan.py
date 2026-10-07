#!/usr/bin/env python3
"""Reconcile the latest release on each supported stable branch."""

import json
import os
import re
import time
import urllib.error
import urllib.request

import stable_packages as packages


REPOSITORY = "himmelblau-idm/himmelblau"
BRANCHES = ("stable-3.x", "stable-4.x")
WORKFLOWS = {
    "release": ("publish-release.yml", "Publish GitHub Release"),
    "packages": ("stable-packages.yml", "Stable packages"),
}
ACTIVE_STATUSES = ("queued", "in_progress", "waiting", "pending", "requested")


def github_api(path, *, payload=None, not_found=False):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN is missing")
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/{path}",
        data=data,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Himmelblau-Stable-Release-Scan",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST" if payload is not None else "GET",
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and not_found:
                return None
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise RuntimeError(f"GitHub API {path} failed (HTTP {exc.code})") from None
        except urllib.error.URLError:
            if attempt == 2:
                raise RuntimeError(f"GitHub API {path} is unavailable") from None
        time.sleep(2 ** attempt)


def latest_tag(branch):
    sha = packages.resolve(f"refs/remotes/origin/{branch}")
    tag = packages.version(sha)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tag):
        packages.summary(f"{branch}: workspace version {tag!r} is not a stable release; skipping.")
        return None
    if tag.split(".", 1)[0] != branch.removeprefix("stable-").removesuffix(".x"):
        raise ValueError(f"{branch}: workspace version {tag} belongs to another stable branch")
    try:
        tagged_sha = packages.resolve(f"refs/tags/{tag}")
    except ValueError:
        raise ValueError(f"{branch}: stable version {tag} has no tag") from None
    if not packages.ancestor(tagged_sha, sha):
        raise ValueError(f"{branch}: tag {tag} is not reachable from the branch")
    if packages.version(tagged_sha) != tag:
        raise ValueError(f"{branch}: tag {tag} has a different workspace version")
    return tag


def active_tags(workflow_file, title):
    tags = set()
    for status in ACTIVE_STATUSES:
        page = 1
        while True:
            result = github_api(
                f"actions/workflows/{workflow_file}/runs?status={status}&per_page=100&page={page}"
            )
            runs = result["workflow_runs"]
            for run in runs:
                display_title = run.get("display_title", "")
                if display_title.startswith(f"{title} "):
                    tags.add(display_title.removeprefix(f"{title} "))
            if len(runs) < 100:
                break
            page += 1
    return tags


def release_published(tag):
    release = github_api(f"releases/tags/{tag}", not_found=True)
    return bool(release and not release.get("draft") and
                not release.get("prerelease") and release.get("published_at"))


def package_status(tag):
    specs = [json.loads(entry["spec"]) for entry in packages.matrix(tag)["include"]]
    remote_by_group = {}
    missing_targets = []
    pending_targets = []
    for spec in specs:
        group = (spec["repository"], spec["format"], tag)
        if group not in remote_by_group:
            remote_by_group[group] = packages.api_packages(*group)
        missing, pending = packages.upload_plan(
            spec["expected_packages"], remote_by_group[group], spec
        )
        target = f"{spec['distro']}/{spec['architecture']}"
        if missing:
            missing_targets.append(target)
        if pending:
            pending_targets.append(target)
    return missing_targets, pending_targets


def dispatch(workflow_file, tag):
    github_api(
        f"actions/workflows/{workflow_file}/dispatches",
        payload={"ref": "main", "inputs": {"tag": tag}},
    )


def scan():
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("Stable release scan must run in the upstream repository")
    packages.require_api_key()
    tags = {tag for branch in BRANCHES if (tag := latest_tag(branch))}
    active = {
        kind: active_tags(workflow_file, title)
        for kind, (workflow_file, title) in WORKFLOWS.items()
    }
    for tag in sorted(tags, key=lambda value: tuple(map(int, value.split(".")))):
        if release_published(tag):
            packages.summary(f"{tag}: GitHub release is published.")
        elif tag in active["release"]:
            packages.summary(f"{tag}: GitHub release publication is already running.")
        else:
            dispatch(WORKFLOWS["release"][0], tag)
            packages.summary(f"{tag}: queued GitHub release publication.")

        if tag in active["packages"]:
            packages.summary(f"{tag}: stable package workflow is already running.")
            continue
        missing, pending = package_status(tag)
        if missing:
            dispatch(WORKFLOWS["packages"][0], tag)
            packages.summary(f"{tag}: queued stable packages; missing targets: {', '.join(missing)}.")
        elif pending:
            packages.summary(f"{tag}: waiting for Cloudsmith synchronization: {', '.join(pending)}.")
        else:
            packages.summary(f"{tag}: stable package set is complete.")
    if not tags:
        packages.summary("No stable release tags to check.")


if __name__ == "__main__":
    try:
        scan()
    except (ValueError, KeyError, RuntimeError) as exc:
        raise SystemExit(f"Stable release scan failed: {exc}") from None
