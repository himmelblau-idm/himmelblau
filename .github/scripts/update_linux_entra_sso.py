#!/usr/bin/env python3
"""Update pinned linux-entra-sso browser extension URLs."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
LATEST_RELEASE_API = "https://api.github.com/repos/siemens/linux-entra-sso/releases/latest"
USER_AGENT = "Himmelblau-linux-entra-sso-updater/1.0"
VERSION_RE = re.compile(r"^v?(?P<version>[0-9]+(?:\.[0-9]+){2})$")
EXTENSION_URL_RE = re.compile(
    r"https://github\.com/siemens/linux-entra-sso/releases/download/"
    r"v?(?P<release>[0-9]+(?:\.[0-9]+){2})/"
    r"linux_entra_sso-(?P<asset>[0-9]+(?:\.[0-9]+){2})(?P<thunderbird>\.thunderbird)?\.xpi"
)


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: str) -> "Version":
        match = VERSION_RE.fullmatch(value.strip())
        if not match:
            raise ValueError(f"Unsupported linux-entra-sso version: {value!r}")
        return cls(*(int(part) for part in match.group("version").split(".")))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class ReleaseInfo:
    version: Version
    firefox_url: str
    thunderbird_url: str


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def http_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", USER_AGENT)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read()[:500].decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} fetching {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc


def release_from_payload(payload: dict[str, Any]) -> ReleaseInfo:
    tag_name = str(payload.get("tag_name", "")).strip()
    version = Version.parse(tag_name)

    firefox_asset = f"linux_entra_sso-{version}.xpi"
    thunderbird_asset = f"linux_entra_sso-{version}.thunderbird.xpi"
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("Latest release payload does not contain an assets list")

    asset_urls: dict[str, str] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        browser_download_url = asset.get("browser_download_url")
        if isinstance(name, str) and isinstance(browser_download_url, str):
            asset_urls[name] = browser_download_url

    missing = [name for name in (firefox_asset, thunderbird_asset) if name not in asset_urls]
    if missing:
        raise RuntimeError(
            "Latest linux-entra-sso release "
            f"{tag_name} is missing required asset(s): {', '.join(missing)}"
        )

    return ReleaseInfo(
        version=version,
        firefox_url=asset_urls[firefox_asset],
        thunderbird_url=asset_urls[thunderbird_asset],
    )


def fetch_latest_release() -> ReleaseInfo:
    return release_from_payload(http_json(LATEST_RELEASE_API))


def git_ls_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [repo_root / line for line in result.stdout.splitlines() if line]


def find_extension_urls(text: str) -> list[re.Match[str]]:
    return list(EXTENSION_URL_RE.finditer(text))


def highest_tracked_version(files: list[Path]) -> Version | None:
    highest: Version | None = None
    for path in files:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in find_extension_urls(text):
            release_version = Version.parse(match.group("release"))
            asset_version = Version.parse(match.group("asset"))
            if release_version != asset_version:
                raise RuntimeError(f"Mismatched release and asset version in {path}: {match.group(0)}")
            if highest is None or release_version > highest:
                highest = release_version
    return highest


def update_tracked_urls(repo_root: Path, release: ReleaseInfo) -> list[Path]:
    tracked_files = git_ls_files(repo_root)
    current_version = highest_tracked_version(tracked_files)
    if current_version is None:
        raise RuntimeError("No tracked linux-entra-sso extension URLs found")
    if release.version < current_version:
        raise RuntimeError(
            f"Refusing to downgrade linux-entra-sso from {current_version} to latest release {release.version}"
        )

    changed: list[Path] = []
    for path in tracked_files:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        def replacement(match: re.Match[str]) -> str:
            return release.thunderbird_url if match.group("thunderbird") else release.firefox_url

        updated = EXTENSION_URL_RE.sub(replacement, text)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(path.relative_to(repo_root))

    return changed


def validate_tracked_urls(repo_root: Path, release: ReleaseInfo) -> None:
    expected = {release.firefox_url, release.thunderbird_url}
    unexpected: list[str] = []
    for path in git_ls_files(repo_root):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in find_extension_urls(text):
            url = match.group(0)
            if url not in expected:
                unexpected.append(f"{path.relative_to(repo_root)}: {url}")

    if unexpected:
        details = "\n".join(unexpected)
        raise RuntimeError(f"Tracked linux-entra-sso URLs are not aligned with {release.version}:\n{details}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate tracked URLs after updating")
    args = parser.parse_args()

    try:
        release = fetch_latest_release()
        changed = update_tracked_urls(REPO_ROOT, release)
        if args.check:
            validate_tracked_urls(REPO_ROOT, release)
    except Exception as exc:
        eprint(f"error: {exc}")
        return 1

    if changed:
        print(f"Updated linux-entra-sso extension URLs to {release.version}:")
        for path in changed:
            print(f"  {path}")
    else:
        print(f"linux-entra-sso extension URLs already match {release.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
