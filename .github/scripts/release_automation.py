#!/usr/bin/env python3
"""Release and linked-artifact automation for Himmelblau."""

from __future__ import annotations

import argparse
import dataclasses
import gzip
import hashlib
import html.parser
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PACKAGE_BASE_URL = "https://packages.himmelblau-idm.org/"
STABLE_TAG_RE = re.compile(r"^\d+\.\d+\.\d+$")
REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_API = "https://api.github.com"

# Context limits for AI release note generation.
# Large initial releases may have 500+ commits and 1000+ files, so we use generous limits.
# At ~100 bytes/commit and ~80 bytes/file, this allows roughly 200KB of context data,
# which fits comfortably within typical LLM context windows when combined with the prompt template.
MAX_COMMITS_IN_CONTEXT = 2000
MAX_FILES_IN_CONTEXT = 2000

# Maximum size for a single field in Debian Packages format to prevent issues with
# malformed files containing excessive continuation lines.
MAX_DEBIAN_FIELD_SIZE = 1024 * 1024  # 1MB

# Network retry configuration for transient failures
HTTP_RETRY_ATTEMPTS = 3
HTTP_RETRY_INITIAL_DELAY = 1.0  # seconds
HTTP_RETRY_BACKOFF_MULTIPLIER = 2.0


@dataclasses.dataclass(frozen=True)
class Artifact:
    name: str
    version: str
    digest: str
    artifact_url: str
    registry_url: str
    repository: str
    status: str
    github_repository: str
    kind: str

    def storage_payload(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "artifact_url": self.artifact_url,
            "registry_url": self.registry_url,
            "repository": self.repository,
            "status": self.status,
            "github_repository": self.github_repository,
        }


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def http_request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    retry: bool = True,
) -> tuple[int, bytes]:
    """Make an HTTP request with automatic retry on transient failures.

    Args:
        url: URL to request
        method: HTTP method (GET, POST, etc.)
        data: Request body for POST/PUT
        headers: HTTP headers
        retry: Enable retry with exponential backoff for GET requests (default True)

    Returns:
        Tuple of (status_code, response_body)

    Raises:
        RuntimeError: On HTTP error or network failure after all retries
    """
    request = urllib.request.Request(url, method=method, data=data)
    merged_headers = {"User-Agent": "Himmelblau-Release-Automation/1.0", **(headers or {})}
    for name, value in merged_headers.items():
        request.add_header(name, value)

    # Only retry GET requests; mutations (POST, etc.) should not auto-retry
    max_attempts = HTTP_RETRY_ATTEMPTS if retry and method == "GET" else 1
    delay = HTTP_RETRY_INITIAL_DELAY

    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            # Don't retry client errors (4xx), only server errors (5xx)
            if exc.code < 500:
                body = exc.read()
                excerpt = body[:500].decode(errors='replace')
                suffix = "..." if len(body) > 500 else ""
                raise RuntimeError(f"HTTP {exc.code} for {url}: {excerpt}{suffix}") from exc

            if attempt < max_attempts:
                eprint(f"HTTP {exc.code} for {url}, retrying in {delay:.1f}s (attempt {attempt}/{max_attempts})")
                time.sleep(delay)
                delay *= HTTP_RETRY_BACKOFF_MULTIPLIER
                continue

            body = exc.read()
            excerpt = body[:500].decode(errors='replace')
            suffix = "..." if len(body) > 500 else ""
            raise RuntimeError(
                f"HTTP {exc.code} for {url} after {max_attempts} attempts: {excerpt}{suffix}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt < max_attempts:
                eprint(f"Network error for {url}: {exc}, retrying in {delay:.1f}s (attempt {attempt}/{max_attempts})")
                time.sleep(delay)
                delay *= HTTP_RETRY_BACKOFF_MULTIPLIER
                continue
            raise RuntimeError(f"HTTP request failed for {url} after {max_attempts} attempts: {exc}") from exc


def fetch_text(url: str) -> str:
    _, body = http_request(url)
    return body.decode("utf-8")


def fetch_bytes(url: str) -> bytes:
    _, body = http_request(url)
    return body


def parse_index_links(html: str) -> list[str]:
    parser = LinkParser()
    parser.feed(html)
    return [href for href in parser.hrefs if href != "../"]


def stable_release_url(tag: str) -> str:
    return urllib.parse.urljoin(PACKAGE_BASE_URL, f"stable/{tag}/")


def package_url(tag: str, *parts: str) -> str:
    path = "/".join(part.strip("/") for part in parts)
    return urllib.parse.urljoin(stable_release_url(tag), path)


def parse_debian_packages(text: str, base_url: str, tag: str, distro: str, github_repo: str) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        fields: dict[str, str] = {}
        current_key: str | None = None
        for line in block.splitlines():
            if not line:
                continue
            if line[0].isspace() and current_key:
                new_value = fields[current_key] + "\n" + line.strip()
                if len(new_value) > MAX_DEBIAN_FIELD_SIZE:
                    eprint(f"Warning: Debian Packages field '{current_key}' exceeds size limit, truncating")
                    continue
                fields[current_key] = new_value
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            current_key = key
            fields[key] = value.strip()

        filename = fields.get("Filename", "").removeprefix("./")
        sha256 = fields.get("SHA256")
        name = fields.get("Package")
        version = fields.get("Version", tag)
        if not filename or not sha256 or not name:
            continue

        artifacts.append(
            Artifact(
                name=name,
                version=version,
                digest=f"sha256:{sha256}",
                artifact_url=urllib.parse.urljoin(base_url, filename),
                registry_url=PACKAGE_BASE_URL,
                repository=f"stable/{tag}/deb/{distro}",
                status="active",
                github_repository=github_repo,
                kind="deb",
            )
        )
    return artifacts


def discover_deb_artifacts(tag: str, github_repo: str) -> list[Artifact]:
    deb_root = package_url(tag, "deb/")
    distros = [href.strip("/") for href in parse_index_links(fetch_text(deb_root)) if href.endswith("/")]
    artifacts: list[Artifact] = []
    for distro in distros:
        distro_url = package_url(tag, "deb", distro, "")
        packages_url = urllib.parse.urljoin(distro_url, "Packages")
        artifacts.extend(parse_debian_packages(fetch_text(packages_url), distro_url, tag, distro, github_repo))
    return artifacts


def parse_rpm_primary(xml_bytes: bytes, base_url: str, tag: str, distro: str, github_repo: str) -> list[Artifact]:
    root = ET.fromstring(xml_bytes)
    ns = {"common": "http://linux.duke.edu/metadata/common"}
    artifacts: list[Artifact] = []
    for package in root.findall("common:package", ns):
        name = package.findtext("common:name", namespaces=ns)
        arch = package.findtext("common:arch", namespaces=ns)
        checksum = package.find("common:checksum", ns)
        version_node = package.find("common:version", ns)
        location = package.find("common:location", ns)
        if name is None or checksum is None or version_node is None or location is None:
            continue
        sha256 = (checksum.text or "").strip()
        href = location.attrib.get("href", "")
        ver = version_node.attrib.get("ver", tag)
        rel = version_node.attrib.get("rel")
        version = f"{ver}-{rel}" if rel else ver
        if not sha256 or checksum.attrib.get("type") != "sha256" or not href:
            continue

        artifacts.append(
            Artifact(
                name=name,
                version=version,
                digest=f"sha256:{sha256}",
                artifact_url=urllib.parse.urljoin(base_url, href),
                registry_url=PACKAGE_BASE_URL,
                repository=f"stable/{tag}/rpm/{distro}",
                status="active",
                github_repository=github_repo,
                kind=f"rpm:{arch or 'unknown'}",
            )
        )
    return artifacts


def rpm_primary_href(repomd_xml: str) -> str:
    root = ET.fromstring(repomd_xml)
    ns = {"repo": "http://linux.duke.edu/metadata/repo"}
    for data in root.findall("repo:data", ns):
        if data.attrib.get("type") != "primary":
            continue
        location = data.find("repo:location", ns)
        if location is not None and location.attrib.get("href"):
            return location.attrib["href"]
    raise RuntimeError("RPM repodata did not contain primary metadata location")


def discover_rpm_artifacts(tag: str, github_repo: str) -> list[Artifact]:
    rpm_root = package_url(tag, "rpm/")
    distros = [href.strip("/") for href in parse_index_links(fetch_text(rpm_root)) if href.endswith("/")]
    artifacts: list[Artifact] = []
    for distro in distros:
        distro_url = package_url(tag, "rpm", distro, "")
        primary_href = rpm_primary_href(fetch_text(urllib.parse.urljoin(distro_url, "repodata/repomd.xml")))
        primary_bytes = fetch_bytes(urllib.parse.urljoin(distro_url, primary_href))
        if primary_href.endswith(".gz"):
            primary_bytes = gzip.decompress(primary_bytes)
        artifacts.extend(parse_rpm_primary(primary_bytes, distro_url, tag, distro, github_repo))
    return artifacts


def discover_sbom_artifact(tag: str, github_repo: str) -> Artifact:
    sbom_url = package_url(tag, "sbom/sbom.json")
    body = fetch_bytes(sbom_url)
    digest = hashlib.sha256(body).hexdigest()
    return Artifact(
        name="himmelblau-sbom",
        version=tag,
        digest=f"sha256:{digest}",
        artifact_url=sbom_url,
        registry_url=PACKAGE_BASE_URL,
        repository=f"stable/{tag}/sbom",
        status="active",
        github_repository=github_repo,
        kind="sbom",
    )


def stable_release_ready(tag: str) -> bool:
    try:
        root_links = set(parse_index_links(fetch_text(stable_release_url(tag))))
        if not {"deb/", "rpm/", "sbom/"}.issubset(root_links):
            return False
        sbom_links = set(parse_index_links(fetch_text(package_url(tag, "sbom/"))))
        return "sbom.json" in sbom_links
    except RuntimeError as exc:
        eprint(f"{tag}: package repository is not ready: {exc}")
        return False


def discover_artifacts(tag: str, github_repo: str) -> list[Artifact]:
    if not stable_release_ready(tag):
        return []
    artifacts: list[Artifact] = []
    artifacts.extend(discover_deb_artifacts(tag, github_repo))
    artifacts.extend(discover_rpm_artifacts(tag, github_repo))
    artifacts.append(discover_sbom_artifact(tag, github_repo))
    return artifacts


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def version_tuple(tag: str) -> tuple[int, int, int]:
    major, minor, patch = tag.split(".")
    return int(major), int(minor), int(patch)


def stable_tags() -> list[str]:
    tags = [tag for tag in run_git(["tag", "--list"]).splitlines() if STABLE_TAG_RE.fullmatch(tag)]
    return sorted(tags, key=version_tuple, reverse=True)


def previous_stable_tag(tag: str) -> str:
    target = version_tuple(tag)
    tags = [candidate for candidate in stable_tags() if version_tuple(candidate) < target]
    same_series = [candidate for candidate in tags if version_tuple(candidate)[:2] == target[:2]]
    if same_series:
        return same_series[0]
    if tags:
        return tags[0]
    raise RuntimeError(f"Could not find a previous stable tag for {tag}")


def github_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_json(path_or_url: str) -> Any:
    url = path_or_url if path_or_url.startswith("https://") else f"{GITHUB_API}{path_or_url}"
    _, body = http_request(url, headers=github_headers())
    return json.loads(body)


def local_compare_context(previous_tag: str, tag: str) -> str:
    commit_log = run_git(
        [
            "log",
            "--date=short",
            "--pretty=format:%h %ad %an%n%B%n---END-COMMIT---",
            f"{previous_tag}..{tag}",
        ]
    )
    files = run_git(["diff", "--name-status", f"{previous_tag}..{tag}"])
    diff_stat = run_git(["diff", "--stat", f"{previous_tag}..{tag}"])
    return "\n".join(
        [
            "## Local commit log",
            commit_log or "(no commits)",
            "",
            "## Changed files",
            files or "(no file changes)",
            "",
            "## Diff stat",
            diff_stat or "(no diff stat)",
        ]
    )


def github_compare_context(repo: str, previous_tag: str, tag: str) -> str:
    compare = github_json(f"/repos/{repo}/compare/{previous_tag}...{tag}")
    commits = compare.get("commits", [])
    files = compare.get("files", [])
    lines = [
        "## GitHub compare summary",
        f"Status: {compare.get('status')}",
        f"Ahead by: {compare.get('ahead_by')}",
        f"Behind by: {compare.get('behind_by')}",
        f"Total commits: {compare.get('total_commits')}",
        "",
        "## Commits from GitHub API",
    ]
    for commit in commits[:MAX_COMMITS_IN_CONTEXT]:
        sha = commit.get("sha", "")[:12]
        message = commit.get("commit", {}).get("message", "").strip()
        author = commit.get("commit", {}).get("author", {}).get("name", "")
        lines.append(f"- {sha} {author}: {message}")
    lines.extend(["", "## Files from GitHub API"])
    for file_info in files[:MAX_FILES_IN_CONTEXT]:
        lines.append(
            "- {status} {filename} (+{additions}/-{deletions}, {changes} changes)".format(
                status=file_info.get("status"),
                filename=file_info.get("filename"),
                additions=file_info.get("additions"),
                deletions=file_info.get("deletions"),
                changes=file_info.get("changes"),
            )
        )
    return "\n".join(lines)


def build_release_prompt(prompt_file: Path, repo: str, previous_tag: str, tag: str) -> str:
    compare_url = f"https://github.com/{repo}/compare/{previous_tag}...{tag}"
    prompt = prompt_file.read_text(encoding="utf-8").replace("<PASTE_COMPARE_URL_HERE>", compare_url)
    context_parts = [local_compare_context(previous_tag, tag)]
    try:
        context_parts.append(github_compare_context(repo, previous_tag, tag))
    except RuntimeError as exc:
        eprint(f"Warning: could not fetch GitHub compare context: {exc}")
    return prompt + "\n\n---\n\n# Additional Workflow-Fetched Compare Context\n\n" + "\n\n".join(context_parts)


def azure_responses_endpoint(resource_name: str) -> str:
    return f"https://{resource_name}.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview"


def extract_response_text(response: dict[str, Any]) -> str:
    if isinstance(response.get("output_text"), str):
        return response["output_text"].strip()
    chunks: list[str] = []
    for item in response.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
    if chunks:
        return "\n".join(chunks).strip()
    raise RuntimeError(f"Azure Responses API returned no text output: {json.dumps(response)[:1000]}")


def call_azure_responses(prompt: str, model: str) -> str:
    resource_name = os.environ.get("AZURE_RESOURCE_NAME")
    api_key = os.environ.get("AZURE_API_KEY") or os.environ.get("AZURE_COGNITIVE_SERVICES_API_KEY")
    if not resource_name:
        raise RuntimeError("AZURE_RESOURCE_NAME is required")
    if not api_key:
        raise RuntimeError("AZURE_API_KEY or AZURE_COGNITIVE_SERVICES_API_KEY is required")
    body = json.dumps({"model": model, "input": prompt}).encode("utf-8")
    _, response_body = http_request(
        azure_responses_endpoint(resource_name),
        method="POST",
        data=body,
        headers={
            "Content-Type": "application/json",
            "api-key": api_key,
        },
    )
    return extract_response_text(json.loads(response_body))


def storage_records(org: str, digest: str) -> list[dict[str, Any]]:
    digest_path = urllib.parse.quote(digest, safe="")
    url = f"{GITHUB_API}/orgs/{org}/artifacts/{digest_path}/metadata/storage-records"
    try:
        _, body = http_request(url, headers=github_headers())
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            return []
        raise
    data = json.loads(body)
    return data.get("storage_records", [])


def create_storage_record(org: str, artifact: Artifact) -> None:
    url = f"{GITHUB_API}/orgs/{org}/artifacts/metadata/storage-record"
    http_request(
        url,
        method="POST",
        data=json.dumps({**artifact.storage_payload(), "return_records": False}).encode("utf-8"),
        headers={**github_headers(), "Content-Type": "application/json"},
    )


def publish_artifacts(tag: str, repo: str, dry_run: bool) -> int:
    owner_repo = repo.split("/", 1)
    if len(owner_repo) != 2:
        raise RuntimeError("--repo must be in OWNER/REPO form when publishing linked artifacts")
    owner, repo_name = owner_repo
    artifacts = discover_artifacts(tag, repo_name)
    if not artifacts:
        eprint(f"{tag}: no package-complete stable release found")
        return 0

    created = 0
    skipped = 0
    for artifact in artifacts:
        payload = artifact.storage_payload()
        if dry_run:
            print(json.dumps(payload, sort_keys=True))
            continue

        existing = storage_records(owner, artifact.digest)
        if any(record.get("artifact_url") == artifact.artifact_url for record in existing):
            skipped += 1
            eprint(f"{tag}: already linked {artifact.artifact_url}")
            continue
        create_storage_record(owner, artifact)
        created += 1
        eprint(f"{tag}: linked {artifact.artifact_url}")

    eprint(f"{tag}: created {created}, skipped {skipped}, total {len(artifacts)}")
    return len(artifacts)


def cmd_release_notes(args: argparse.Namespace) -> int:
    tag = args.tag
    previous_tag = args.previous_tag or previous_stable_tag(tag)
    model = args.model or os.environ.get("AZURE_OPENAI_DEPLOYMENT") or "gpt-5.5"
    prompt = build_release_prompt(args.prompt_file, args.repo, previous_tag, tag)
    if args.dry_run:
        args.output.write_text(prompt, encoding="utf-8")
        return 0
    notes = call_azure_responses(prompt, model)
    args.output.write_text(notes + "\n", encoding="utf-8")
    eprint(f"Wrote release notes for {previous_tag}...{tag} to {args.output}")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    owner_repo = args.repo.split("/", 1)
    github_repo = owner_repo[1] if len(owner_repo) == 2 else args.repo
    artifacts = discover_artifacts(args.tag, github_repo)
    print(json.dumps([artifact.storage_payload() | {"kind": artifact.kind} for artifact in artifacts], indent=2))
    return 0


def cmd_publish_linked_artifacts(args: argparse.Namespace) -> int:
    tags = [args.tag] if args.tag else stable_tags()[: args.limit]
    total = 0
    for tag in tags:
        total += publish_artifacts(tag, args.repo, args.dry_run)
    eprint(f"Processed {len(tags)} tag(s), found {total} artifact(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "himmelblau-idm/himmelblau"))
    subparsers = parser.add_subparsers(required=True)

    release_notes = subparsers.add_parser("release-notes")
    release_notes.add_argument("--tag", required=True)
    release_notes.add_argument("--previous-tag")
    release_notes.add_argument("--prompt-file", type=Path, required=True)
    release_notes.add_argument("--output", type=Path, required=True)
    release_notes.add_argument("--model")
    release_notes.add_argument("--dry-run", action="store_true")
    release_notes.set_defaults(func=cmd_release_notes)

    discover = subparsers.add_parser("discover")
    discover.add_argument("--tag", required=True)
    discover.set_defaults(func=cmd_discover)

    publish = subparsers.add_parser("publish-linked-artifacts")
    publish.add_argument("--tag")
    publish.add_argument("--limit", type=int, default=20)
    publish.add_argument("--dry-run", action="store_true")
    publish.set_defaults(func=cmd_publish_linked_artifacts)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
