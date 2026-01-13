#!/usr/bin/env python3
"""
AI-Powered Backport Assistant

Analyzes patches in the main branch and suggests backports to supported versions.
Uses AI (Claude or Gemini CLI) to analyze commits, apply cherry-picks, fix build
issues, and create PRs.

Supported versions are read from SECURITY.md.

Usage:
  python scripts/backport.py [--ai-provider gemini|claude] [--since COMMIT] [--dry-run]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def print_color(text: str, color: str):
    """Print colored text."""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")


@dataclass
class Commit:
    """A git commit."""
    sha: str
    short_sha: str
    subject: str
    body: str
    author: str
    date: str
    files_changed: list[str] = field(default_factory=list)

    @property
    def is_merge(self) -> bool:
        return self.subject.startswith("Merge ")

    @property
    def is_dependabot(self) -> bool:
        return "dependabot" in self.subject.lower() or "dependabot" in self.author.lower()

    @property
    def is_ci_only(self) -> bool:
        """Check if commit only affects CI files."""
        ci_patterns = [".github/", "ci/", ".gitlab-ci", "Jenkinsfile"]
        return all(any(p in f for p in ci_patterns) for f in self.files_changed) if self.files_changed else False


@dataclass
class SupportedVersion:
    """A supported version for backporting."""
    version: str
    branch: str


@dataclass
class DependabotPR:
    """A dependabot pull request."""
    number: int
    title: str
    head_sha: str
    head_ref: str
    base_ref: str
    url: str


class DependabotPRFetcher:
    """Fetch open dependabot PRs for a branch."""

    def __init__(self, repo: str):
        self.repo = repo

    def fetch_prs(self, base_branch: str) -> list[DependabotPR]:
        """Fetch open PRs from dependabot for a specific base branch."""
        try:
            result = subprocess.run(
                [
                    "gh", "pr", "list",
                    "--repo", self.repo,
                    "--author", "dependabot[bot]",
                    "--base", base_branch,
                    "--state", "open",
                    "--json", "number,title,headRefOid,headRefName,baseRefName,url",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                print_color(f"  Warning: Could not fetch dependabot PRs: {result.stderr}", "yellow")
                return []

            prs_data = json.loads(result.stdout)
            prs = []
            for pr in prs_data:
                prs.append(DependabotPR(
                    number=pr['number'],
                    title=pr['title'],
                    head_sha=pr['headRefOid'],
                    head_ref=pr['headRefName'],
                    base_ref=pr['baseRefName'],
                    url=pr['url'],
                ))

            return prs

        except subprocess.TimeoutExpired:
            print_color("  Warning: Timed out fetching dependabot PRs", "yellow")
            return []
        except json.JSONDecodeError as e:
            print_color(f"  Warning: Could not parse dependabot PR data: {e}", "yellow")
            return []
        except Exception as e:
            print_color(f"  Warning: Error fetching dependabot PRs: {e}", "yellow")
            return []


class SecurityMdParser:
    """Parse SECURITY.md to get supported versions."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root

    def parse(self) -> list[SupportedVersion]:
        """Parse supported versions from SECURITY.md."""
        security_md = self.repo_root / "SECURITY.md"
        if not security_md.exists():
            print_color("Warning: SECURITY.md not found", "yellow")
            return []

        content = security_md.read_text()
        versions = []

        # Pattern: | 2.x | Yes | or similar
        pattern = r'\|\s*([0-9]+\.x|[0-9]+\.[0-9]+\.x)\s*\|\s*.*?[Yy]es.*?\|'
        for match in re.finditer(pattern, content):
            version = match.group(1).strip()
            # Convert version to branch name (e.g., "2.x" -> "stable-2.x")
            branch = f"stable-{version}"
            versions.append(SupportedVersion(version=version, branch=branch))

        return versions


class GitClient:
    """Git operations."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root

    def run(self, *args, capture=True, check=True) -> subprocess.CompletedProcess:
        """Run a git command."""
        cmd = ["git", "-C", str(self.repo_root)] + list(args)
        if capture:
            return subprocess.run(cmd, capture_output=True, text=True, check=check)
        else:
            return subprocess.run(cmd, check=check)

    def get_commits_since(self, since: str, until: str = "HEAD") -> list[Commit]:
        """Get commits between two refs."""
        # Get commit info with custom format
        format_str = "%H%n%h%n%s%n%b%n%an%n%ad%n---COMMIT_END---"
        result = self.run(
            "log", f"{since}..{until}",
            f"--format={format_str}",
            "--date=short"
        )

        commits = []
        raw_commits = result.stdout.split("---COMMIT_END---")

        for raw in raw_commits:
            raw = raw.strip()
            if not raw:
                continue

            lines = raw.split("\n")
            if len(lines) < 5:
                continue

            sha = lines[0]
            short_sha = lines[1]
            subject = lines[2]
            # Body is everything between subject and author (last 2 lines)
            body = "\n".join(lines[3:-2]) if len(lines) > 5 else ""
            author = lines[-2]
            date = lines[-1]

            # Get files changed
            files_result = self.run("diff-tree", "--no-commit-id", "--name-only", "-r", sha)
            files = [f.strip() for f in files_result.stdout.strip().split("\n") if f.strip()]

            commits.append(Commit(
                sha=sha,
                short_sha=short_sha,
                subject=subject,
                body=body,
                author=author,
                date=date,
                files_changed=files,
            ))

        return commits

    def branch_exists(self, branch: str, remote: bool = True) -> bool:
        """Check if a branch exists."""
        try:
            if remote:
                result = self.run("ls-remote", "--heads", "origin", branch)
                return bool(result.stdout.strip())
            else:
                self.run("rev-parse", "--verify", branch)
                return True
        except subprocess.CalledProcessError:
            return False

    def get_current_branch(self) -> str:
        """Get current branch name."""
        result = self.run("rev-parse", "--abbrev-ref", "HEAD")
        return result.stdout.strip()

    def checkout(self, branch: str, create: bool = False, from_ref: Optional[str] = None):
        """Checkout a branch."""
        args = ["checkout"]
        if create:
            args.append("-b")
        args.append(branch)
        if from_ref:
            args.append(from_ref)
        result = self.run(*args, check=False)
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise subprocess.CalledProcessError(
                result.returncode, args, output=result.stdout, stderr=error_msg
            )

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes."""
        result = self.run("status", "--porcelain")
        # Filter out untracked files (lines starting with ??)
        lines = [l for l in result.stdout.strip().split('\n') if l and not l.startswith('??')]
        return bool(lines)

    def stash(self, message: str = "backport-script-stash") -> bool:
        """Stash current changes. Returns True if something was stashed."""
        result = self.run("stash", "push", "-m", message, check=False)
        return "No local changes to save" not in result.stdout

    def stash_pop(self) -> bool:
        """Pop the most recent stash. Returns True on success."""
        result = self.run("stash", "pop", check=False)
        return result.returncode == 0

    def is_commit_in_branch(self, commit_sha: str, branch: str, commit_subject: str = "") -> bool:
        """Check if a commit has already been cherry-picked to a branch.

        Checks by:
        1. Looking for "(cherry picked from commit <sha>)" in commit messages
        2. Looking for the same commit subject in the branch history
        """
        # Method 1: Check if any commit references this SHA in cherry-pick message
        try:
            result = self.run(
                "log", branch, "--grep", f"cherry picked from commit {commit_sha[:12]}",
                "--oneline", "-n", "1",
                check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                return True
        except subprocess.CalledProcessError:
            pass

        # Method 2: Check if commit subject exists in branch (exact match)
        if commit_subject:
            try:
                # Escape special regex characters in subject
                escaped_subject = re.escape(commit_subject)
                result = self.run(
                    "log", branch, f"--grep=^{escaped_subject}$",
                    "--oneline", "-n", "1", "--fixed-strings",
                    check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    return True
            except subprocess.CalledProcessError:
                pass

            # Method 3: Simpler grep without regex anchors
            try:
                result = self.run(
                    "log", branch, "--oneline", "-n", "100",
                    check=False
                )
                if result.returncode == 0 and commit_subject in result.stdout:
                    return True
            except subprocess.CalledProcessError:
                pass

        return False

    def cherry_pick(self, sha: str, no_commit: bool = False) -> bool:
        """Cherry-pick a commit. Returns True on success."""
        try:
            args = ["cherry-pick"]
            if no_commit:
                args.append("--no-commit")
            args.append(sha)
            self.run(*args)
            return True
        except subprocess.CalledProcessError:
            return False

    def abort_cherry_pick(self):
        """Abort an in-progress cherry-pick."""
        try:
            self.run("cherry-pick", "--abort")
        except subprocess.CalledProcessError:
            pass

    def reset_hard(self, ref: str = "HEAD"):
        """Hard reset to a ref."""
        self.run("reset", "--hard", ref)

    def fetch(self, remote: str = "origin"):
        """Fetch from remote."""
        self.run("fetch", remote)

    def push(self, remote: str = "origin", branch: Optional[str] = None, force: bool = False, set_upstream: bool = False):
        """Push to remote."""
        args = ["push"]
        if force:
            args.append("--force")
        if set_upstream:
            args.append("-u")
        args.append(remote)
        if branch:
            args.append(branch)
        self.run(*args, capture=False)

    def commit(self, message: str, signoff: bool = True, allow_empty: bool = False):
        """Create a commit."""
        args = ["commit", "-m", message]
        if signoff:
            args.append("--signoff")
        if allow_empty:
            args.append("--allow-empty")
        self.run(*args)

    def add(self, *paths):
        """Stage files."""
        self.run("add", *paths)

    def status_porcelain(self) -> str:
        """Get porcelain status."""
        return self.run("status", "--porcelain").stdout

    def get_merge_base(self, ref1: str, ref2: str) -> str:
        """Get merge base between two refs."""
        result = self.run("merge-base", ref1, ref2)
        return result.stdout.strip()


class AIRunner:
    """Run AI CLI for analysis and fixes."""

    ANALYSIS_PROMPT = """You are helping analyze git commits for potential backporting to stable branches.

## Context
I'm maintaining Himmelblau, an Azure AD/Entra ID authentication provider for Linux.
I need to identify commits from the main branch that should be backported to older stable versions.

## Supported Stable Versions
{versions}

## Commits to Analyze
{commits}

## Your Task
Analyze each commit and determine if it should be backported. Consider:

1. **Security fixes** - ALWAYS backport to all supported versions
2. **Bug fixes** - Backport if the bug exists in stable versions
3. **Small improvements** - Consider backporting if low-risk
4. **New features** - Generally DO NOT backport (risk of instability)
5. **Refactoring** - Generally DO NOT backport
6. **Dependencies updates** - Handle via dependabot, skip here
7. **CI/build changes** - Usually DO NOT backport unless critical

For each commit, provide:
- **Verdict**: BACKPORT, SKIP, or MAYBE
- **Target versions**: Which stable versions it applies to
- **Reason**: Brief explanation

Format your response as:
```
COMMIT: <short_sha>
VERDICT: BACKPORT|SKIP|MAYBE
TARGETS: <version1>, <version2> (or "all" for all supported)
REASON: <explanation>
```

Be conservative - stability is more important than features for stable branches.
"""

    FIX_BUILD_PROMPT = """I'm backporting a commit to an older stable branch and the build is failing.

## Original Commit
{commit_info}

## Target Branch
{target_branch}

## Build Error
```
{build_error}
```

## Your Task
1. Analyze the build error
2. Identify what needs to be fixed for the backport to work
3. Make the necessary changes to fix the build

Common issues when backporting:
- API differences between versions (especially libhimmelblau)
- Missing dependencies that were added in newer versions
- Struct field changes
- Function signature changes

Please investigate the error and apply fixes. Focus on making minimal changes
to get the build working while preserving the intent of the original commit.
"""

    FIX_DEPENDABOT_PROMPT = """I'm cherry-picking a dependabot dependency update to a stable branch and there are conflicts.

## Dependabot PR
- PR #{pr_number}: {pr_title}
- Target Branch: {target_branch}

## Conflict Details
```
{conflict_info}
```

## Your Task
1. Examine the conflicts (usually in Cargo.toml or Cargo.lock)
2. Resolve the conflicts by keeping the dependency update while maintaining compatibility
3. The goal is to update the dependency version as requested by dependabot

Common conflict scenarios:
- Cargo.toml has different formatting or additional dependencies in stable branch
- Cargo.lock has different dependency trees
- Version constraints may differ between branches

Tips:
- For Cargo.toml conflicts: Accept the new version from dependabot, but keep any stable-branch-specific dependencies
- For Cargo.lock conflicts: After resolving Cargo.toml, run `cargo update -p <package>` to regenerate the lock file
- Make sure to stage resolved files with `git add`

Please resolve the conflicts and ensure the dependency update is applied correctly.
"""

    def __init__(self, provider: str, cli_path: Optional[str] = None):
        self.provider = provider
        self.cli_path = cli_path or provider

    def is_available(self) -> bool:
        """Check if the AI CLI is available."""
        return shutil.which(self.cli_path) is not None

    def analyze_commits(self, commits: list[Commit], versions: list[SupportedVersion]) -> dict:
        """Ask AI to analyze commits for backporting."""
        versions_str = "\n".join(f"- {v.version} (branch: {v.branch})" for v in versions)

        commits_str = ""
        for c in commits:
            commits_str += f"\n### Commit {c.short_sha}\n"
            commits_str += f"**Subject**: {c.subject}\n"
            commits_str += f"**Author**: {c.author}\n"
            commits_str += f"**Date**: {c.date}\n"
            commits_str += f"**Files**: {', '.join(c.files_changed[:10])}"
            if len(c.files_changed) > 10:
                commits_str += f" (+{len(c.files_changed) - 10} more)"
            commits_str += "\n"
            if c.body:
                commits_str += f"**Body**:\n{c.body[:500]}\n"

        prompt = self.ANALYSIS_PROMPT.format(
            versions=versions_str,
            commits=commits_str,
        )

        return self._run_prompt(prompt)

    def fix_build_interactive(self, commit: Commit, target_branch: str, build_error: str) -> bool:
        """Launch AI CLI to fix build issues (auto-exits when done)."""
        commit_info = f"""
Commit: {commit.sha}
Subject: {commit.subject}
Author: {commit.author}
Files: {', '.join(commit.files_changed)}
"""
        if commit.body:
            commit_info += f"Body:\n{commit.body}\n"

        prompt = self.FIX_BUILD_PROMPT.format(
            commit_info=commit_info,
            target_branch=target_branch,
            build_error=build_error,
        )

        print_color(f"\nLaunching {self.provider} CLI to fix build (will exit automatically when done)...", "green")

        try:
            # Use -p flag for non-interactive mode that exits when done
            result = subprocess.run(
                [self.cli_path, "-p", prompt],
                timeout=600,  # 10 minute timeout for complex fixes
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print_color(f"  {self.provider} timed out after 10 minutes", "yellow")
            return False
        except KeyboardInterrupt:
            print("\n")
            return False
        except Exception as e:
            print_color(f"Error running {self.provider}: {e}", "red")
            return False

    def fix_dependabot_conflict_interactive(
        self,
        pr: "DependabotPR",
        target_branch: str,
        conflict_info: str,
    ) -> bool:
        """Launch AI CLI to fix dependabot cherry-pick conflicts (auto-exits when done)."""
        prompt = self.FIX_DEPENDABOT_PROMPT.format(
            pr_number=pr.number,
            pr_title=pr.title,
            target_branch=target_branch,
            conflict_info=conflict_info,
        )

        print_color(f"\nLaunching {self.provider} CLI to fix dependabot conflict (will exit automatically when done)...", "green")

        try:
            # Use -p flag for non-interactive mode that exits when done
            result = subprocess.run(
                [self.cli_path, "-p", prompt],
                timeout=300,  # 5 minute timeout for dependency conflicts
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print_color(f"  {self.provider} timed out after 5 minutes", "yellow")
            return False
        except KeyboardInterrupt:
            print("\n")
            return False
        except Exception as e:
            print_color(f"Error running {self.provider}: {e}", "red")
            return False

    def _run_prompt(self, prompt: str) -> Optional[str]:
        """Run a prompt through the AI CLI."""
        try:
            if self.provider == 'claude':
                result = subprocess.run(
                    [self.cli_path, "-p", prompt, "--output-format", "text"],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()

            elif self.provider == 'gemini':
                result = subprocess.run(
                    [self.cli_path, "-p", prompt],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()

            # Fallback: pipe via stdin
            result = subprocess.run(
                [self.cli_path],
                input=prompt,
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()

            return None
        except subprocess.TimeoutExpired:
            print_color("AI analysis timed out", "yellow")
            return None
        except Exception as e:
            print_color(f"Error running AI: {e}", "red")
            return None


class BackportManager:
    """Manages the backport process."""

    def __init__(
        self,
        repo_root: Path,
        git: GitClient,
        ai: AIRunner,
        versions: list[SupportedVersion],
        dry_run: bool = False,
    ):
        self.repo_root = repo_root
        self.git = git
        self.ai = ai
        self.versions = versions
        self.dry_run = dry_run

    def update_make_vet_from_main(self, target_branch: str) -> bool:
        """Update make vet target and cargo_vet_review.py from main branch."""
        print_color("\nUpdating `make vet` from main branch...", "blue")

        try:
            # 1. Download latest cargo_vet_review.py from main
            url = "https://raw.githubusercontent.com/himmelblau-idm/himmelblau/refs/heads/main/scripts/cargo_vet_review.py"
            scripts_dir = self.repo_root / "scripts"
            target_file = scripts_dir / "cargo_vet_review.py"

            print(f"  Downloading {url}...")
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'himmelblau-backport/1.0',
                })
                with urllib.request.urlopen(req, timeout=30) as response:
                    content = response.read().decode('utf-8')

                target_file.write_text(content)
                print_color("  Updated scripts/cargo_vet_review.py", "green")
            except Exception as e:
                print_color(f"  Warning: Could not download cargo_vet_review.py: {e}", "yellow")

            # 2. Get the make vet target from main Makefile
            makefile_url = "https://raw.githubusercontent.com/himmelblau-idm/himmelblau/refs/heads/main/Makefile"
            print(f"  Downloading {makefile_url}...")
            try:
                req = urllib.request.Request(makefile_url, headers={
                    'User-Agent': 'himmelblau-backport/1.0',
                })
                with urllib.request.urlopen(req, timeout=30) as response:
                    main_makefile = response.read().decode('utf-8')

                # Extract the vet target from main Makefile
                vet_match = re.search(r'^vet:.*?(?=^[a-z]|\Z)', main_makefile, re.MULTILINE | re.DOTALL)
                if vet_match:
                    main_vet_target = vet_match.group(0).strip()

                    # Read current Makefile
                    local_makefile_path = self.repo_root / "Makefile"
                    local_makefile = local_makefile_path.read_text()

                    # Replace or add vet target
                    local_vet_match = re.search(r'^vet:.*?(?=^[a-z]|\Z)', local_makefile, re.MULTILINE | re.DOTALL)
                    if local_vet_match:
                        # Replace existing vet target
                        new_makefile = local_makefile[:local_vet_match.start()] + main_vet_target + "\n\n" + local_makefile[local_vet_match.end():]
                    else:
                        # Add vet target before help target (or at end)
                        help_match = re.search(r'^help:', local_makefile, re.MULTILINE)
                        if help_match:
                            new_makefile = local_makefile[:help_match.start()] + main_vet_target + "\n\n" + local_makefile[help_match.start():]
                        else:
                            new_makefile = local_makefile + "\n\n" + main_vet_target + "\n"

                    local_makefile_path.write_text(new_makefile)
                    print_color("  Updated Makefile vet target", "green")
                else:
                    print_color("  Warning: Could not find vet target in main Makefile", "yellow")

            except Exception as e:
                print_color(f"  Warning: Could not update Makefile: {e}", "yellow")

            # 3. Stage and commit changes if any
            status = self.git.status_porcelain()
            if status:
                self.git.add("scripts/cargo_vet_review.py", "Makefile")
                self.git.commit(
                    "Update make vet from main branch\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                    signoff=True
                )
                print_color("  Committed vet updates", "green")
            else:
                print_color("  No vet changes needed", "green")

            return True

        except Exception as e:
            print_color(f"Error updating make vet: {e}", "red")
            return False

    def run_make_vet(self) -> tuple[bool, str]:
        """Run make vet and return success status and output."""
        print_color("\nRunning `make vet`...", "blue")
        try:
            result = subprocess.run(
                ["make", "vet"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=600,
            )
            output = result.stdout + result.stderr
            if result.returncode == 0:
                print_color("  make vet passed", "green")
                return True, output
            else:
                print_color("  make vet failed", "red")
                return False, output
        except subprocess.TimeoutExpired:
            return False, "make vet timed out"
        except Exception as e:
            return False, str(e)

    def try_build(self) -> tuple[bool, str]:
        """Try to build the project. Returns (success, error_output)."""
        print_color("  Building project...", "blue")
        try:
            result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode == 0:
                print_color("  Build succeeded", "green")
                return True, ""
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "Build timed out"
        except Exception as e:
            return False, str(e)

    def update_libhimmelblau(self) -> bool:
        """Update libhimmelblau to latest version."""
        print_color("  Updating libhimmelblau...", "blue")
        try:
            # Update Cargo.toml to use latest libhimmelblau
            result = subprocess.run(
                ["cargo", "update", "-p", "libhimmelblau"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                # Check if Cargo.lock changed
                status = self.git.status_porcelain()
                if "Cargo.lock" in status:
                    self.git.add("Cargo.lock")
                    self.git.commit(
                        "Update libhimmelblau to latest version\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                        signoff=True
                    )
                    print_color("  Updated libhimmelblau", "green")
                else:
                    print_color("  libhimmelblau already at latest", "green")
                return True
            else:
                print_color(f"  Warning: Could not update libhimmelblau: {result.stderr}", "yellow")
                return True  # Non-fatal
        except Exception as e:
            print_color(f"  Warning: Could not update libhimmelblau: {e}", "yellow")
            return True  # Non-fatal

    def cherry_pick_dependabot_prs(
        self,
        prs: list[DependabotPR],
        target_version: SupportedVersion,
    ) -> list[DependabotPR]:
        """Cherry-pick dependabot PRs onto the current branch.

        Returns a list of successfully cherry-picked PRs.
        """
        if not prs:
            return []

        print_color(f"\n  Cherry-picking {len(prs)} dependabot PR(s)...", "blue")
        successful = []

        for pr in prs:
            print(f"    PR #{pr.number}: {pr.title[:50]}...")

            # Fetch the PR's head ref
            try:
                self.git.run("fetch", "origin", f"pull/{pr.number}/head:{pr.head_ref}")
            except subprocess.CalledProcessError as e:
                print_color(f"      Failed to fetch PR #{pr.number}: {e}", "yellow")
                continue

            # Try to cherry-pick the commit
            if self.git.cherry_pick(pr.head_sha):
                print_color(f"      Cherry-picked successfully", "green")
                successful.append(pr)
            else:
                print_color(f"      Cherry-pick failed (conflicts), launching AI to fix...", "yellow")

                # Get conflict details
                status = self.git.status_porcelain()

                # Launch AI to fix conflicts
                if not self.ai.fix_dependabot_conflict_interactive(pr, target_version.branch, status):
                    print_color(f"      AI fix aborted, skipping PR", "yellow")
                    self.git.abort_cherry_pick()
                    continue

                # Check if conflicts were resolved
                status = self.git.status_porcelain()
                if "UU " in status or "AA " in status or "DD " in status:
                    print_color(f"      Conflicts not fully resolved, skipping PR", "yellow")
                    self.git.abort_cherry_pick()
                    continue

                # Stage any resolved files and complete the cherry-pick
                try:
                    self.git.add("-A")
                    # Check if there's anything to commit (cherry-pick might have completed)
                    status = self.git.status_porcelain()
                    if status:
                        self.git.commit(
                            f"{pr.title}\n\n(cherry-picked from dependabot PR #{pr.number})\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                            signoff=True
                        )
                    print_color(f"      Conflict resolved, cherry-pick complete", "green")
                    successful.append(pr)
                except subprocess.CalledProcessError as e:
                    print_color(f"      Failed to complete cherry-pick: {e}", "yellow")
                    self.git.abort_cherry_pick()
                    continue

        if successful:
            print_color(f"  Successfully cherry-picked {len(successful)}/{len(prs)} dependabot PR(s)", "green")
        else:
            print_color(f"  No dependabot PRs could be cherry-picked", "yellow")

        return successful

    def backport_commit(
        self,
        commit: Commit,
        target_version: SupportedVersion,
        branch_prefix: str = "backport",
    ) -> Optional[str]:
        """
        Backport a single commit to a target version.
        Returns the branch name on success, None on failure.
        """
        branch_name = f"{branch_prefix}/{commit.short_sha}-to-{target_version.version}"

        print_color(f"\n  Backporting {commit.short_sha} to {target_version.branch}...", "cyan")

        # Fetch latest
        self.git.fetch()

        # Create branch from stable branch
        try:
            self.git.checkout(branch_name, create=True, from_ref=f"origin/{target_version.branch}")
        except subprocess.CalledProcessError as e:
            print_color(f"  Failed to create branch: {e}", "red")
            return None

        # Update libhimmelblau first
        self.update_libhimmelblau()

        # Cherry-pick the commit
        if not self.git.cherry_pick(commit.sha):
            print_color("  Cherry-pick failed, attempting to resolve...", "yellow")

            # Try to fix with AI
            status = self.git.status_porcelain()
            if status:
                build_success, build_error = False, "Cherry-pick conflict:\n" + status
                if not self.ai.fix_build_interactive(commit, target_version.branch, build_error):
                    self.git.abort_cherry_pick()
                    self.git.checkout("main")
                    return None

                # Check if user resolved conflicts
                status = self.git.status_porcelain()
                if "UU " in status or "AA " in status:
                    print_color("  Conflicts not resolved, aborting", "red")
                    self.git.abort_cherry_pick()
                    self.git.checkout("main")
                    return None

                # Commit the resolution
                self.git.add("-A")
                try:
                    self.git.commit(
                        f"{commit.subject}\n\n(cherry-picked from {commit.sha})\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                        signoff=True
                    )
                except subprocess.CalledProcessError:
                    pass  # May already be committed

        # Try to build
        build_success, build_error = self.try_build()
        max_fix_attempts = 3
        attempt = 0

        while not build_success and attempt < max_fix_attempts:
            attempt += 1
            print_color(f"  Build failed, attempt {attempt}/{max_fix_attempts} to fix...", "yellow")

            if not self.ai.fix_build_interactive(commit, target_version.branch, build_error):
                break

            # Check for changes
            status = self.git.status_porcelain()
            if status:
                self.git.add("-A")
                self.git.commit(
                    f"Fix build for backport of {commit.short_sha}\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                    signoff=True
                )

            build_success, build_error = self.try_build()

        if not build_success:
            print_color("  Could not fix build, skipping this backport", "red")
            self.git.checkout("main")
            return None

        print_color(f"  Backport successful on branch {branch_name}", "green")
        return branch_name

    def create_pr(
        self,
        branch_name: str,
        target_version: SupportedVersion,
        commits: list[Commit],
        dependabot_prs: Optional[list[DependabotPR]] = None,
    ) -> bool:
        """Create a PR for the backport."""
        print_color(f"\nCreating PR for {branch_name}...", "blue")

        if self.dry_run:
            print_color("  (dry-run) Would create PR", "yellow")
            return True

        # Push the branch
        try:
            self.git.push("origin", branch_name, set_upstream=True)
        except subprocess.CalledProcessError as e:
            print_color(f"  Failed to push: {e}", "red")
            return False

        # Create PR body
        commit_list = "\n".join(f"- {c.short_sha}: {c.subject}" for c in commits)

        # Add dependabot PRs section if any
        dependabot_section = ""
        if dependabot_prs:
            dependabot_list = "\n".join(f"- {pr.title} (#{pr.number})" for pr in dependabot_prs)
            dependabot_section = f"""
### Dependabot Updates Included
{dependabot_list}

"""

        body = f"""## Summary
Backport commits to {target_version.branch}:

{commit_list}
{dependabot_section}
## Test plan
- [ ] Build succeeds
- [ ] `make vet` passes
- [ ] Basic functionality tested

---
Generated with [Claude Code](https://claude.com/claude-code)
"""

        # Create the PR title
        title_parts = []
        if commits:
            if len(commits) == 1:
                title_parts.append(commits[0].subject)
            else:
                title_parts.append(f"{len(commits)} commits")
        if dependabot_prs:
            title_parts.append(f"{len(dependabot_prs)} dependency update(s)")

        title = f"Backport to {target_version.version}: " + " + ".join(title_parts)

        try:
            result = subprocess.run(
                [
                    "gh", "pr", "create",
                    "--title", title,
                    "--body", body,
                    "--base", target_version.branch,
                    "--head", branch_name,
                ],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                pr_url = result.stdout.strip()
                print_color(f"  PR created: {pr_url}", "green")
                return True
            else:
                print_color(f"  Failed to create PR: {result.stderr}", "red")
                return False
        except Exception as e:
            print_color(f"  Failed to create PR: {e}", "red")
            return False


def normalize_version_target(target: str) -> str:
    """Normalize a version target string.

    Converts various formats to a canonical version string:
    - 'stable-2.x' -> '2.x'
    - '2.x' -> '2.x'
    - 'none' -> ''
    """
    target = target.strip().lower()
    if target in ('none', 'n/a', '-', ''):
        return ''
    # Remove 'stable-' prefix if present
    if target.startswith('stable-'):
        target = target[7:]
    return target


def parse_ai_analysis(analysis: str) -> dict[str, dict]:
    """Parse AI analysis output into structured data."""
    results = {}
    current_commit = None

    for line in analysis.split('\n'):
        line = line.strip()
        if line.startswith('COMMIT:'):
            current_commit = line.split(':', 1)[1].strip()
            results[current_commit] = {'verdict': 'SKIP', 'targets': [], 'reason': ''}
        elif line.startswith('VERDICT:') and current_commit:
            results[current_commit]['verdict'] = line.split(':', 1)[1].strip().upper()
        elif line.startswith('TARGETS:') and current_commit:
            targets_str = line.split(':', 1)[1].strip()
            if targets_str.lower() == 'all':
                results[current_commit]['targets'] = ['all']
            else:
                # Parse and normalize each target
                targets = []
                for t in targets_str.split(','):
                    normalized = normalize_version_target(t)
                    if normalized:  # Skip empty (none) targets
                        targets.append(normalized)
                results[current_commit]['targets'] = targets
        elif line.startswith('REASON:') and current_commit:
            results[current_commit]['reason'] = line.split(':', 1)[1].strip()

    return results


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered backport assistant for Himmelblau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze recent commits and suggest backports
  %(prog)s --target 2.x             # Only backport to stable-2.x branch
  %(prog)s --target 2.x --target 1.x  # Backport to 2.x and 1.x branches
  %(prog)s --since v2.0.0           # Analyze commits since v2.0.0
  %(prog)s --ai-provider gemini     # Use Gemini AI instead of Claude
  %(prog)s --dry-run                # Analyze only, don't create PRs
  %(prog)s --interactive            # Interactive mode - confirm each backport
        """,
    )
    parser.add_argument(
        "--ai-provider",
        type=str,
        default="claude",
        choices=["claude", "gemini"],
        help="AI CLI to use (default: claude)",
    )
    parser.add_argument(
        "--ai-provider-path",
        type=str,
        default=None,
        help="Path to the AI CLI binary",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help="Analyze commits since this ref (default: auto-detect from stable branches)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze and suggest only, don't apply backports",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive mode - confirm each backport before applying",
    )
    parser.add_argument(
        "--repo",
        type=str,
        default="himmelblau-idm/himmelblau",
        help="GitHub repository (default: himmelblau-idm/himmelblau)",
    )
    parser.add_argument(
        "--target",
        type=str,
        action="append",
        dest="targets",
        metavar="VERSION",
        help="Target version(s) to backport to (e.g., '2.x', 'stable-2.x'). "
             "Can be specified multiple times. If not specified, all supported versions are used.",
    )
    parser.add_argument(
        "--skip-dependabot",
        action="store_true",
        help="Skip cherry-picking open dependabot PRs",
    )

    args = parser.parse_args()

    # Determine repo root
    repo_root = Path(__file__).parent.parent.resolve()

    print_color("=" * 70, "cyan")
    print_color("  Himmelblau AI Backport Assistant", "bold")
    print_color("=" * 70, "cyan")
    print()

    # Initialize components
    git = GitClient(repo_root)
    ai = AIRunner(args.ai_provider, args.ai_provider_path)
    security_parser = SecurityMdParser(repo_root)

    # Check prerequisites
    if not shutil.which("gh"):
        print_color("Error: GitHub CLI (gh) is not installed", "red")
        print("Install from: https://cli.github.com/")
        sys.exit(1)

    if not ai.is_available():
        cli_name = args.ai_provider_path or args.ai_provider
        print_color(f"Error: {args.ai_provider.capitalize()} CLI not found at '{cli_name}'", "red")
        if args.ai_provider == "claude":
            print("Install with: npm install -g @anthropic-ai/claude-code")
        elif args.ai_provider == "gemini":
            print("Install with: npm install -g @anthropic-ai/gemini-cli")
        sys.exit(1)

    print_color(f"Using {args.ai_provider.capitalize()} CLI", "green")

    # Parse supported versions
    versions = security_parser.parse()
    if not versions:
        print_color("Error: No supported versions found in SECURITY.md", "red")
        sys.exit(1)

    print_color(f"\nSupported versions for backporting:", "blue")
    for v in versions:
        branch_exists = git.branch_exists(v.branch)
        status = "exists" if branch_exists else "NOT FOUND"
        color = "green" if branch_exists else "red"
        print_color(f"  - {v.version} (branch: {v.branch}) [{status}]", color)

    # Filter to versions with existing branches
    versions = [v for v in versions if git.branch_exists(v.branch)]
    if not versions:
        print_color("Error: No valid stable branches found", "red")
        sys.exit(1)

    # Filter by target versions if specified
    if args.targets:
        def matches_target(v: SupportedVersion, targets: list[str]) -> bool:
            for t in targets:
                # Normalize target: remove 'stable-' prefix if present
                normalized = t.replace('stable-', '')
                if v.version == normalized or v.branch == t or v.branch == f"stable-{t}":
                    return True
            return False

        filtered_versions = [v for v in versions if matches_target(v, args.targets)]
        if not filtered_versions:
            print_color(f"Error: No matching versions found for targets: {args.targets}", "red")
            print("Available versions:")
            for v in versions:
                print(f"  - {v.version} (branch: {v.branch})")
            sys.exit(1)
        versions = filtered_versions
        print_color(f"\nFiltered to target version(s): {', '.join(v.version for v in versions)}", "blue")

    # Determine the 'since' ref
    if args.since:
        since_ref = args.since
    else:
        # Use the merge base of main and the oldest stable branch
        oldest_branch = versions[-1].branch
        since_ref = git.get_merge_base(f"origin/{oldest_branch}", "origin/main")
        print_color(f"\nAuto-detected since ref: {since_ref[:12]}", "blue")

    # Get commits to analyze
    print_color(f"\nFetching commits from {since_ref[:12]}..HEAD...", "blue")
    git.fetch()
    commits = git.get_commits_since(since_ref)

    # Filter out merge commits, dependabot, and CI-only commits
    original_count = len(commits)
    commits = [c for c in commits if not c.is_merge and not c.is_dependabot and not c.is_ci_only]

    print(f"  Found {original_count} commits, {len(commits)} after filtering")
    print(f"  (Filtered out merge commits, dependabot updates, and CI-only changes)")

    if not commits:
        print_color("\nNo commits to analyze for backporting.", "green")
        sys.exit(0)

    # Display commits
    print_color(f"\nCommits to analyze ({len(commits)}):", "blue")
    for c in commits[:20]:
        print(f"  {c.short_sha} {c.subject[:60]}")
    if len(commits) > 20:
        print(f"  ... and {len(commits) - 20} more")

    # Ask AI to analyze commits
    print_color("\nAnalyzing commits with AI...", "blue")
    analysis_result = ai.analyze_commits(commits, versions)

    if not analysis_result:
        print_color("AI analysis failed", "red")
        sys.exit(1)

    print()
    print_color("=" * 70, "magenta")
    print_color("AI ANALYSIS", "bold")
    print_color("=" * 70, "magenta")
    print()
    print(analysis_result)
    print()

    # Parse the analysis
    parsed = parse_ai_analysis(analysis_result)

    # Identify backports to apply
    backports_to_apply = []
    for commit in commits:
        if commit.short_sha in parsed:
            info = parsed[commit.short_sha]
            if info['verdict'] == 'BACKPORT':
                targets = info['targets']
                if not targets:
                    # No targets specified but verdict is BACKPORT - skip
                    continue
                if 'all' in targets:
                    target_versions = versions
                else:
                    # Match targets against versions (both are normalized now)
                    # e.g., target '2.x' should match version '2.x'
                    target_versions = [
                        v for v in versions
                        if any(t == v.version.lower() or t in v.version.lower() for t in targets)
                    ]

                for tv in target_versions:
                    backports_to_apply.append((commit, tv))

    if not backports_to_apply:
        print_color("\nNo commits recommended for backporting.", "green")
        sys.exit(0)

    print_color(f"\nBackports to apply ({len(backports_to_apply)}):", "blue")
    for commit, target in backports_to_apply:
        print(f"  {commit.short_sha} -> {target.version}: {commit.subject[:50]}")

    if args.dry_run:
        print_color("\n(dry-run mode - no changes will be made)", "yellow")
        sys.exit(0)

    # Confirm before proceeding
    if args.interactive:
        try:
            confirm = input("\nProceed with backports? [y/N]: ").strip().lower()
            if confirm != 'y':
                print_color("Aborted.", "yellow")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print_color("\nAborted.", "yellow")
            sys.exit(0)

    # Save current branch
    original_branch = git.get_current_branch()

    # Check for uncommitted changes
    stashed = False
    if git.has_uncommitted_changes():
        print_color("\nYou have uncommitted changes in your working directory.", "yellow")
        print("Git cannot switch branches with uncommitted changes.")
        try:
            choice = input("Would you like to stash them? [Y/n]: ").strip().lower()
            if choice == 'n':
                print_color("Cannot proceed without stashing changes. Please commit or stash manually.", "red")
                sys.exit(1)
            else:
                if git.stash("backport-script-auto-stash"):
                    print_color("Changes stashed successfully.", "green")
                    stashed = True
                else:
                    print_color("No changes to stash (only untracked files).", "green")
        except (KeyboardInterrupt, EOFError):
            print_color("\nAborted.", "yellow")
            sys.exit(0)

    # Initialize backport manager and dependabot fetcher
    manager = BackportManager(repo_root, git, ai, versions, args.dry_run)
    dependabot_fetcher = DependabotPRFetcher(args.repo)

    # Group backports by target version
    by_version: dict[str, list[Commit]] = {}
    for commit, target in backports_to_apply:
        key = target.version
        if key not in by_version:
            by_version[key] = []
        by_version[key].append(commit)

    # Apply backports
    successful_branches = []
    for version_str, commits_for_version in by_version.items():
        target = next(v for v in versions if v.version == version_str)
        print_color(f"\n{'=' * 70}", "cyan")
        print_color(f"Processing backports to {version_str}", "bold")
        print_color(f"{'=' * 70}", "cyan")

        # Create a single branch for all commits to this version
        branch_name = f"backport/batch-to-{version_str}"
        timestamp = subprocess.run(
            ["date", "+%Y%m%d%H%M%S"],
            capture_output=True, text=True
        ).stdout.strip()
        branch_name = f"{branch_name}-{timestamp}"

        print_color(f"\nCreating branch {branch_name}...", "blue")

        # Fetch and create branch
        git.fetch()
        try:
            git.checkout(branch_name, create=True, from_ref=f"origin/{target.branch}")
        except subprocess.CalledProcessError as e:
            error_detail = e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)
            print_color(f"Failed to create branch: {error_detail}", "red")
            try:
                git.checkout(original_branch)
            except subprocess.CalledProcessError:
                pass  # Already on original branch or can't switch
            continue

        # Update libhimmelblau first
        manager.update_libhimmelblau()

        # Fetch and cherry-pick open dependabot PRs for this branch
        cherry_picked_dependabot_prs = []
        if not args.skip_dependabot:
            print_color(f"\nChecking for open dependabot PRs on {target.branch}...", "blue")
            dependabot_prs = dependabot_fetcher.fetch_prs(target.branch)
            if dependabot_prs:
                print_color(f"  Found {len(dependabot_prs)} open dependabot PR(s):", "green")
                for pr in dependabot_prs:
                    print(f"    - PR #{pr.number}: {pr.title[:60]}")
                cherry_picked_dependabot_prs = manager.cherry_pick_dependabot_prs(dependabot_prs, target)
            else:
                print_color("  No open dependabot PRs found", "green")
        else:
            print_color("\nSkipping dependabot PRs (--skip-dependabot)", "yellow")

        # Apply each commit
        all_success = True
        skipped_already_present = 0
        for commit in commits_for_version:
            print_color(f"\n  Cherry-picking {commit.short_sha}: {commit.subject[:50]}...", "cyan")

            # Check if commit is already in the target branch
            if git.is_commit_in_branch(commit.sha, f"origin/{target.branch}", commit.subject):
                print_color("    Already present in target branch, skipping", "yellow")
                skipped_already_present += 1
                continue

            if args.interactive:
                try:
                    confirm = input("  Apply this commit? [Y/n]: ").strip().lower()
                    if confirm == 'n':
                        print_color("  Skipped", "yellow")
                        continue
                except (KeyboardInterrupt, EOFError):
                    print_color("\nAborted.", "yellow")
                    git.checkout(original_branch)
                    sys.exit(0)

            if not git.cherry_pick(commit.sha):
                print_color("  Cherry-pick failed, launching AI to fix...", "yellow")

                status = git.status_porcelain()
                if not ai.fix_build_interactive(commit, target.branch, f"Cherry-pick conflict:\n{status}"):
                    git.abort_cherry_pick()
                    all_success = False
                    continue

                # Check if resolved
                status = git.status_porcelain()
                if "UU " in status or "AA " in status:
                    print_color("  Conflicts not resolved, skipping commit", "red")
                    git.abort_cherry_pick()
                    all_success = False
                    continue

                # Commit resolution
                git.add("-A")
                try:
                    git.commit(
                        f"{commit.subject}\n\n(cherry-picked from {commit.sha})\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                        signoff=True
                    )
                except subprocess.CalledProcessError:
                    pass

            print_color("  Cherry-pick successful", "green")

        if skipped_already_present > 0:
            print_color(f"\n  Skipped {skipped_already_present} commit(s) already present in {target.branch}", "yellow")

        if not all_success:
            print_color(f"\nSome cherry-picks failed for {version_str}", "yellow")

        # Try to build
        build_success, build_error = manager.try_build()
        max_fix_attempts = 3
        attempt = 0

        while not build_success and attempt < max_fix_attempts:
            attempt += 1
            print_color(f"\nBuild failed, attempt {attempt}/{max_fix_attempts} to fix...", "yellow")

            # Use AI to fix
            dummy_commit = commits_for_version[0]  # Use first commit for context
            if not ai.fix_build_interactive(dummy_commit, target.branch, build_error):
                break

            status = git.status_porcelain()
            if status:
                git.add("-A")
                git.commit(
                    f"Fix build for backport batch\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                    signoff=True
                )

            build_success, build_error = manager.try_build()

        if not build_success:
            print_color(f"\nCould not fix build for {version_str}, skipping", "red")
            git.checkout(original_branch)
            continue

        # Update make vet from main
        manager.update_make_vet_from_main(target.branch)

        # Run make vet
        vet_success, vet_output = manager.run_make_vet()
        if not vet_success:
            print_color(f"\nmake vet failed for {version_str}", "yellow")
            print("  You may need to address vet issues manually")
            # Continue anyway - vet issues shouldn't block the PR creation

        # Commit any supply-chain changes from vetting
        status = git.status_porcelain()
        if status and ("supply-chain" in status or "audits.toml" in status or "config.toml" in status):
            print_color("\nCommitting cargo vet supply-chain updates...", "blue")
            git.add("supply-chain/")
            try:
                git.commit(
                    "Update cargo vet audits for backport\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
                    signoff=True
                )
                print_color("  Committed supply-chain updates", "green")
            except subprocess.CalledProcessError:
                # May fail if nothing to commit
                pass

        successful_branches.append((branch_name, target, commits_for_version, cherry_picked_dependabot_prs))
        print_color(f"\nBackport branch {branch_name} ready", "green")

    # Return to original branch
    git.checkout(original_branch)

    # Restore stashed changes if any
    if stashed:
        print_color("\nRestoring stashed changes...", "blue")
        if git.stash_pop():
            print_color("Stashed changes restored.", "green")
        else:
            print_color("Warning: Could not restore stashed changes. Use 'git stash pop' manually.", "yellow")

    # Create PRs for successful branches
    if successful_branches:
        print_color(f"\n{'=' * 70}", "cyan")
        print_color("Creating Pull Requests", "bold")
        print_color(f"{'=' * 70}", "cyan")

        for branch_name, target, commits_list, dependabot_prs_list in successful_branches:
            manager.create_pr(branch_name, target, commits_list, dependabot_prs_list)

    # Summary
    print()
    print_color("=" * 70, "cyan")
    print_color("SUMMARY", "bold")
    print_color("=" * 70, "cyan")
    print(f"  Commits analyzed: {len(commits)}")
    print(f"  Backports identified: {len(backports_to_apply)}")
    print(f"  Successful backport branches: {len(successful_branches)}")

    if successful_branches:
        print("\n  Created branches:")
        for branch_name, target, commits_list, dependabot_list in successful_branches:
            deps_info = f" (+{len(dependabot_list)} dependabot)" if dependabot_list else ""
            print(f"    - {branch_name} -> {target.branch}{deps_info}")


if __name__ == "__main__":
    main()
