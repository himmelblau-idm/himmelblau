#!/usr/bin/env python3
"""
Dependabot rollup helper.

Creates a single branch off main (or another base) and cherry-picks all open
Dependabot PR commits onto it so the branch can be merged into main.

Usage:
  python scripts/dependabot_rollup.py
  python scripts/dependabot_rollup.py --base main --branch dependabot-rollup-20260209
  python scripts/dependabot_rollup.py --dry-run
"""

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path

from backport import DependabotPRFetcher, GitClient, has_unresolved_conflicts, print_color


def get_commit_range(git: GitClient, base_ref: str, head_ref: str) -> tuple[str, list[str]]:
    merge_base = git.get_merge_base(base_ref, head_ref)
    commit_range = f"{merge_base}..{head_ref}"
    result = git.run("rev-list", "--reverse", commit_range)
    commits = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return commit_range, commits


def has_tracked_changes(status: str) -> bool:
    for line in status.splitlines():
        if line and not line.startswith("??"):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Roll up open Dependabot PRs into a single branch",
    )
    parser.add_argument(
        "--repo",
        default="himmelblau-idm/himmelblau",
        help="GitHub repository (default: himmelblau-idm/himmelblau)",
    )
    parser.add_argument(
        "--base",
        default="main",
        help="Base branch to roll up into (default: main)",
    )
    parser.add_argument(
        "--branch",
        default=None,
        help="Branch name to create/use (default: dependabot-rollup-<base>-YYYYMMDD)",
    )
    parser.add_argument(
        "--use-existing-branch",
        action="store_true",
        help="Use an existing local branch instead of creating a new one",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List PRs and commits without cherry-picking",
    )
    parser.add_argument(
        "--skip-conflicts",
        action="store_true",
        help="Abort and skip PRs that conflict instead of stopping",
    )
    args = parser.parse_args()

    if not shutil.which("gh"):
        print_color("Error: GitHub CLI (gh) is not installed", "red")
        print("Install from: https://cli.github.com/")
        return 1

    repo_root = Path(__file__).parent.parent.resolve()
    git = GitClient(repo_root)

    status = git.status_porcelain()
    if has_tracked_changes(status):
        print_color("Error: working tree has uncommitted changes", "red")
        print("Please commit or stash tracked changes before running.")
        return 1

    branch = args.branch
    if not branch:
        date_str = dt.datetime.now(dt.UTC).strftime("%Y%m%d")
        branch = f"dependabot-rollup-{args.base}-{date_str}"

    base_ref = f"origin/{args.base}"

    print_color("Fetching latest refs...", "blue")
    git.fetch()

    if not git.branch_exists(args.base):
        print_color(f"Error: base branch not found on origin: {args.base}", "red")
        return 1

    fetcher = DependabotPRFetcher(args.repo)
    prs = fetcher.fetch_prs(args.base)
    if not prs:
        print_color("No open Dependabot PRs found.", "yellow")
        return 0

    print_color(f"Found {len(prs)} Dependabot PR(s) targeting {args.base}", "green")

    if args.dry_run:
        for pr in prs:
            print(f"PR #{pr.number}: {pr.title}")
            try:
                git.run("fetch", "origin", f"pull/{pr.number}/head:{pr.head_ref}")
                commit_range, commits = get_commit_range(git, base_ref, pr.head_ref)
                print(f"  {commit_range} ({len(commits)} commit(s))")
            except Exception as exc:
                print_color(f"  Failed to inspect PR #{pr.number}: {exc}", "yellow")
        return 0

    if args.use_existing_branch:
        if not git.branch_exists(branch, remote=False):
            print_color(f"Error: local branch not found: {branch}", "red")
            return 1
        git.checkout(branch)
    else:
        if git.branch_exists(branch, remote=False) or git.branch_exists(branch, remote=True):
            print_color(f"Error: branch already exists: {branch}", "red")
            print("Use --use-existing-branch to reuse it.")
            return 1
        git.checkout(branch, create=True, from_ref=base_ref)

    applied = []
    skipped = []

    for pr in prs:
        print(f"\nPR #{pr.number}: {pr.title}")

        try:
            git.run("fetch", "origin", f"pull/{pr.number}/head:{pr.head_ref}")
        except Exception as exc:
            print_color(f"  Failed to fetch PR #{pr.number}: {exc}", "yellow")
            skipped.append(pr)
            continue

        commit_range, commits = get_commit_range(git, base_ref, pr.head_ref)
        if not commits:
            print_color("  No new commits to cherry-pick", "yellow")
            skipped.append(pr)
            continue

        print(f"  Cherry-picking {len(commits)} commit(s) from {commit_range}")
        result = git.run("cherry-pick", commit_range, check=False)
        if result.returncode == 0:
            print_color("  Cherry-pick successful", "green")
            applied.append(pr)
            continue

        status = git.status_porcelain()
        if has_unresolved_conflicts(status):
            print_color("  Cherry-pick conflict detected", "red")
        else:
            print_color("  Cherry-pick failed", "red")

        if args.skip_conflicts:
            git.abort_cherry_pick()
            skipped.append(pr)
            print_color("  Aborted and skipped due to --skip-conflicts", "yellow")
            continue

        print("Resolve conflicts, then run `git cherry-pick --continue`.")
        print("After resolving, you can re-run this script to process remaining PRs.")
        return 1

    print_color("\nRollup complete", "green")
    print(f"Branch: {branch}")
    print(f"Applied: {len(applied)}")
    if skipped:
        print(f"Skipped: {len(skipped)}")
        for pr in skipped:
            print(f"  - #{pr.number}: {pr.title}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
