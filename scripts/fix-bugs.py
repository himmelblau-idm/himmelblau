#!/usr/bin/env python3
"""
Bug Fix Assistant

Fetches open bugs from GitHub and launches an AI CLI (Claude or Gemini)
interactively to help fix each bug.

Usage:
  python scripts/fix-bugs.py [--ai-provider gemini|claude] [--issue NUMBER]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
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
class Bug:
    """A GitHub bug report."""
    number: int
    title: str
    body: str
    url: str
    author: str
    created_at: str
    labels: list[str]

    @property
    def version(self) -> str:
        """Extract version from bug body."""
        # Look for "### Version" section
        match = re.search(r'### Version\s*\n+([^\n#]+)', self.body, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return "unknown"

    @property
    def description(self) -> str:
        """Extract description from bug body."""
        match = re.search(r'### Description\s*\n+(.*?)(?=###|\Z)', self.body, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return self.body[:500]


class GitHubClient:
    """Fetch bugs from GitHub using gh CLI."""

    def __init__(self, repo: str):
        self.repo = repo

    def is_available(self) -> bool:
        """Check if gh CLI is available and authenticated."""
        if not shutil.which("gh"):
            return False
        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def fetch_bugs(self, specific_issue: Optional[int] = None) -> list[Bug]:
        """Fetch open bugs from GitHub."""
        try:
            if specific_issue:
                result = subprocess.run(
                    ["gh", "issue", "view", str(specific_issue),
                     "--repo", self.repo,
                     "--json", "number,title,body,url,createdAt,author,labels"],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    print_color(f"Error fetching issue: {result.stderr}", "red")
                    return []
                data = json.loads(result.stdout)
                return [self._parse_bug(data)]
            else:
                result = subprocess.run(
                    ["gh", "issue", "list",
                     "--repo", self.repo,
                     "--state", "open",
                     "--json", "number,title,body,url,createdAt,author,labels",
                     "--limit", "50"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode != 0:
                    print_color(f"Error fetching issues: {result.stderr}", "red")
                    return []
                data = json.loads(result.stdout)
                # Filter to bug reports (have Description and Version sections)
                bugs = []
                for item in data:
                    body = item.get("body", "")
                    if "### Description" in body and "### Version" in body:
                        bugs.append(self._parse_bug(item))
                return bugs
        except subprocess.TimeoutExpired:
            print_color("Timeout fetching issues from GitHub", "red")
            return []
        except json.JSONDecodeError as e:
            print_color(f"Error parsing GitHub response: {e}", "red")
            return []

    def _parse_bug(self, data: dict) -> Bug:
        """Parse a bug from GitHub API response."""
        author = data.get("author", {})
        if isinstance(author, dict):
            author_name = author.get("login", "unknown")
        else:
            author_name = str(author)

        labels = [l.get("name", "") for l in data.get("labels", [])]

        return Bug(
            number=data.get("number", 0),
            title=data.get("title", ""),
            body=data.get("body", ""),
            url=data.get("url", ""),
            author=author_name,
            created_at=data.get("createdAt", "")[:10],
            labels=labels,
        )


class AIRunner:
    """Run AI CLI interactively."""

    PROMPT_TEMPLATE = """I need your help fixing a bug in the Himmelblau project.

## About Himmelblau
Himmelblau is an Azure AD/Entra ID authentication provider for Linux, written in Rust.
Key components:
- src/daemon/ - Main authentication daemon (himmelblaud)
- src/pam/ - PAM module for authentication
- src/nss/ - NSS module for user/group lookup
- src/cli/ - Command-line tools (aad-tool)
- src/broker/ - Authentication broker
- src/common/ - Shared utilities

## Bug Report

**Issue #{number}**: {title}
**URL**: {url}
**Version**: {version}
**Author**: {author}
**Created**: {created_at}

### Description
{description}

### Full Bug Report
{body}

## Your Task

1. First, explore the codebase to understand the relevant code
2. Identify the root cause of the bug
3. Implement a fix
4. Run tests to verify: cargo test

If you cannot fix the bug (too complex, need more info, etc.), explain why and what additional information would help.

Please start by exploring the codebase to understand the issue.
"""

    def __init__(self, provider: str, cli_path: Optional[str] = None):
        self.provider = provider
        self.cli_path = cli_path or provider

    def is_available(self) -> bool:
        """Check if the AI CLI is available."""
        return shutil.which(self.cli_path) is not None

    def create_prompt(self, bug: Bug) -> str:
        """Create the initial prompt for the AI."""
        return self.PROMPT_TEMPLATE.format(
            number=bug.number,
            title=bug.title,
            url=bug.url,
            version=bug.version,
            author=bug.author,
            created_at=bug.created_at,
            description=bug.description,
            body=bug.body,
        )

    def run_interactive(self, bug: Bug) -> bool:
        """Run the AI CLI interactively with bug context."""
        prompt = self.create_prompt(bug)

        print_color(f"\nLaunching {self.provider} CLI to fix issue #{bug.number}...", "green")
        print_color("The AI will start with context about the bug.", "yellow")
        print_color("Use /exit, Ctrl+C, or Ctrl+D to exit when done.\n", "yellow")

        try:
            # Both Claude and Gemini accept an initial prompt as argument
            subprocess.run([self.cli_path, prompt])
            return True
        except KeyboardInterrupt:
            print("\n")
            return True
        except FileNotFoundError:
            print_color(f"Error: {self.provider} CLI not found at '{self.cli_path}'", "red")
            return False
        except Exception as e:
            print_color(f"Error running {self.provider}: {e}", "red")
            return False


def display_bug(bug: Bug):
    """Display a bug summary."""
    print()
    print_color("═" * 70, "cyan")
    print_color(f"Issue #{bug.number}: {bug.title}", "yellow")
    print_color("═" * 70, "cyan")
    print(f"  URL:     {bug.url}")
    print(f"  Author:  {bug.author}")
    print(f"  Created: {bug.created_at}")
    print(f"  Version: {bug.version}")
    if bug.labels:
        print(f"  Labels:  {', '.join(bug.labels)}")
    print()
    print_color("Description:", "blue")

    # Show truncated description
    desc_lines = bug.description.split('\n')
    for line in desc_lines[:15]:
        print(f"  {line}")
    if len(desc_lines) > 15:
        print_color(f"  ... ({len(desc_lines) - 15} more lines)", "yellow")
    print()


def prompt_action() -> str:
    """Prompt user for action on current bug."""
    print_color("What would you like to do?", "cyan")
    print("  [f] Fix this bug with AI")
    print("  [s] Skip to next bug")
    print("  [v] View full issue in browser")
    print("  [q] Quit")
    print()

    try:
        choice = input("Choice [f/s/v/q]: ").strip().lower()
        return choice
    except (KeyboardInterrupt, EOFError):
        return 'q'


def prompt_result() -> str:
    """Prompt user for result after AI session."""
    print()
    print_color("How did it go?", "cyan")
    print("  [c] Fixed - create commit")
    print("  [p] Fixed - already committed, create PR")
    print("  [n] Not fixed - continue to next bug")
    print("  [r] Retry this bug")
    print("  [q] Quit")
    print()

    try:
        choice = input("Result [c/p/n/r/q]: ").strip().lower()
        return choice
    except (KeyboardInterrupt, EOFError):
        return 'q'


def create_branch(bug: Bug) -> Optional[str]:
    """Create a new branch for the fix."""
    default_branch = f"ai-fix/issue-{bug.number}"
    print(f"Enter branch name (or press Enter for '{default_branch}'):")
    try:
        branch_name = input("> ").strip() or default_branch
    except (KeyboardInterrupt, EOFError):
        return None

    # Create and checkout the new branch
    result = subprocess.run(
        ["git", "checkout", "-b", branch_name],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print_color(f"Failed to create branch: {result.stderr}", "red")
        return None

    print_color(f"Created branch: {branch_name}", "green")
    return branch_name


def create_commit(bug: Bug) -> bool:
    """Create a git commit for the fix."""
    print_color("\nCreating commit...", "yellow")

    # Check for changes
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True, text=True
    )
    if not result.stdout.strip():
        print_color("No changes to commit!", "yellow")
        return False

    # Get commit message
    default_msg = f"Fix: {bug.title}\n\nFixes #{bug.number}"
    print(f"Enter commit message (or press Enter for default):")
    print_color(f"Default: {bug.title}", "cyan")

    try:
        custom_msg = input("> ").strip()
    except (KeyboardInterrupt, EOFError):
        return False

    if custom_msg:
        commit_msg = f"{custom_msg}\n\nFixes #{bug.number}"
    else:
        commit_msg = default_msg

    # Stage and commit
    subprocess.run(["git", "add", "-A"])
    result = subprocess.run(
        ["git", "commit", "-m", commit_msg],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        print_color("Commit created successfully!", "green")
        return True
    else:
        print_color(f"Commit failed: {result.stderr}", "red")
        return False


def create_pr(bug: Bug, branch_name: Optional[str] = None) -> bool:
    """Create a PR for the fix."""
    if not branch_name:
        default_branch = f"ai-fix/issue-{bug.number}"
        print(f"Enter branch name (or press Enter for '{default_branch}'):")
        try:
            branch_name = input("> ").strip() or default_branch
        except (KeyboardInterrupt, EOFError):
            return False

    # Check if we need to create and push the branch
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True
    )
    current_branch = result.stdout.strip()

    if current_branch != branch_name:
        # Create new branch
        subprocess.run(["git", "checkout", "-b", branch_name])

    # Push branch
    print_color(f"Pushing branch {branch_name}...", "yellow")
    result = subprocess.run(
        ["git", "push", "-u", "origin", branch_name],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print_color(f"Push failed: {result.stderr}", "red")
        return False

    # Create PR
    print_color("Creating PR...", "yellow")
    result = subprocess.run(
        ["gh", "pr", "create", "--fill", "--head", branch_name],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        print_color(f"PR created: {result.stdout.strip()}", "green")
        return True
    else:
        print_color(f"PR creation failed: {result.stderr}", "red")
        return False


def discard_changes():
    """Discard uncommitted changes."""
    subprocess.run(
        ["git", "checkout", "--", "."],
        capture_output=True
    )


def main():
    parser = argparse.ArgumentParser(
        description="Bug fix assistant using AI CLI tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Interactive bug fixing with Claude
  %(prog)s --ai-provider gemini   # Use Gemini AI instead
  %(prog)s --issue 981            # Fix a specific issue
  %(prog)s --repo owner/repo      # Use a different repository
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
        "--issue",
        type=int,
        default=None,
        help="Process a specific issue only",
    )
    parser.add_argument(
        "--repo",
        type=str,
        default="himmelblau-idm/himmelblau",
        help="GitHub repository (default: himmelblau-idm/himmelblau)",
    )

    args = parser.parse_args()

    # Setup
    print_color("═" * 70, "cyan")
    print_color("  Himmelblau Bug Fix Assistant", "bold")
    print_color("═" * 70, "cyan")
    print()

    # Check prerequisites
    gh_client = GitHubClient(args.repo)
    if not gh_client.is_available():
        print_color("Error: GitHub CLI (gh) is not installed or not authenticated", "red")
        print("Install from: https://cli.github.com/")
        print("Then run: gh auth login")
        sys.exit(1)

    ai_runner = AIRunner(args.ai_provider, args.ai_provider_path)
    if not ai_runner.is_available():
        cli_name = args.ai_provider_path or args.ai_provider
        print_color(f"Error: {args.ai_provider.capitalize()} CLI not found at '{cli_name}'", "red")
        if args.ai_provider == "claude":
            print("Install with: npm install -g @anthropic-ai/claude-code")
        elif args.ai_provider == "gemini":
            print("Install with: npm install -g @anthropic-ai/gemini-cli")
        sys.exit(1)

    print_color(f"Using {args.ai_provider.capitalize()} CLI", "green")
    print()

    # Fetch bugs
    print_color(f"Fetching bugs from {args.repo}...", "blue")
    bugs = gh_client.fetch_bugs(args.issue)

    if not bugs:
        print_color("No open bugs found!", "green")
        sys.exit(0)

    print_color(f"Found {len(bugs)} open bug(s)", "green")

    # Process each bug
    idx = 0
    while idx < len(bugs):
        bug = bugs[idx]
        display_bug(bug)

        action = prompt_action()

        if action == 'f':
            # Run AI to fix the bug
            ai_runner.run_interactive(bug)

            # Ask about result
            result = prompt_result()

            if result == 'c':
                # Create branch first, then commit
                branch_name = create_branch(bug)
                if branch_name and create_commit(bug):
                    try:
                        create_pr_choice = input("Create PR now? [y/N]: ").strip().lower()
                        if create_pr_choice == 'y':
                            create_pr(bug, branch_name)
                    except (KeyboardInterrupt, EOFError):
                        pass
                idx += 1

            elif result == 'p':
                # Create PR from existing branch
                create_pr(bug)
                idx += 1

            elif result == 'n':
                # Not fixed, continue
                discard_changes()
                idx += 1

            elif result == 'r':
                # Retry
                discard_changes()
                # Don't increment idx

            elif result == 'q':
                print_color("\nGoodbye!", "green")
                sys.exit(0)

            else:
                idx += 1

        elif action == 's':
            # Skip
            idx += 1

        elif action == 'v':
            # View in browser
            subprocess.run(["gh", "issue", "view", str(bug.number),
                          "--repo", args.repo, "--web"])
            # Don't increment, show same bug again

        elif action == 'q':
            print_color("\nGoodbye!", "green")
            sys.exit(0)

        else:
            print_color("Invalid choice, please try again.", "yellow")

    print()
    print_color("All bugs processed!", "green")


if __name__ == "__main__":
    main()
