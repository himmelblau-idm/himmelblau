#!/usr/bin/env python3
"""
Automated dependency cleanup script for Himmelblau workspace.

This script systematically tests ALL dependencies in the cargo tree (direct,
transitive, and descendants) to identify which crates can be safely masked
without breaking the build.

For each dependency, it:
1. Masks the dependency using gen_mask_shim.py
2. Runs `cargo build --all-features --workspace`
3. If build succeeds: keeps the mask and commits (dependency was unused)
4. If build fails: reverts the mask (dependency is needed)

Usage:
    # Dry run (no commits)
    ./scripts/auto_cleanup_deps.py --dry-run --limit 3

    # Interactive mode
    ./scripts/auto_cleanup_deps.py --interactive --limit 5

    # Full run
    ./scripts/auto_cleanup_deps.py

    # Resume from previous run
    ./scripts/auto_cleanup_deps.py --resume
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List

# Import GitClient from backport.py
sys.path.insert(0, str(Path(__file__).parent))
from backport import GitClient


@dataclass
class Dependency:
    """Represents an external dependency."""
    name: str
    version: str

    def __str__(self):
        return f"{self.name}:{self.version}"

    def key(self):
        """Return the key for comparison (name:version)."""
        return f"{self.name}:{self.version}"


@dataclass
class BuildResult:
    """Result of a cargo build attempt."""
    success: bool
    duration: float
    error: str = ""


@dataclass
class MaskResult:
    """Result of a mask operation."""
    success: bool
    error: str = ""


class DependencyExtractor:
    """Extracts all external dependencies from cargo metadata."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root

    def extract_all_dependencies(self) -> List[Dependency]:
        """
        Extract ALL dependencies from cargo tree (direct + transitive + descendants).

        Returns list of external dependencies from crates.io registry.
        Excludes workspace members (source=null).
        """
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version", "1"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=120,
                check=True
            )

            metadata = json.loads(result.stdout)
            dependencies = []

            for package in metadata.get("packages", []):
                # Only include external dependencies (source is not null)
                # Workspace members have source=null
                source = package.get("source")
                if source and "registry" in source:
                    dependencies.append(Dependency(
                        name=package["name"],
                        version=package["version"]
                    ))

            return dependencies

        except subprocess.TimeoutExpired:
            print("ERROR: cargo metadata timed out after 120s", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: cargo metadata failed: {e.stderr}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse cargo metadata JSON: {e}", file=sys.stderr)
            sys.exit(1)

    def get_already_masked(self) -> set[str]:
        """
        Read [replace] section from Cargo.toml to find already-masked dependencies.

        Returns set of "crate:version" strings.
        """
        cargo_toml = self.repo_root / "Cargo.toml"
        if not cargo_toml.exists():
            return set()

        masked = set()
        in_replace_section = False

        with open(cargo_toml) as f:
            for line in f:
                stripped = line.strip()

                # Track [replace] section
                if stripped == "[replace]":
                    in_replace_section = True
                    continue
                elif stripped.startswith("[") and in_replace_section:
                    # Exited [replace] section
                    break

                # Parse entries like: "crate:version" = { path = "..." }
                if in_replace_section and stripped.startswith('"'):
                    # Extract "crate:version" part
                    end_quote = stripped.find('"', 1)
                    if end_quote > 0:
                        masked.add(stripped[1:end_quote])

        return masked


class MaskManager:
    """Manages mask creation and reversion using gen_mask_shim.py."""

    def __init__(self, repo_root: Path, dry_run: bool = False):
        self.repo_root = repo_root
        self.dry_run = dry_run
        self.gen_mask_script = repo_root / "scripts" / "gen_mask_shim.py"

    def apply_mask(self, dep: Dependency) -> MaskResult:
        """
        Apply a mask to the given dependency using gen_mask_shim.py.

        Returns MaskResult indicating success/failure.
        """
        if self.dry_run:
            print(f"  [DRY-RUN] Would mask {dep}")
            return MaskResult(success=True)

        try:
            # First attempt with auto-features
            subprocess.run(
                [
                    str(self.gen_mask_script),
                    "--crate-name", dep.name,
                    "--managed-version", dep.version
                ],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=60,
                check=True
            )
            return MaskResult(success=True)

        except subprocess.CalledProcessError as e:
            # Check if it's a network error, retry with --no-auto-features
            if "network" in e.stderr.lower() or "timeout" in e.stderr.lower():
                try:
                    subprocess.run(
                        [
                            str(self.gen_mask_script),
                            "--crate-name", dep.name,
                            "--managed-version", dep.version,
                            "--no-auto-features"
                        ],
                        cwd=self.repo_root,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=True
                    )
                    return MaskResult(success=True)
                except subprocess.CalledProcessError as e2:
                    return MaskResult(success=False, error=e2.stderr)

            return MaskResult(success=False, error=e.stderr)

        except subprocess.TimeoutExpired:
            return MaskResult(success=False, error="gen_mask_shim.py timed out")

    def revert_mask(self, dep: Dependency) -> None:
        """
        Revert a mask by removing the override directory and restoring Cargo files.
        """
        if self.dry_run:
            print(f"  [DRY-RUN] Would revert mask for {dep}")
            return

        # Remove override directory
        override_dir = self.repo_root / "src" / "overrides" / dep.name / dep.version
        if override_dir.exists():
            shutil.rmtree(override_dir)

        # Restore Cargo.toml and Cargo.lock using git
        subprocess.run(
            ["git", "restore", "Cargo.toml", "Cargo.lock"],
            cwd=self.repo_root,
            check=True
        )


class BuildValidator:
    """Validates that the build still works after masking."""

    def __init__(self, repo_root: Path, log_file: Path):
        self.repo_root = repo_root
        self.log_file = log_file

        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def validate_build(self) -> BuildResult:
        """
        Run cargo build --all-features --workspace.

        Returns BuildResult with success status and duration.
        """
        start_time = time.time()

        try:
            result = subprocess.run(
                ["cargo", "build", "--all-features", "--workspace"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                check=True
            )

            duration = time.time() - start_time

            # Log build output
            with open(self.log_file, "a") as f:
                f.write(f"\n=== BUILD SUCCESS ({duration:.1f}s) ===\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write(result.stderr)

            return BuildResult(success=True, duration=duration)

        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time

            with open(self.log_file, "a") as f:
                f.write(f"\n=== BUILD TIMEOUT ({duration:.1f}s) ===\n")
                if e.stdout:
                    f.write(e.stdout.decode() if isinstance(e.stdout, bytes) else e.stdout)
                if e.stderr:
                    f.write(e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr)

            return BuildResult(success=False, duration=duration, error="Build timed out")

        except subprocess.CalledProcessError as e:
            duration = time.time() - start_time

            with open(self.log_file, "a") as f:
                f.write(f"\n=== BUILD FAILED ({duration:.1f}s) ===\n")
                f.write(e.stdout)
                if e.stderr:
                    f.write(e.stderr)

            return BuildResult(success=False, duration=duration, error="Build failed")


class GitOperations:
    """Manages git operations for committing masks."""

    def __init__(self, repo_root: Path, dry_run: bool = False):
        self.git = GitClient(repo_root)
        self.repo_root = repo_root
        self.dry_run = dry_run

    def add_cargo_vet_policy(self, dep: Dependency) -> None:
        """
        Add a policy entry to supply-chain/config.toml for the masked dependency.

        Inserts the entry in alphabetical order among other [policy.*] entries.
        """
        if self.dry_run:
            return

        config_file = self.repo_root / "supply-chain" / "config.toml"
        if not config_file.exists():
            print(f"  WARNING: {config_file} not found, skipping cargo-vet policy")
            return

        with open(config_file) as f:
            lines = f.readlines()

        # Find the [policy.*] section and determine where to insert
        policy_lines = []
        insert_idx = None
        in_policy_section = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect policy section entries
            if stripped.startswith('[policy.'):
                in_policy_section = True
                policy_lines.append((i, stripped))
            elif in_policy_section and (stripped.startswith('[[') or (stripped.startswith('[') and not stripped.startswith('[policy.'))):
                # Exited policy section (found exemptions or other section)
                insert_idx = i
                break

        if insert_idx is None:
            # Didn't find the end, append before exemptions (search for [[exemptions)
            for i, line in enumerate(lines):
                if line.strip().startswith('[[exemptions'):
                    insert_idx = i
                    break

        # Create the new policy entry
        new_entry = f'[policy."{dep.name}:{dep.version}"]\naudit-as-crates-io = true\n\n'

        # Find the correct insertion point (alphabetically)
        target_key = f'[policy."{dep.name}:{dep.version}"]'
        insert_at = insert_idx  # Default to end of policy section

        for idx, policy_line in policy_lines:
            if policy_line > target_key:
                insert_at = idx
                break

        # Insert the new entry
        lines.insert(insert_at, new_entry)

        # Write back
        with open(config_file, 'w') as f:
            f.writelines(lines)

    def commit_mask(self, dep: Dependency) -> None:
        """
        Commit the masked dependency with a descriptive message.
        """
        if self.dry_run:
            print(f"  [DRY-RUN] Would commit {dep}")
            return

        # Add cargo-vet policy entry
        self.add_cargo_vet_policy(dep)

        # Run cargo vet to reformat supply-chain/config.toml
        # Ignore exit code and output - we just want it to reformat the file
        try:
            subprocess.run(
                ["cargo", "vet"],
                cwd=self.repo_root,
                capture_output=True,
                timeout=60,
                check=False  # Don't raise on non-zero exit
            )
        except subprocess.TimeoutExpired:
            # If cargo vet times out, continue anyway
            pass

        # Stage all relevant files:
        # - override directory
        # - Cargo.toml (updated [replace] section)
        # - Cargo.lock (updated after masking)
        # - supply-chain/config.toml (new policy entry, reformatted by cargo vet)
        override_dir = f"src/overrides/{dep.name}/{dep.version}"
        self.git.run("add", override_dir, "Cargo.toml", "Cargo.lock", "supply-chain/config.toml")

        # Create commit message
        message = f"""Remove unused dependency: {dep}

Automated cleanup via auto_cleanup_deps.py
This dependency was not required by cargo build --all-features

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"""

        # Commit
        self.git.run("commit", "-m", message, "--signoff")

    def check_clean_state(self) -> bool:
        """
        Check if working directory is clean.

        Ignores untracked files (especially .claude/ working directory).
        Only checks for modified, staged, or deleted files.
        """
        result = self.git.run("status", "--porcelain")

        # Parse porcelain output - ignore untracked files (?? prefix)
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            # Untracked files start with '??'
            if not line.startswith('??'):
                # Found a modified/staged/deleted file
                return False

        return True


class StateManager:
    """Manages persistent state for resume capability."""

    def __init__(self, state_file: Path):
        self.state_file = state_file
        self.state = self._load_state()

    def _load_state(self) -> dict:
        """Load state from JSON file."""
        if self.state_file.exists():
            with open(self.state_file) as f:
                return json.load(f)
        else:
            return {
                "processed": [],
                "stats": {"removed": 0, "kept": 0, "errors": 0},
                "last_updated": None
            }

    def save_progress(self) -> None:
        """Save current state to JSON file."""
        self.state["last_updated"] = datetime.now().isoformat()

        # Ensure directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)

    def mark_completed(self, dep: Dependency, result: str) -> None:
        """
        Mark a dependency as processed with the given result.

        result: "removed", "kept", or "error"
        """
        self.state["processed"].append([dep.name, dep.version, result])
        self.state["stats"][result] = self.state["stats"].get(result, 0) + 1
        self.save_progress()

    def is_processed(self, dep: Dependency) -> bool:
        """Check if a dependency has already been processed."""
        return any(
            p[0] == dep.name and p[1] == dep.version
            for p in self.state["processed"]
        )

    def get_stats(self) -> dict:
        """Get current statistics."""
        return self.state["stats"]


class CleanupOrchestrator:
    """Main orchestrator for the cleanup process."""

    def __init__(self, args):
        self.args = args
        self.repo_root = Path.cwd()

        # Initialize components
        self.extractor = DependencyExtractor(self.repo_root)
        self.mask_manager = MaskManager(self.repo_root, dry_run=args.dry_run)
        self.build_validator = BuildValidator(
            self.repo_root,
            self.repo_root / ".claude" / "auto_cleanup_deps.log"
        )
        self.git_ops = GitOperations(self.repo_root, dry_run=args.dry_run)
        self.state_manager = StateManager(
            self.repo_root / ".claude" / "auto_cleanup_state.json"
        )

    def run(self) -> None:
        """Main execution loop."""

        # Check git state
        if not self.args.dry_run and not self.git_ops.check_clean_state():
            print("ERROR: Working directory is not clean. Please commit or stash changes.", file=sys.stderr)
            sys.exit(1)

        # Extract all dependencies
        print("Extracting dependencies from cargo metadata...")
        all_deps = self.extractor.extract_all_dependencies()
        print(f"Found {len(all_deps)} total dependencies in cargo tree")

        # Filter out already-masked dependencies
        already_masked = self.extractor.get_already_masked()
        print(f"Already masked: {len(already_masked)} dependencies")

        dependencies = [
            dep for dep in all_deps
            if dep.key() not in already_masked
        ]
        print(f"Remaining to test: {len(dependencies)} dependencies")

        # Filter out already-processed (for resume)
        if self.args.resume:
            dependencies = [
                dep for dep in dependencies
                if not self.state_manager.is_processed(dep)
            ]
            print(f"After resume filter: {len(dependencies)} dependencies")

        # Apply limit if specified
        if self.args.limit:
            dependencies = dependencies[:self.args.limit]
            print(f"Limited to first {len(dependencies)} dependencies")

        # List mode
        if self.args.list:
            print("\nDependencies to test:")
            for i, dep in enumerate(dependencies, 1):
                print(f"  {i}. {dep}")
            return

        # Process each dependency
        total = len(dependencies)
        for i, dep in enumerate(dependencies, 1):
            print(f"\n[{i}/{total}] Testing {dep}...")

            # Apply mask
            mask_result = self.mask_manager.apply_mask(dep)
            if not mask_result.success:
                print(f"  ✗ ERROR masking: {mask_result.error}")
                self.state_manager.mark_completed(dep, "error")
                continue

            # Validate build (skip in dry-run)
            if self.args.dry_run:
                print(f"  [DRY-RUN] Would test build")
                continue

            build_result = self.build_validator.validate_build()

            if build_result.success:
                # Build succeeded → dependency unused → keep mask + commit
                print(f"  ✓ REMOVED (build succeeded in {build_result.duration:.1f}s)")

                if self.args.interactive:
                    response = input(f"    Commit removal of {dep}? [Y/n] ")
                    if response.lower() == 'n':
                        print("    Skipping commit, reverting mask...")
                        self.mask_manager.revert_mask(dep)
                        self.state_manager.mark_completed(dep, "kept")
                        continue

                self.git_ops.commit_mask(dep)
                self.state_manager.mark_completed(dep, "removed")

            else:
                # Build failed → dependency needed → revert mask
                print(f"  ✗ KEPT (build failed in {build_result.duration:.1f}s)")
                self.mask_manager.revert_mask(dep)
                self.state_manager.mark_completed(dep, "kept")

        # Print final summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        stats = self.state_manager.get_stats()
        print(f"Removed: {stats.get('removed', 0)}")
        print(f"Kept:    {stats.get('kept', 0)}")
        print(f"Errors:  {stats.get('errors', 0)}")
        print(f"Total:   {sum(stats.values())}")

        if self.args.dry_run:
            print("\n(DRY RUN - no actual changes made)")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Automated dependency cleanup for Himmelblau workspace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run with 3 dependencies
  %(prog)s --dry-run --limit 3

  # Interactive mode with 5 dependencies
  %(prog)s --interactive --limit 5

  # Full run
  %(prog)s

  # Resume from previous run
  %(prog)s --resume
        """
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test without making actual changes (no commits)"
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt before each commit"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List dependencies that would be tested and exit"
    )

    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Test only first N dependencies (for testing)"
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from previous run (skip already-processed deps)"
    )

    parser.add_argument(
        "--ignore-exemptions",
        action="store_true",
        help="Ignore exemptions from .cargo/barely-used.toml"
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    orchestrator = CleanupOrchestrator(args)
    orchestrator.run()


if __name__ == "__main__":
    main()
