#!/usr/bin/env python3
"""
Detect barely-used Rust dependencies with high transitive cost.

This script analyzes the FULL dependency tree to identify dependencies that:
1. Are used minimally in the source code (few imports)
2. Pull in significant transitive dependencies
3. Are not heavily depended upon by other crates in the tree
4. Could potentially be replaced with lighter alternatives

Usage:
    python3 scripts/check_barely_used_deps.py --format=human
    python3 scripts/check_barely_used_deps.py --format=json --output=report.json
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import tomli
except ImportError:
    try:
        import tomllib as tomli  # Python 3.11+
    except ImportError:
        print("Error: tomli library required. Install with: pip install tomli", file=sys.stderr)
        sys.exit(1)


# Scoring thresholds
SCORE_CRITICAL = 50
SCORE_HIGH = 20
SCORE_MEDIUM = 10

# Lightweight alternatives database
ALTERNATIVES = {
    "reqwest": "Consider ureq or minreq for simple HTTP requests without async",
    "regex": "Consider aho-corasick for simple pattern matching, or manual string operations",
    "clap": "Consider lexopt or pico-args for simple CLI parsing",
    "serde_json": "Consider simd-json for performance, or manual parsing for simple cases",
    "tokio": "Consider async-std or smol for lighter async runtime (if feasible)",
    "chrono": "Consider time crate for lighter datetime handling",
    "uuid": "Consider simple-uuid for lighter UUID generation",
    "log": "Consider tracing (if not already using) or manual logging",
}


class DependencyAnalyzer:
    """Analyzes Rust workspace dependencies for barely-used crates."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.exemptions: Dict[str, str] = {}

        # All dependencies in the tree (not just workspace-defined)
        self.all_deps: Set[str] = set()
        self.workspace_deps: Set[str] = set()

        # Reverse dependency graph: crate -> list of crates that depend on it
        self.reverse_deps: Dict[str, Set[str]] = defaultdict(set)

        # Forward dependency graph: crate -> list of crates it depends on
        self.forward_deps: Dict[str, Set[str]] = defaultdict(set)

        # Metrics
        self.transitive_deps: Dict[str, int] = {}
        self.binary_sizes: Dict[str, float] = {}
        self.import_counts: Dict[str, int] = {}
        self.feature_counts: Dict[str, int] = {}
        self.crates_using: Dict[str, List[str]] = defaultdict(list)
        self.dependency_kinds: Dict[str, str] = {}  # "normal", "build", "dev"

        # Centrality metrics
        self.reverse_dep_counts: Dict[str, int] = {}  # How many crates depend on this
        self.depth_in_tree: Dict[str, int] = {}  # How deep in dependency chain

    def check_tool_availability(self) -> bool:
        """Check if required tools are available, install if needed."""
        tools = {
            "cargo": "cargo is required but not found",
            "rg": "ripgrep (rg) is required. Install with: cargo install ripgrep",
        }

        optional_tools = {
            "cargo-bloat": "cargo install cargo-bloat",
            "cargo-diet": "cargo install cargo-diet",
        }

        # Check required tools
        for tool, error_msg in tools.items():
            if not self._check_command(tool):
                print(f"Error: {error_msg}", file=sys.stderr)
                return False

        # Check and offer to install optional tools
        for tool, install_cmd in optional_tools.items():
            if not self._check_command(tool):
                print(f"Warning: {tool} not found. Installing...", file=sys.stderr)
                try:
                    subprocess.run(
                        install_cmd.split(),
                        check=True,
                        capture_output=True,
                    )
                    print(f"  ✓ Installed {tool}", file=sys.stderr)
                except subprocess.CalledProcessError as e:
                    print(f"  ✗ Failed to install {tool}: {e}", file=sys.stderr)
                    print(f"    You can install manually: {install_cmd}", file=sys.stderr)
                    return False

        return True

    def _check_command(self, cmd: str) -> bool:
        """Check if a command is available."""
        try:
            subprocess.run(
                [cmd, "--version"],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def load_exemptions(self) -> None:
        """Load exemptions from .cargo/barely-used.toml."""
        exemption_file = self.workspace_root / ".cargo" / "barely-used.toml"

        if not exemption_file.exists():
            print(f"Warning: Exemption file not found at {exemption_file}", file=sys.stderr)
            print("  No exemptions will be applied.", file=sys.stderr)
            return

        try:
            with open(exemption_file, "rb") as f:
                data = tomli.load(f)
                self.exemptions = data.get("exemptions", {})
                print(f"Loaded {len(self.exemptions)} exemptions", file=sys.stderr)
        except Exception as e:
            print(f"Error loading exemptions: {e}", file=sys.stderr)

    def collect_all_deps(self) -> None:
        """Collect ALL dependencies in the tree using cargo metadata."""
        print("Building complete dependency graph...", file=sys.stderr)

        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version", "1"],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                check=True,
            )
            metadata = json.loads(result.stdout)

            # Get workspace members
            workspace_members = set(metadata.get("workspace_members", []))

            # Process all packages in the resolve graph
            for package in metadata.get("packages", []):
                pkg_id = package.get("id", "")
                pkg_name = package.get("name", "")

                if not pkg_name:
                    continue

                self.all_deps.add(pkg_name)

                # Mark workspace-defined deps
                if pkg_id in workspace_members:
                    # This is a workspace member, track its dependencies
                    for dep in package.get("dependencies", []):
                        dep_name = dep.get("name")
                        if dep_name:
                            self.workspace_deps.add(dep_name)
                            self.crates_using[dep_name].append(pkg_name)
                            kind = dep.get("kind")
                            if kind:
                                self.dependency_kinds[dep_name] = kind

            # Build dependency graphs from resolve data
            # Use the deps array which has the actual dependency names
            resolve = metadata.get("resolve", {})
            for node in resolve.get("nodes", []):
                node_id = node.get("id", "")
                # Extract package name from ID
                # Format: "registry+https://...#package_name@version" or "path+file://...#package_name@version"
                node_name_match = re.search(r'#([^@]+)@', node_id)
                if not node_name_match:
                    continue
                node_name = node_name_match.group(1)

                # Process dependencies using the "deps" array which has actual names
                for dep_info in node.get("deps", []):
                    dep_name = dep_info.get("name", "")
                    if not dep_name:
                        continue

                    # Normalize dependency name (replace _ with -)
                    dep_name_normalized = dep_name.replace("_", "-")

                    # Build forward and reverse graphs
                    self.forward_deps[node_name].add(dep_name_normalized)
                    self.reverse_deps[dep_name_normalized].add(node_name)

                    # Also track with underscores for compatibility
                    if "_" in dep_name:
                        self.reverse_deps[dep_name].add(node_name)

            print(f"  Found {len(self.all_deps)} total dependencies in tree", file=sys.stderr)
            print(f"  Found {len(self.workspace_deps)} direct workspace dependencies", file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(f"Error collecting dependencies: {e.stderr}", file=sys.stderr)
            sys.exit(1)

    def calculate_reverse_dep_counts(self) -> None:
        """Calculate how many crates depend on each dependency."""
        print("Calculating reverse dependency counts...", file=sys.stderr)

        for dep_name in self.all_deps:
            count = len(self.reverse_deps.get(dep_name, set()))
            self.reverse_dep_counts[dep_name] = count

        print(f"  Calculated reverse dep counts for {len(self.reverse_dep_counts)} crates", file=sys.stderr)

    def collect_transitive_deps(self) -> None:
        """Collect transitive dependency counts using cargo tree."""
        print("Analyzing transitive dependencies...", file=sys.stderr)

        try:
            # Get full dependency tree
            result = subprocess.run(
                ["cargo", "tree", "--edges", "normal", "--prefix", "none"],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                check=True,
            )

            # Count unique dependencies per crate
            tree_lines = result.stdout.strip().split("\n")
            dep_pattern = re.compile(r'^(\S+)')

            for line in tree_lines:
                match = dep_pattern.match(line)
                if match:
                    crate_spec = match.group(1)
                    # Extract crate name (before version)
                    crate_name = crate_spec.split()[0]
                    # Remove version suffix
                    crate_name = re.sub(r' v[\d.]+.*$', '', crate_name)

                    if crate_name in self.transitive_deps:
                        self.transitive_deps[crate_name] += 1
                    else:
                        self.transitive_deps[crate_name] = 1

            print(f"  Analyzed {len(self.transitive_deps)} crates in tree", file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(f"Warning: cargo tree failed: {e.stderr}", file=sys.stderr)

    def collect_binary_sizes(self) -> None:
        """Collect binary size contributions using cargo bloat."""
        print("Analyzing binary sizes (this may take a few minutes)...", file=sys.stderr)

        try:
            # Build in release mode first (cargo bloat requires it)
            print("  Building in release mode...", file=sys.stderr)
            subprocess.run(
                ["cargo", "build", "--release", "--quiet"],
                cwd=self.workspace_root,
                capture_output=True,
                check=True,
            )

            # Run cargo bloat
            result = subprocess.run(
                ["cargo", "bloat", "--release", "--crates", "-n", "200"],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse output
            # Format: "  X.X%   XXX.XKiB   crate_name"
            size_pattern = re.compile(r'\s+([\d.]+)%\s+([\d.]+)([KM])iB\s+(.+)')

            for line in result.stdout.split("\n"):
                match = size_pattern.match(line)
                if match:
                    percent, size_val, unit, crate_name = match.groups()
                    size_kb = float(size_val)
                    if unit == "M":
                        size_kb *= 1024

                    # Clean crate name (remove version info)
                    crate_name = crate_name.strip().split()[0]
                    self.binary_sizes[crate_name] = size_kb

            print(f"  Collected size data for {len(self.binary_sizes)} crates", file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(f"Warning: cargo bloat failed: {e.stderr}", file=sys.stderr)
            print("  Continuing without binary size data...", file=sys.stderr)

    def analyze_source_imports(self) -> None:
        """Analyze source code to count imports per dependency."""
        print("Analyzing source code imports in workspace...", file=sys.stderr)

        try:
            # Use ripgrep to find all use statements in workspace source
            result = subprocess.run(
                ["rg", r"^use\s+(\w+)", "--only-matching", "--no-filename", "src/"],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
            )

            if result.returncode not in (0, 1):  # 1 means no matches, which is ok
                raise subprocess.CalledProcessError(result.returncode, result.args)

            # Count imports
            import_pattern = re.compile(r'use\s+(\w+)')
            for line in result.stdout.split("\n"):
                match = import_pattern.match(line)
                if match:
                    crate_name = match.group(1)
                    # Normalize crate names (replace - with _)
                    normalized = crate_name.replace("_", "-")

                    if normalized in self.import_counts:
                        self.import_counts[normalized] += 1
                    else:
                        self.import_counts[normalized] = 1

                    # Also track underscore version
                    if crate_name in self.import_counts:
                        self.import_counts[crate_name] += 1
                    else:
                        self.import_counts[crate_name] = 1

            print(f"  Found {len(self.import_counts)} crates imported in workspace source", file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(f"Warning: import analysis failed: {e}", file=sys.stderr)

    def collect_feature_counts(self) -> None:
        """Collect feature usage information."""
        print("Analyzing feature usage...", file=sys.stderr)

        try:
            result = subprocess.run(
                ["cargo", "tree", "-e", "features", "--depth", "1"],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse feature tree to count features per crate
            # Format: "crate_name v1.2.3 (features: feat1, feat2, ...)"
            feature_pattern = re.compile(r'(\S+) v[\d.]+ .*features: ([^)]+)')

            for line in result.stdout.split("\n"):
                match = feature_pattern.search(line)
                if match:
                    crate_name, features_str = match.groups()
                    features = [f.strip() for f in features_str.split(",")]
                    self.feature_counts[crate_name] = len(features)

            print(f"  Collected feature data for {len(self.feature_counts)} crates", file=sys.stderr)

        except subprocess.CalledProcessError:
            # Features analysis is optional
            pass

    def calculate_scores(self) -> List[Dict]:
        """Calculate barely-used scores for all dependencies."""
        print("Calculating scores with full dependency graph analysis...", file=sys.stderr)

        results = []

        # Analyze workspace-defined dependencies (the ones we can control)
        # But use reverse dependency data from the ENTIRE tree
        for dep_name in self.workspace_deps:
            # Skip if exempted
            if dep_name in self.exemptions:
                continue

            # Skip build dependencies
            if self.dependency_kinds.get(dep_name) == "build":
                continue

            # Gather metrics
            transitive_count = self.transitive_deps.get(dep_name, 1)
            binary_kb = self.binary_sizes.get(dep_name, 0)

            # Direct imports in workspace source
            direct_import_count = max(
                self.import_counts.get(dep_name, 0),
                self.import_counts.get(dep_name.replace("-", "_"), 0)
            )

            feature_count = self.feature_counts.get(dep_name, 0)

            # Reverse dependency count (how many crates depend on this in the ENTIRE tree)
            reverse_dep_count = self.reverse_dep_counts.get(dep_name, 0)

            # Calculate usage score (how much we use it)
            # Factor in both direct usage in workspace AND how central it is to the dependency graph
            # High reverse dep count means other crates rely on it, so it's well-integrated
            # Weight reverse deps heavily since they indicate usage throughout the tree
            usage_score = (direct_import_count * 10) + (reverse_dep_count * 20)

            if usage_score == 0:
                usage_score = 1  # Avoid division by zero

            # Calculate weight score (cost of having it)
            weight_score = (transitive_count * 5) + (binary_kb / 10) + (feature_count * 2)

            # Calculate barely-used score (higher = more problematic)
            # No centrality penalty - reverse_dep_count already factored into usage_score
            barely_used_score = (weight_score / max(usage_score, 1)) * 10

            # Categorize
            if barely_used_score > SCORE_CRITICAL:
                category = "critical"
            elif barely_used_score > SCORE_HIGH:
                category = "high"
            elif barely_used_score > SCORE_MEDIUM:
                category = "medium"
            else:
                category = "low"

            # Get suggestion if available
            suggestion = ALTERNATIVES.get(dep_name, "Review usage and consider lighter alternatives")

            # Build list of what depends on this crate
            depended_by = list(self.reverse_deps.get(dep_name, set()))[:5]  # Top 5

            results.append({
                "crate": dep_name,
                "score": round(barely_used_score, 1),
                "category": category,
                "usage": {
                    "workspace_imports": direct_import_count,
                    "reverse_deps": reverse_dep_count,
                    "depended_by": depended_by,
                    "crates_using": self.crates_using.get(dep_name, []),
                },
                "cost": {
                    "transitive_deps": transitive_count,
                    "binary_kb": round(binary_kb, 1),
                    "features": feature_count,
                },
                "suggestion": suggestion,
            })

        # Sort by score (descending)
        results.sort(key=lambda x: x["score"], reverse=True)

        print(f"  Calculated scores for {len(results)} dependencies", file=sys.stderr)
        return results

    def generate_human_report(self, results: List[Dict]) -> str:
        """Generate human-readable report."""
        lines = []
        lines.append("=" * 80)
        lines.append("Barely-Used Dependency Report (Full Tree Analysis)")
        lines.append("=" * 80)
        lines.append("")

        # Group by category
        by_category = defaultdict(list)
        for result in results:
            by_category[result["category"]].append(result)

        # Critical
        if by_category["critical"]:
            lines.append(f"CRITICAL (score > {SCORE_CRITICAL}):")
            for r in by_category["critical"]:
                lines.append(f"  - {r['crate']} (score: {r['score']})")
                lines.append(f"    Workspace imports: {r['usage']['workspace_imports']}")
                lines.append(f"    Reverse dependencies: {r['usage']['reverse_deps']} crates depend on this")
                if r['usage']['depended_by']:
                    lines.append(f"    Depended by: {', '.join(r['usage']['depended_by'])}")
                lines.append(f"    Cost: {r['cost']['transitive_deps']} transitive deps, "
                           f"{r['cost']['binary_kb']} KB binary, "
                           f"{r['cost']['features']} features")
                lines.append(f"    Suggestion: {r['suggestion']}")
                lines.append("")

        # High
        if by_category["high"]:
            lines.append(f"HIGH (score > {SCORE_HIGH}):")
            for r in by_category["high"]:
                lines.append(f"  - {r['crate']} (score: {r['score']})")
                lines.append(f"    Workspace imports: {r['usage']['workspace_imports']}, "
                           f"Reverse deps: {r['usage']['reverse_deps']}")
                if r['usage']['depended_by']:
                    lines.append(f"    Depended by: {', '.join(r['usage']['depended_by'][:3])}")
                lines.append(f"    Cost: {r['cost']['transitive_deps']} transitive deps, "
                           f"{r['cost']['binary_kb']} KB")
                lines.append(f"    Suggestion: {r['suggestion']}")
                lines.append("")

        # Medium
        if by_category["medium"]:
            lines.append(f"MEDIUM (score > {SCORE_MEDIUM}):")
            for r in by_category["medium"]:
                lines.append(f"  - {r['crate']} (score: {r['score']})")
                lines.append(f"    Workspace imports: {r['usage']['workspace_imports']}, "
                           f"Reverse deps: {r['usage']['reverse_deps']}, "
                           f"{r['cost']['transitive_deps']} transitive deps")
                lines.append("")

        # Exempted
        if self.exemptions:
            lines.append("")
            lines.append("EXEMPTED:")
            for crate, reason in sorted(self.exemptions.items()):
                lines.append(f"  - {crate}: {reason}")
            lines.append("")

        # Summary
        lines.append("=" * 80)
        flagged = len([r for r in results if r["category"] in ("critical", "high", "medium")])
        lines.append(f"Total dependencies in tree: {len(self.all_deps)}")
        lines.append(f"Workspace-defined dependencies: {len(self.workspace_deps)}")
        lines.append(f"Analyzed for barely-used: {len(results)}")
        lines.append(f"Flagged as barely-used: {flagged}")
        lines.append(f"Exempted: {len(self.exemptions)}")
        lines.append("=" * 80)
        lines.append("")
        lines.append("Note: This analysis examines the ENTIRE dependency tree,")
        lines.append("accounting for usage both in workspace source AND within dependencies.")
        lines.append("A low 'reverse deps' count indicates few other crates depend on it.")

        return "\n".join(lines)

    def generate_json_report(self, results: List[Dict]) -> Dict:
        """Generate JSON report."""
        # Group by category
        by_category = defaultdict(list)
        for result in results:
            by_category[result["category"]].append(result)

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_deps_in_tree": len(self.all_deps),
            "workspace_defined_deps": len(self.workspace_deps),
            "analyzed": len(results),
            "flagged_count": len([r for r in results if r["category"] in ("critical", "high", "medium")]),
            "exempted_count": len(self.exemptions),
            "categories": {
                "critical": by_category.get("critical", []),
                "high": by_category.get("high", []),
                "medium": by_category.get("medium", []),
                "low": by_category.get("low", []),
            },
            "exempted": [
                {"crate": crate, "reason": reason}
                for crate, reason in sorted(self.exemptions.items())
            ],
        }


def main():
    parser = argparse.ArgumentParser(
        description="Detect barely-used Rust dependencies with high transitive cost"
    )
    parser.add_argument(
        "--format",
        choices=["human", "json"],
        default="human",
        help="Output format (default: human)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd(),
        help="Workspace root directory (default: current directory)",
    )

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = DependencyAnalyzer(args.workspace)

    # Check tools
    if not analyzer.check_tool_availability():
        sys.exit(1)

    # Load exemptions
    analyzer.load_exemptions()

    # Collect data - now analyzing the FULL dependency tree
    analyzer.collect_all_deps()
    analyzer.calculate_reverse_dep_counts()
    analyzer.collect_transitive_deps()
    analyzer.collect_binary_sizes()
    analyzer.analyze_source_imports()
    analyzer.collect_feature_counts()

    # Calculate scores with full graph analysis
    results = analyzer.calculate_scores()

    # Generate report
    if args.format == "human":
        report = analyzer.generate_human_report(results)
        if args.output:
            args.output.write_text(report)
        else:
            print(report)
    else:  # json
        report = analyzer.generate_json_report(results)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
        else:
            print(json.dumps(report, indent=2))

    # Exit with code indicating if issues were found
    flagged = len([r for r in results if r["category"] in ("critical", "high")])
    sys.exit(0 if flagged == 0 else 1)


if __name__ == "__main__":
    main()
