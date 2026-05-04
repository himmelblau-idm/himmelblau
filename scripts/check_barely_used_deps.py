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
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
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

# Standard library replacements for shallow usage analysis
STDLIB_REPLACEMENTS = {
    "lazy_static": ("std::sync::OnceLock or LazyLock", "Rust 1.70+"),
    "once_cell": ("std::sync::OnceLock", "Rust 1.70+"),
}


class ReplacementStrategy(Enum):
    """Replacement strategy for barely-used dependencies."""
    STDLIB = "stdlib"
    VENDOR = "vendor"
    WRAPPER = "wrapper"
    ELIMINATE = "eliminate"
    KEEP = "keep"
    UNKNOWN = "unknown"


@dataclass
class SymbolImport:
    """Represents a single symbol import from a dependency."""
    crate_name: str
    symbol: str
    import_type: str  # "macro", "function", "type", "unknown"
    file_path: str
    line_number: int
    is_glob: bool


@dataclass
class UsageBreadth:
    """Metrics for how much of a dependency's API we use."""
    unique_symbols: Set[str]
    import_sites: int
    usage_sites: int
    glob_imports: int


@dataclass
class ReplacementSuggestion:
    """Suggestion for replacing a dependency."""
    strategy: ReplacementStrategy
    confidence: str
    rationale: str
    alternative: Optional[str]
    effort: str
    symbols_to_replace: List[str]


class DependencyAnalyzer:
    """Analyzes Rust workspace dependencies for barely-used crates."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.exemptions: Dict[str, str] = {}
        self.shallow_exemptions: Dict[str, str] = {}

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

        # Shallow usage analysis (NEW)
        self.symbol_imports: Dict[str, List[SymbolImport]] = defaultdict(list)
        self.usage_breadth: Dict[str, UsageBreadth] = {}

        # Duplicate version tracking (NEW)
        self.package_versions: Dict[str, List[Dict]] = defaultdict(list)

        # Replace directive tracking for managed duplicates
        self.replace_directives: Dict[str, Dict[str, str]] = {}

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
                self.shallow_exemptions = data.get("shallow-exemptions", {})
                print(f"Loaded {len(self.exemptions)} exemptions, {len(self.shallow_exemptions)} shallow exemptions", file=sys.stderr)
        except Exception as e:
            print(f"Error loading exemptions: {e}", file=sys.stderr)

    def parse_replace_section(self) -> None:
        """Parse [replace] section from root Cargo.toml to identify managed duplicates."""
        print("Parsing [replace] section from Cargo.toml...", file=sys.stderr)

        cargo_toml_path = self.workspace_root / "Cargo.toml"

        if not cargo_toml_path.exists():
            print(f"  Warning: Cargo.toml not found at {cargo_toml_path}", file=sys.stderr)
            return

        try:
            with open(cargo_toml_path, "rb") as f:
                data = tomli.load(f)
                replace_section = data.get("replace", {})

                if not replace_section:
                    print("  No [replace] section found", file=sys.stderr)
                    return

                # Parse each replace directive
                for key, value in replace_section.items():
                    # Key format: "crate_name:version"
                    if ':' not in key:
                        print(f"  Warning: Invalid replace key format: {key}", file=sys.stderr)
                        continue

                    crate_name, version = key.rsplit(':', 1)
                    override_path = value.get('path') if isinstance(value, dict) else None

                    if not override_path:
                        print(f"  Warning: No path specified for {key}", file=sys.stderr)
                        continue

                    # Store in nested dict
                    if crate_name not in self.replace_directives:
                        self.replace_directives[crate_name] = {}

                    self.replace_directives[crate_name][version] = override_path

                print(f"  Found {len(replace_section)} replace directives", file=sys.stderr)

                # Validate that override paths exist
                self._validate_override_paths()

        except Exception as e:
            print(f"  Error parsing [replace] section: {e}", file=sys.stderr)

    def _validate_override_paths(self) -> None:
        """Validate that override paths actually exist."""
        missing_paths = []

        for crate_name, versions in self.replace_directives.items():
            for version, path in versions.items():
                full_path = self.workspace_root / path
                if not full_path.exists():
                    missing_paths.append(f"{crate_name}:{version} -> {path}")

        if missing_paths:
            print("  Warning: Missing override paths:", file=sys.stderr)
            for missing in missing_paths:
                print(f"    {missing}", file=sys.stderr)

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

                # Extract version information for duplicate detection
                # Package ID format: "registry+https://...#package_name@version"
                version_match = re.search(r'#([^@]+)@([^"\s]+)', pkg_id)
                if version_match:
                    version = version_match.group(2)
                    self.package_versions[pkg_name].append({
                        "version": version,
                        "pkg_id": pkg_id
                    })

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

    def collect_binary_sizes(self, timeout: Optional[int] = 600) -> None:
        """Collect binary size contributions using cargo bloat.

        Args:
            timeout: Timeout in seconds for build and bloat operations (default: 600s = 10min)
        """
        print("Analyzing binary sizes (this may take a few minutes)...", file=sys.stderr)

        try:
            # Build in release mode first (cargo bloat requires it)
            print("  Building in release mode...", file=sys.stderr)
            subprocess.run(
                ["cargo", "build", "--release", "--quiet"],
                cwd=self.workspace_root,
                capture_output=True,
                check=True,
                timeout=timeout,
            )

            # Run cargo bloat
            result = subprocess.run(
                ["cargo", "bloat", "--release", "--crates", "-n", "200"],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                check=True,
                timeout=60,  # Bloat itself should be fast once build is done
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

        except subprocess.TimeoutExpired:
            print("Warning: Binary size analysis timed out, skipping", file=sys.stderr)
            print("  Continuing without binary size data...", file=sys.stderr)
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

    def analyze_symbol_imports(self) -> None:
        """Analyze which specific symbols are imported from each dependency."""
        print("Analyzing symbol-level imports...", file=sys.stderr)

        patterns = {
            # use foo::{Bar, Baz, qux};
            'grouped': r'^use\s+(\w+)::\{([^}]+)\}',

            # use foo::Bar;
            'type': r'^use\s+(\w+)::([A-Z]\w+)',

            # use foo::bar;
            'function': r'^use\s+(\w+)::([a-z_]\w+)',

            # use foo::*;
            'glob': r'^use\s+(\w+)::\*',

            # use foo::bar as baz;
            'renamed': r'^use\s+(\w+)::(\w+)\s+as\s+',
        }

        for pattern_name, pattern in patterns.items():
            try:
                result = subprocess.run(
                    ["rg", pattern, "--only-matching", "--with-filename",
                     "--line-number", "src/"],
                    cwd=self.workspace_root,
                    capture_output=True,
                    text=True,
                )

                if result.returncode in (0, 1):  # 0 = found, 1 = not found
                    self._parse_symbol_imports(result.stdout, pattern_name)

            except subprocess.CalledProcessError as e:
                print(f"Warning: pattern '{pattern_name}' failed: {e}", file=sys.stderr)

        print(f"  Found {sum(len(v) for v in self.symbol_imports.values())} symbol imports", file=sys.stderr)

    def _parse_symbol_imports(self, rg_output: str, pattern_type: str) -> None:
        """Parse ripgrep output to extract symbol imports."""
        for line in rg_output.split("\n"):
            if not line.strip():
                continue

            # Parse: "src/path/file.rs:123:use foo::Bar;"
            match = re.match(r'([^:]+):(\d+):(.*)', line)
            if not match:
                continue

            file_path, line_num, import_stmt = match.groups()

            if pattern_type == 'grouped':
                # Parse: use foo::{Bar, Baz, qux};
                crate_match = re.search(r'use\s+(\w+)::\{([^}]+)\}', import_stmt)
                if crate_match:
                    crate_name = crate_match.group(1)
                    symbols_str = crate_match.group(2)
                    symbols = [s.strip().split(' as ')[0] for s in symbols_str.split(',')]

                    for symbol in symbols:
                        self.symbol_imports[crate_name].append(SymbolImport(
                            crate_name=crate_name,
                            symbol=symbol,
                            import_type=self._infer_symbol_type(symbol),
                            file_path=file_path,
                            line_number=int(line_num),
                            is_glob=False,
                        ))

            elif pattern_type == 'glob':
                # Parse: use foo::*;
                crate_match = re.search(r'use\s+(\w+)::\*', import_stmt)
                if crate_match:
                    crate_name = crate_match.group(1)
                    self.symbol_imports[crate_name].append(SymbolImport(
                        crate_name=crate_name,
                        symbol="*",
                        import_type="glob",
                        file_path=file_path,
                        line_number=int(line_num),
                        is_glob=True,
                    ))

            elif pattern_type in ('type', 'function', 'renamed'):
                # Parse: use foo::Bar; or use foo::bar; or use foo::bar as baz;
                crate_match = re.search(r'use\s+(\w+)::(\w+)', import_stmt)
                if crate_match:
                    crate_name = crate_match.group(1)
                    symbol = crate_match.group(2)
                    self.symbol_imports[crate_name].append(SymbolImport(
                        crate_name=crate_name,
                        symbol=symbol,
                        import_type=self._infer_symbol_type(symbol),
                        file_path=file_path,
                        line_number=int(line_num),
                        is_glob=False,
                    ))

    def _infer_symbol_type(self, symbol: str) -> str:
        """Infer symbol type from naming convention."""
        if symbol.endswith('!'):
            return "macro"
        elif symbol[0].isupper():
            return "type"
        elif symbol[0].islower():
            return "function"
        else:
            return "unknown"

    def calculate_usage_breadth(self) -> None:
        """Calculate how much of each dependency's API we actually use."""
        print("Calculating usage breadth metrics...", file=sys.stderr)

        for dep_name in self.workspace_deps:
            # Normalize hyphenated crate names to underscores for lookup
            # (Cargo.toml uses hyphens, Rust imports use underscores)
            normalized_dep_name = dep_name.replace("-", "_")
            symbol_list = self.symbol_imports.get(normalized_dep_name, [])

            # Unique symbols (exclude globs)
            unique_symbols = {s.symbol for s in symbol_list if not s.is_glob}

            # Import sites (unique file:line pairs)
            import_sites = len({(s.file_path, s.line_number) for s in symbol_list})

            # Usage sites (count actual usage in code)
            usage_sites = self._count_usage_sites(dep_name, unique_symbols)

            # Glob imports (penalty indicator)
            glob_imports = sum(1 for s in symbol_list if s.is_glob)

            self.usage_breadth[dep_name] = UsageBreadth(
                unique_symbols=unique_symbols,
                import_sites=import_sites,
                usage_sites=usage_sites,
                glob_imports=glob_imports,
            )

        print(f"  Calculated breadth for {len(self.usage_breadth)} dependencies", file=sys.stderr)

    def _count_usage_sites(self, crate_name: str, symbols: Set[str]) -> int:
        """Count how many times symbols are actually used in code."""
        if not symbols or '*' in symbols:
            return 0

        total_count = 0
        crate_patterns = [crate_name, crate_name.replace("-", "_")]

        for symbol in symbols:
            # Search for direct symbol usage
            for pattern in crate_patterns:
                try:
                    result = subprocess.run(
                        ["rg", f"{pattern}::{symbol}", "--count", "src/"],
                        cwd=self.workspace_root,
                        capture_output=True,
                        text=True,
                    )

                    if result.returncode == 0:
                        for line in result.stdout.split("\n"):
                            if ":" in line:
                                try:
                                    total_count += int(line.split(":")[-1].strip())
                                except ValueError:
                                    # Skip malformed lines from rg --count output
                                    pass
                except subprocess.CalledProcessError:
                    # Pattern not found or grep failed - continue with best-effort counting
                    pass

            # Also count direct symbol usage (for imported symbols)
            try:
                result = subprocess.run(
                    ["rg", rf"\b{symbol}\b", "--count", "src/"],
                    cwd=self.workspace_root,
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if ":" in line:
                            try:
                                total_count += int(line.split(":")[-1].strip())
                            except ValueError:
                                # Skip malformed lines from rg --count output
                                pass
            except subprocess.CalledProcessError:
                # Pattern not found or grep failed - continue with best-effort counting
                pass

        return total_count

    def calculate_shallow_usage_score(self, breadth: UsageBreadth) -> float:
        """Calculate shallow usage score (higher = shallower usage = better candidate)."""
        unique_count = len(breadth.unique_symbols)

        # Base score (inverse of unique symbols)
        if unique_count == 0:
            return 100.0
        elif unique_count == 1:
            base_score = 50.0  # CRITICAL: single symbol
        elif unique_count <= 3:
            base_score = 30.0  # HIGH: vendorable
        elif unique_count <= 5:
            base_score = 15.0  # MEDIUM
        elif unique_count <= 10:
            base_score = 5.0   # LOW
        else:
            base_score = 1.0   # Keep (too integrated)

        # Penalties
        glob_penalty = breadth.glob_imports * 10  # Wildcard = broad usage
        usage_penalty = min(breadth.usage_sites / 10, 20)  # Many uses = integrated

        return max(base_score - glob_penalty - usage_penalty, 0)

    def suggest_replacement_strategy(
        self,
        dep_name: str,
        breadth: UsageBreadth,
        shallow_score: float
    ) -> ReplacementSuggestion:
        """Determine best replacement strategy for a dependency."""
        unique_count = len(breadth.unique_symbols)
        symbols = breadth.unique_symbols

        # Rule 1: Glob imports → keep (too embedded)
        if breadth.glob_imports > 0:
            return ReplacementSuggestion(
                strategy=ReplacementStrategy.KEEP,
                confidence="high",
                rationale=f"Uses wildcard imports ({breadth.glob_imports}), indicating broad API usage",
                alternative=None,
                effort="n/a",
                symbols_to_replace=[],
            )

        # Rule 2: Standard library alternatives
        if dep_name in STDLIB_REPLACEMENTS:
            alt, version = STDLIB_REPLACEMENTS[dep_name]
            return ReplacementSuggestion(
                strategy=ReplacementStrategy.STDLIB,
                confidence="high",
                rationale=f"Standard library provides {alt} (since {version})",
                alternative=alt,
                effort="low",
                symbols_to_replace=list(symbols),
            )

        # Rule 3: Single function/type → vendor
        if unique_count == 1:
            symbol = list(symbols)[0]
            return ReplacementSuggestion(
                strategy=ReplacementStrategy.VENDOR,
                confidence="medium",
                rationale=f"Only uses single symbol '{symbol}', likely vendorable",
                alternative=f"Inline implementation of {symbol}",
                effort="low",
                symbols_to_replace=[symbol],
            )

        # Rule 4: 2-3 simple functions → vendor
        if unique_count <= 3 and all(s[0].islower() for s in symbols if s):
            return ReplacementSuggestion(
                strategy=ReplacementStrategy.VENDOR,
                confidence="medium",
                rationale=f"Uses {unique_count} functions: {', '.join(sorted(symbols))}",
                alternative=f"Vendor {unique_count} functions inline",
                effort="low",
                symbols_to_replace=list(symbols),
            )

        # Rule 5: High usage sites despite few symbols → keep
        if breadth.usage_sites > 20:
            return ReplacementSuggestion(
                strategy=ReplacementStrategy.KEEP,
                confidence="medium",
                rationale=f"Used in {breadth.usage_sites} locations, likely well-integrated",
                alternative=None,
                effort="n/a",
                symbols_to_replace=[],
            )

        # Default: needs analysis
        return ReplacementSuggestion(
            strategy=ReplacementStrategy.UNKNOWN,
            confidence="low",
            rationale="Mixed usage pattern requires manual analysis",
            alternative="Review usage to determine best approach",
            effort="unknown",
            symbols_to_replace=list(symbols),
        )

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

    def detect_shallow_usage(self) -> List[Dict]:
        """Detect dependencies with shallow usage patterns."""
        print("Detecting shallow usage patterns...", file=sys.stderr)

        results = []

        for dep_name in self.workspace_deps:
            # Skip if exempted (check both exemption types)
            if dep_name in self.exemptions or dep_name in self.shallow_exemptions:
                continue

            # Skip build dependencies
            if self.dependency_kinds.get(dep_name) == "build":
                continue

            breadth = self.usage_breadth.get(dep_name)
            if not breadth:
                continue

            shallow_score = self.calculate_shallow_usage_score(breadth)

            # Only flag if score is high enough (threshold: 10)
            if shallow_score < 10:
                continue

            suggestion = self.suggest_replacement_strategy(dep_name, breadth, shallow_score)

            # Skip "keep" suggestions
            if suggestion.strategy == ReplacementStrategy.KEEP:
                continue

            results.append({
                "crate": dep_name,
                "shallow_score": round(shallow_score, 1),
                "category": self._categorize_shallow_score(shallow_score),
                "symbols": {
                    "unique": sorted(list(breadth.unique_symbols)),
                    "count": len(breadth.unique_symbols),
                    "import_sites": breadth.import_sites,
                    "usage_sites": breadth.usage_sites,
                    "glob_imports": breadth.glob_imports,
                },
                "replacement": {
                    "strategy": suggestion.strategy.value,
                    "confidence": suggestion.confidence,
                    "rationale": suggestion.rationale,
                    "alternative": suggestion.alternative,
                    "effort": suggestion.effort,
                },
            })

        # Sort by score (descending)
        results.sort(key=lambda x: x["shallow_score"], reverse=True)

        print(f"  Detected {len(results)} shallow usage candidates", file=sys.stderr)
        return results

    def _is_managed_duplicate(self, crate_name: str, version: str) -> bool:
        """Check if a specific version is managed via [replace] directive."""
        return (crate_name in self.replace_directives and
                version in self.replace_directives[crate_name])

    def detect_duplicate_versions(self) -> Tuple[List[Dict], List[Dict]]:
        """Detect crates with multiple versions, categorized by management status.

        Returns:
            Tuple of (managed_duplicates, unmanaged_duplicates)
        """
        print("Detecting duplicate crate versions...", file=sys.stderr)

        managed = []
        unmanaged = []

        for crate_name, version_list in self.package_versions.items():
            if len(version_list) <= 1:
                continue

            # Sort versions for consistent display
            versions_sorted = sorted(
                version_list,
                key=lambda x: x["version"],
                reverse=True
            )

            # Check which versions are managed via [replace]
            versions_info = [v["version"] for v in versions_sorted]
            managed_versions = [
                v for v in versions_info
                if self._is_managed_duplicate(crate_name, v)
            ]
            unmanaged_versions = [
                v for v in versions_info
                if not self._is_managed_duplicate(crate_name, v)
            ]

            # Build duplicate entry
            duplicate_entry = {
                "crate": crate_name,
                "version_count": len(versions_sorted),
                "versions": versions_info,
                "managed_versions": managed_versions,
                "unmanaged_versions": unmanaged_versions,
            }

            # Categorize based on number of UNMANAGED versions
            if len(unmanaged_versions) >= 2:
                # 2+ unmanaged versions = problematic duplicate
                unmanaged.append(duplicate_entry)
            else:
                # 0-1 unmanaged version with managed redirects = intentional deduplication
                managed.append(duplicate_entry)

        # Sort by number of versions (most duplicates first)
        managed.sort(key=lambda x: x["version_count"], reverse=True)
        unmanaged.sort(key=lambda x: x["version_count"], reverse=True)

        print(f"  Detected {len(managed)} managed duplicate sets", file=sys.stderr)
        print(f"  Detected {len(unmanaged)} unmanaged duplicate sets", file=sys.stderr)

        return managed, unmanaged

    def _categorize_shallow_score(self, score: float) -> str:
        """Categorize shallow usage score."""
        if score >= 40:
            return "critical"
        elif score >= 25:
            return "high"
        elif score >= 15:
            return "medium"
        else:
            return "low"

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

    def generate_combined_report(self, high_cost: List[Dict], shallow: List[Dict], managed_duplicates: List[Dict], unmanaged_duplicates: List[Dict], mode: str) -> str:
        """Generate combined human-readable report."""
        lines = ["=" * 80, "Dependency Analysis Report", "=" * 80, ""]

        if mode in ("high-cost", "both") and high_cost:
            lines.append("### HIGH-COST, LOW-USAGE DEPENDENCIES")
            lines.append("")
            lines.append("These dependencies pull in significant transitive baggage:")
            lines.append("")

            for r in high_cost:
                if r["category"] not in ("critical", "high"):
                    continue
                lines.append(f"- {r['crate']} (score: {r['score']})")
                lines.append(f"  Usage: {r['usage']['workspace_imports']} imports, {r['usage']['reverse_deps']} reverse deps")
                lines.append(f"  Cost: {r['cost']['transitive_deps']} transitive deps, {r['cost']['binary_kb']} KB")
                lines.append(f"  Suggestion: {r['suggestion']}")
                lines.append("")

        if mode in ("shallow-usage", "both") and shallow:
            if mode == "both":
                lines.append("")
            lines.append("### SHALLOW USAGE DEPENDENCIES")
            lines.append("")
            lines.append("These dependencies are used minimally and could be replaced:")
            lines.append("")

            for r in shallow:
                if r["category"] not in ("critical", "high", "medium"):
                    continue

                lines.append(f"- {r['crate']} (shallow score: {r['shallow_score']})")

                symbols = r['symbols']
                symbol_list = ', '.join(symbols['unique'][:5])
                if len(symbols['unique']) > 5:
                    symbol_list += f", ... ({symbols['count']} total)"
                lines.append(f"  Symbols: {symbol_list}")
                lines.append(f"  Usage: {symbols['import_sites']} import sites, {symbols['usage_sites']} usage sites")

                repl = r['replacement']
                lines.append(f"  Strategy: {repl['strategy']} ({repl['confidence']} confidence)")
                lines.append(f"  Rationale: {repl['rationale']}")
                if repl['alternative']:
                    lines.append(f"  Alternative: {repl['alternative']}")
                lines.append(f"  Effort: {repl['effort']}")
                lines.append("")

        if unmanaged_duplicates:
            if mode == "both" and (high_cost or shallow):
                lines.append("")
            lines.append("### UNMANAGED DUPLICATE CRATE VERSIONS (ACTION REQUIRED)")
            lines.append("")
            lines.append("These crates have 2+ unmanaged versions (true duplicates):")
            lines.append("")

            for r in unmanaged_duplicates:
                versions_str = ", ".join(r['versions'])
                lines.append(f"- {r['crate']} ({r['version_count']} versions: {versions_str})")
                if r['unmanaged_versions']:
                    unmanaged_str = ", ".join(r['unmanaged_versions'])
                    lines.append(f"  Unmanaged: {unmanaged_str}")

            lines.append("")

        if managed_duplicates:
            lines.append("### MANAGED DUPLICATE CRATE VERSIONS (Intentional)")
            lines.append("")
            lines.append("These are deduplicated via [replace] to a single target version:")
            lines.append("")

            for r in managed_duplicates:
                versions_str = ", ".join(r['versions'])
                lines.append(f"- {r['crate']} ({r['version_count']} versions: {versions_str})")
                if r['managed_versions']:
                    managed_str = ", ".join(r['managed_versions'])
                    lines.append(f"  Managed via [replace]: {managed_str}")
                if r['unmanaged_versions']:
                    target_str = ", ".join(r['unmanaged_versions'])
                    lines.append(f"  Target version: {target_str}")

            lines.append("")

        # Exempted
        if self.exemptions or self.shallow_exemptions:
            lines.append("")
            lines.append("EXEMPTED:")
            for crate, reason in sorted(self.exemptions.items()):
                lines.append(f"  - {crate}: {reason}")
            for crate, reason in sorted(self.shallow_exemptions.items()):
                lines.append(f"  - {crate} (shallow): {reason}")
            lines.append("")

        lines.append("=" * 80)
        lines.append(f"Mode: {mode}")
        if high_cost:
            flagged = len([r for r in high_cost if r["category"] in ("critical", "high")])
            lines.append(f"High-cost flagged: {flagged}")
        if shallow:
            flagged = len([r for r in shallow if r["category"] in ("critical", "high", "medium")])
            lines.append(f"Shallow usage flagged: {flagged}")
        if managed_duplicates or unmanaged_duplicates:
            lines.append(f"Managed duplicate versions: {len(managed_duplicates)}")
            lines.append(f"Unmanaged duplicate versions (ACTION REQUIRED): {len(unmanaged_duplicates)}")
        lines.append("=" * 80)

        return "\n".join(lines)

    def generate_combined_json_report(self, high_cost: List[Dict], shallow: List[Dict], managed_duplicates: List[Dict], unmanaged_duplicates: List[Dict], mode: str) -> Dict:
        """Generate combined JSON report."""
        # Group by category
        high_cost_by_cat = defaultdict(list)
        for result in high_cost:
            high_cost_by_cat[result["category"]].append(result)

        shallow_by_cat = defaultdict(list)
        for result in shallow:
            shallow_by_cat[result["category"]].append(result)

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "mode": mode,
            "total_deps_in_tree": len(self.all_deps),
            "workspace_defined_deps": len(self.workspace_deps),
        }

        if mode in ("high-cost", "both"):
            report["high_cost"] = {
                "analyzed": len(high_cost),
                "flagged_count": len([r for r in high_cost if r["category"] in ("critical", "high", "medium")]),
                "categories": {
                    "critical": high_cost_by_cat.get("critical", []),
                    "high": high_cost_by_cat.get("high", []),
                    "medium": high_cost_by_cat.get("medium", []),
                    "low": high_cost_by_cat.get("low", []),
                },
            }

        if mode in ("shallow-usage", "both"):
            report["shallow_usage"] = {
                "analyzed": len(shallow),
                "flagged_count": len([r for r in shallow if r["category"] in ("critical", "high", "medium")]),
                "categories": {
                    "critical": shallow_by_cat.get("critical", []),
                    "high": shallow_by_cat.get("high", []),
                    "medium": shallow_by_cat.get("medium", []),
                    "low": shallow_by_cat.get("low", []),
                },
            }

        if managed_duplicates or unmanaged_duplicates:
            report["duplicate_versions"] = {
                "managed": {
                    "count": len(managed_duplicates),
                    "crates": managed_duplicates,
                },
                "unmanaged": {
                    "count": len(unmanaged_duplicates),
                    "crates": unmanaged_duplicates,
                },
                "total_count": len(managed_duplicates) + len(unmanaged_duplicates),
            }

        report["exempted"] = {
            "high_cost": [
                {"crate": crate, "reason": reason}
                for crate, reason in sorted(self.exemptions.items())
            ],
            "shallow_usage": [
                {"crate": crate, "reason": reason}
                for crate, reason in sorted(self.shallow_exemptions.items())
            ],
        }

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Detect barely-used Rust dependencies"
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
    parser.add_argument(
        "--mode",
        choices=["high-cost", "shallow-usage", "both"],
        default="both",
        help="Analysis mode: high-cost (original), shallow-usage (new), or both (default)",
    )
    parser.add_argument(
        "--skip-binary-size",
        action="store_true",
        help="Skip binary size analysis (faster, less comprehensive)",
    )

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = DependencyAnalyzer(args.workspace)

    # Check tools
    if not analyzer.check_tool_availability():
        sys.exit(1)

    # Load exemptions
    analyzer.load_exemptions()

    # Parse [replace] section for managed duplicates
    analyzer.parse_replace_section()

    # Collect common data
    analyzer.collect_all_deps()
    analyzer.calculate_reverse_dep_counts()

    # Detect duplicate versions
    managed_duplicates, unmanaged_duplicates = analyzer.detect_duplicate_versions()

    # Run high-cost analysis
    high_cost_results = []
    if args.mode in ("high-cost", "both"):
        analyzer.collect_transitive_deps()
        if not args.skip_binary_size:
            analyzer.collect_binary_sizes()
        analyzer.analyze_source_imports()
        analyzer.collect_feature_counts()
        high_cost_results = analyzer.calculate_scores()

    # Run shallow-usage analysis
    shallow_results = []
    if args.mode in ("shallow-usage", "both"):
        analyzer.analyze_symbol_imports()
        analyzer.calculate_usage_breadth()
        shallow_results = analyzer.detect_shallow_usage()

    # Generate report
    if args.format == "human":
        report = analyzer.generate_combined_report(
            high_cost_results, shallow_results, managed_duplicates, unmanaged_duplicates, args.mode
        )
        if args.output:
            args.output.write_text(report)
        else:
            print(report)
    else:  # json
        report = analyzer.generate_combined_json_report(
            high_cost_results, shallow_results, managed_duplicates, unmanaged_duplicates, args.mode
        )
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
        else:
            print(json.dumps(report, indent=2))

    # Exit with code indicating if issues were found
    flagged = 0
    if high_cost_results:
        flagged += len([r for r in high_cost_results if r["category"] in ("critical", "high")])
    if shallow_results:
        flagged += len([r for r in shallow_results if r["category"] in ("critical", "high")])

    sys.exit(0 if flagged == 0 else 1)


if __name__ == "__main__":
    main()
