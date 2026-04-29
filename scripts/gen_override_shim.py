#!/usr/bin/env python3
"""
Generate dependency deduplication shim scaffolding.

This script creates shim crates that re-export a newer version of a dependency,
allowing multiple parts of the codebase to consolidate on a single version.
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def validate_crate_name(name: str) -> bool:
    """Validate that crate name contains only valid characters."""
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', name))


def validate_version(version: str) -> bool:
    """Validate that version string looks like semver (basic check)."""
    return bool(re.fullmatch(r'\d+\.\d+(\.\d+)?', version))


def fetch_crate_metadata(crate_name: str, version: str) -> Tuple[bool, Dict, str]:
    """
    Fetch features and optional dependencies from crates.io.

    Returns:
        (success, metadata_dict, error_message)

    metadata_dict structure:
        {
            'features': dict[str, list[str]],  # feature_name -> dependencies
            'optional_deps': dict[str, str]     # dep_name -> version_req
        }
    """
    metadata = {'features': {}, 'optional_deps': {}}

    try:
        # Fetch crate version metadata for features
        url = f'https://crates.io/api/v1/crates/{crate_name}/{version}'
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'himmelblau-gen-override-shim/1.0')

        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                metadata['features'] = data.get('version', {}).get('features', {})
            else:
                return False, {}, f'HTTP {resp.status} from crates.io'

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, {}, f'Crate {crate_name}@{version} not found on crates.io'
        return False, {}, f'HTTP error {e.code}: {e.reason}'
    except urllib.error.URLError as e:
        return False, {}, f'Network error: {e.reason}'
    except json.JSONDecodeError:
        return False, {}, 'Invalid JSON response from crates.io'
    except Exception as e:
        return False, {}, f'Unexpected error: {str(e)}'

    try:
        # Fetch dependencies to get optional dependency version info
        deps_url = f'https://crates.io/api/v1/crates/{crate_name}/{version}/dependencies'
        req = urllib.request.Request(deps_url)
        req.add_header('User-Agent', 'himmelblau-gen-override-shim/1.0')

        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                deps_data = json.loads(resp.read().decode('utf-8'))
                for dep in deps_data.get('dependencies', []):
                    if dep.get('optional', False):
                        metadata['optional_deps'][dep['crate_id']] = dep['req']

    except Exception:
        # If dependency fetching fails, continue with what we have
        # Features are more critical than optional dep versions
        pass

    return True, metadata, ''


def analyze_features(
    crate_name: str,
    managed_version: str,
    new_version: str
) -> Dict:
    """
    Compare features between versions and categorize them.

    Returns:
        {
            'safe': [(name, definition), ...],  # Auto-forward these
            'attention': [(name, reason, old_def, new_def), ...],  # Manual review
            'dep_conflicts': {dep_name: (old_ver, new_ver), ...},  # Version conflicts
            'old_only': [name, ...],  # Features only in old version
            'metadata_old': dict,  # Full metadata for old version
            'metadata_new': dict   # Full metadata for new version
        }
    """
    result = {
        'safe': [],
        'attention': [],
        'dep_conflicts': {},
        'old_only': [],
        'metadata_old': {},
        'metadata_new': {}
    }

    # Fetch metadata for both versions
    success_old, meta_old, err_old = fetch_crate_metadata(crate_name, managed_version)
    success_new, meta_new, err_new = fetch_crate_metadata(crate_name, new_version)

    if not success_old or not success_new:
        # Can't analyze without both versions
        return result

    result['metadata_old'] = meta_old
    result['metadata_new'] = meta_new

    features_old = meta_old.get('features', {})
    features_new = meta_new.get('features', {})
    optional_deps_old = meta_old.get('optional_deps', {})
    optional_deps_new = meta_new.get('optional_deps', {})

    # Identify common features
    common_features = set(features_old.keys()) & set(features_new.keys())
    old_only_features = set(features_old.keys()) - set(features_new.keys())

    result['old_only'] = sorted(old_only_features)

    # Analyze each common feature
    for feature_name in sorted(common_features):
        old_def = features_old[feature_name]
        new_def = features_new[feature_name]

        # Normalize definitions for comparison (sort lists)
        old_def_sorted = sorted(old_def) if isinstance(old_def, list) else []
        new_def_sorted = sorted(new_def) if isinstance(new_def, list) else []

        if old_def_sorted == new_def_sorted:
            # Identical definition - safe to forward
            result['safe'].append((feature_name, old_def))
        else:
            # Different definition - needs review
            reason = 'definition changed between versions'
            result['attention'].append((feature_name, reason, old_def, new_def))

    # Check for optional dependency version conflicts
    for dep_name in optional_deps_old:
        if dep_name in optional_deps_new:
            old_ver = optional_deps_old[dep_name]
            new_ver = optional_deps_new[dep_name]
            if old_ver != new_ver:
                result['dep_conflicts'][dep_name] = (old_ver, new_ver)

    return result


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate dependency deduplication shim scaffolding',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single managed version
  %(prog)s --crate-name hashbrown --new-version 0.17.0 --managed-version 0.16.1

  # Multiple managed versions
  %(prog)s --crate-name hashbrown --new-version 0.17.0 \\
    --managed-version 0.12.3 --managed-version 0.15.5 --managed-version 0.16.1
        """
    )

    parser.add_argument(
        '--crate-name',
        required=True,
        help='The crate being deduplicated (e.g., "hashbrown")'
    )
    parser.add_argument(
        '--new-version',
        required=True,
        help='The actual version to depend on (e.g., "0.17.0")'
    )
    parser.add_argument(
        '--managed-version',
        action='append',
        dest='managed_versions',
        required=True,
        help='Old version(s) being shimmed (can be specified multiple times)'
    )
    parser.add_argument(
        '--no-auto-features',
        action='store_true',
        help='Disable automatic feature detection (generate basic shim only)'
    )

    args = parser.parse_args()

    # Validate arguments
    if not validate_crate_name(args.crate_name):
        parser.error(f'Invalid crate name: {args.crate_name}')

    if not validate_version(args.new_version):
        parser.error(f'Invalid version format: {args.new_version}')

    for version in args.managed_versions:
        if not validate_version(version):
            parser.error(f'Invalid version format: {version}')

    return args


def generate_features_section(
    crate_name: str,
    features: List[Tuple[str, List[str]]],
    dep_conflicts: Optional[Dict[str, Tuple[str, str]]] = None
) -> str:
    """
    Generate [features] TOML section.

    Transforms feature definitions to forward to the actual crate.
    Internal feature dependencies are handled by the actual crate,
    so we only forward the feature itself and any optional dependencies
    that have version conflicts.

    Example:
    - Old: Wdk_Foundation = ["Wdk"]
    - New: Wdk_Foundation = ["windows-sys/Wdk_Foundation"]
      (The "Wdk" dependency is handled internally by windows-sys)

    - Old: default-hasher = ["dep:foldhash"]
    - New: default-hasher = ["windows-sys/default-hasher", "foldhash"]
      (foldhash is an optional dependency with a version conflict)
    """
    if not features:
        return ''

    lines = ['', '[features]']
    conflict_deps = set(dep_conflicts.keys()) if dep_conflicts else set()

    for feature_name, feature_def in features:
        # Start with just the forwarded feature
        forwarded_def = [f'{crate_name}/{feature_name}']

        # Only add optional dependencies that have version conflicts
        # (these are added explicitly to maintain old version compatibility)
        for dep in feature_def:
            # Check for dep:X syntax or plain dep names that are in conflicts
            if dep.startswith('dep:'):
                dep_name = dep[4:]
                if dep_name in conflict_deps:
                    forwarded_def.append(dep_name)
            elif dep in conflict_deps:
                forwarded_def.append(dep)
            # Note: We don't add internal feature references (like "Wdk")
            # because those are handled by the actual crate internally

        # Format as TOML
        if len(forwarded_def) == 1:
            lines.append(f'{feature_name} = ["{forwarded_def[0]}"]')
        else:
            deps_str = ', '.join(f'"{d}"' for d in forwarded_def)
            lines.append(f'{feature_name} = [{deps_str}]')

    return '\n'.join(lines)


def generate_optional_deps_section(
    dep_conflicts: Dict[str, Tuple[str, str]]
) -> str:
    """
    Generate additional [dependencies] entries for version conflicts.

    Example output:
        foldhash = { version = "0.1.2", optional = true, default-features = false }
    """
    if not dep_conflicts:
        return ''

    lines = []
    for dep_name, (old_ver, new_ver) in sorted(dep_conflicts.items()):
        # Use the old version to maintain compatibility with managed version
        lines.append(
            f'{dep_name} = {{ version = "{old_ver}", optional = true, default-features = false }}'
        )

    return '\n'.join(lines)


def generate_cargo_toml(
    crate_name: str,
    managed_version: str,
    new_version: str,
    features: Optional[List[Tuple[str, List[str]]]] = None,
    dep_conflicts: Optional[Dict[str, Tuple[str, str]]] = None
) -> str:
    """
    Generate Cargo.toml content for the shim package.

    Parameters:
        features: List of (name, definition) tuples to include in [features]
        dep_conflicts: Dict of dep_name -> (old_ver, new_ver) for optional dependencies
    """
    # Base content
    content = f"""[package]
name = "{crate_name}"
version = "{managed_version}"
authors.workspace = true
rust-version.workspace = true
edition.workspace = true
license.workspace = true
homepage.workspace = true
repository.workspace = true
"""

    # Add features section if provided
    if features:
        features_section = generate_features_section(crate_name, features, dep_conflicts)
        content += features_section + '\n'

    # Add dependencies section
    content += '\n[dependencies]\n'
    content += f'{crate_name} = {{ version = "^{new_version}" }}\n'

    # Add optional dependencies for conflicts
    if dep_conflicts:
        optional_deps = generate_optional_deps_section(dep_conflicts)
        if optional_deps:
            content += optional_deps + '\n'

    return content


def generate_lib_rs(crate_name: str) -> str:
    """Generate lib.rs content for the shim package."""
    # Convert crate name to valid Rust identifier (replace hyphens with underscores)
    rust_ident = crate_name.replace('-', '_')
    return f"pub use {rust_ident}::*;\n"


def create_shim_files(
    crate_name: str,
    managed_version: str,
    new_version: str,
    auto_detect_features: bool = True
) -> Tuple[bool, str, Optional[Dict]]:
    """
    Create shim directory structure and files for a single managed version.

    Parameters:
        auto_detect_features: If True, perform automatic feature detection

    Returns:
        (success, error_message, analysis_info)

    analysis_info contains:
        - 'safe_features': Features that were auto-forwarded
        - 'attention_features': Features needing manual review
        - 'dep_conflicts': Optional dependency conflicts resolved
        - 'old_only': Features in old but not new
        - 'fetch_error': Error message if feature fetch failed
    """
    base_dir = Path(f'src/overrides/{crate_name}/{managed_version}')
    src_dir = base_dir / 'src'
    analysis_info = None

    # Check if directory already exists
    if base_dir.exists():
        return False, f"Directory already exists: {base_dir}", None

    # Perform feature analysis if enabled
    features_to_forward = None
    dep_conflicts = None

    if auto_detect_features:
        analysis = analyze_features(crate_name, managed_version, new_version)

        # Check if we got valid metadata
        if analysis.get('metadata_old') and analysis.get('metadata_new'):
            # We have valid analysis. Forward all features from the managed
            # version so the shim preserves the old feature surface, even when
            # some feature definitions changed and still need manual review.
            old_features = analysis.get('metadata_old', {}).get('features', {})
            if isinstance(old_features, dict):
                # Convert to list of (name, definition) tuples
                features_to_forward = [(name, defn) for name, defn in sorted(old_features.items())]
            else:
                # Fallback to previous behavior if metadata is malformed
                features_to_forward = analysis.get('safe', [])

            dep_conflicts = analysis.get('dep_conflicts', {})

            analysis_info = {
                'safe_features': analysis.get('safe', []),
                'attention_features': analysis.get('attention', []),
                'dep_conflicts': dep_conflicts,
                'old_only': analysis.get('old_only', []),
                'fetch_error': None
            }
        else:
            # Feature detection failed
            analysis_info = {
                'safe_features': [],
                'attention_features': [],
                'dep_conflicts': {},
                'old_only': [],
                'fetch_error': 'Could not fetch features from crates.io'
            }

    try:
        # Create directories
        src_dir.mkdir(parents=True, exist_ok=False)

        # Write Cargo.toml
        cargo_toml_path = base_dir / 'Cargo.toml'
        cargo_toml_content = generate_cargo_toml(
            crate_name,
            managed_version,
            new_version,
            features=features_to_forward,
            dep_conflicts=dep_conflicts
        )
        cargo_toml_path.write_text(cargo_toml_content)

        # Write lib.rs
        lib_rs_path = src_dir / 'lib.rs'
        lib_rs_content = generate_lib_rs(crate_name)
        lib_rs_path.write_text(lib_rs_content)

        return True, "", analysis_info

    except Exception as e:
        return False, str(e), None


def update_root_cargo_toml(crate_name: str, managed_versions: List[str]) -> Tuple[bool, str]:
    """
    Update root Cargo.toml with replace entries.

    Returns (success, error_message)
    """
    cargo_toml_path = Path('./Cargo.toml')

    if not cargo_toml_path.exists():
        return False, "Root Cargo.toml not found"

    try:
        # Read existing content
        content = cargo_toml_path.read_text()

        # Find [replace] section
        replace_pattern = r'\[replace\]'
        if not re.search(replace_pattern, content):
            return False, "No [replace] section found in Cargo.toml"

        # Split content into lines for processing
        lines = content.split('\n')

        # Find the [replace] section
        replace_idx = None
        for i, line in enumerate(lines):
            if line.strip() == '[replace]':
                replace_idx = i
                break

        if replace_idx is None:
            return False, "Could not locate [replace] section"

        # Collect existing replace entries and new entries
        existing_entries = []
        insert_idx = replace_idx + 1

        # Scan existing entries
        for i in range(replace_idx + 1, len(lines)):
            line = lines[i].strip()
            # Stop at next section or empty lines that indicate end of section
            if line.startswith('[') or (not line and i > replace_idx + 1):
                insert_idx = i
                break
            if line and not line.startswith('#'):
                existing_entries.append(line)
                insert_idx = i + 1

        # Create new entries
        new_entries = []
        for version in managed_versions:
            entry = f'"{crate_name}:{version}" = {{ path = "src/overrides/{crate_name}/{version}" }}'
            new_entries.append(entry)

        # Combine and sort all entries
        all_entries = existing_entries + new_entries
        all_entries.sort()

        # Rebuild the [replace] section
        new_lines = lines[:replace_idx + 1]
        for entry in all_entries:
            new_lines.append(entry)
        new_lines.extend(lines[insert_idx:])

        # Write back
        new_content = '\n'.join(new_lines)
        cargo_toml_path.write_text(new_content)

        return True, ""

    except Exception as e:
        return False, str(e)


def main():
    """Main entry point."""
    args = parse_args()

    crate_name = args.crate_name
    new_version = args.new_version
    managed_versions = args.managed_versions
    auto_features = not args.no_auto_features

    print(f"Creating shims for {crate_name} -> {new_version}\n")

    # Track results
    succeeded = []
    failed = []
    analyses = {}  # version -> analysis_info

    # Create shim files for each managed version
    for version in managed_versions:
        if auto_features:
            print(f"Analyzing features for {crate_name} {version}...")

        success, error, analysis = create_shim_files(
            crate_name, version, new_version, auto_detect_features=auto_features
        )

        if success:
            succeeded.append(version)
            if analysis:
                analyses[version] = analysis
        else:
            failed.append((version, error))

    # Update root Cargo.toml if we had any successes
    if succeeded:
        success, error = update_root_cargo_toml(crate_name, succeeded)
        if not success:
            print(f"ERROR: Failed to update root Cargo.toml: {error}", file=sys.stderr)
            sys.exit(1)

    # Print summary
    if succeeded:
        print("\nSuccessfully scaffolded:")
        for version in succeeded:
            suffix = ""
            if version in analyses:
                analysis = analyses[version]
                if analysis.get('fetch_error'):
                    suffix = " (basic shim - feature fetch failed)"
                elif analysis.get('safe_features'):
                    num_features = len(analysis['safe_features'])
                    suffix = f" ({num_features} {'feature' if num_features == 1 else 'features'} auto-forwarded)"

            print(f"  ✓ {version}{suffix}")
            print(f"    - src/overrides/{crate_name}/{version}/Cargo.toml")
            print(f"    - src/overrides/{crate_name}/{version}/src/lib.rs")

        print(f"\nUpdated:")
        print(f"  - ./Cargo.toml [replace] section ({len(succeeded)} {'entry' if len(succeeded) == 1 else 'entries'} added)")

    if failed:
        print("\nFailed:")
        for version, error in failed:
            print(f"  ✗ {version} - {error}")

    # Print detailed feature analysis for each version
    for version in succeeded:
        if version in analyses:
            analysis = analyses[version]

            if analysis.get('fetch_error'):
                print(f"\n⚠ Warning for {version}: {analysis['fetch_error']}")
                continue

            safe = analysis.get('safe_features', [])
            attention = analysis.get('attention_features', [])
            conflicts = analysis.get('dep_conflicts', {})
            old_only = analysis.get('old_only', [])

            if safe or attention or conflicts or old_only:
                print(f"\nFeature Summary for {version}:")

            if safe:
                print(f"  Auto-forwarded ({len(safe)}):")
                for feature_name, _ in safe:
                    extra = ""
                    if feature_name in [name for name, _ in conflicts.items()]:
                        extra = " (with dependency)"
                    print(f"    ✓ {feature_name}{extra}")

            if attention:
                print(f"  Needs Manual Review ({len(attention)}):")
                for feature_name, reason, old_def, new_def in attention:
                    print(f"    ⚠ {feature_name} - {reason}")
                    print(f"      OLD: {old_def}")
                    print(f"      NEW: {new_def}")

            if conflicts:
                print(f"  Optional Dependency Conflicts ({len(conflicts)}):")
                for dep_name, (old_ver, new_ver) in conflicts.items():
                    print(f"    ! {dep_name}: {version} uses {old_ver} but {new_version} uses {new_ver}")
                    print(f"      Added explicit {dep_name} = \"{old_ver}\" to maintain compatibility")

            if old_only:
                print(f"  Features Only in {version} ({len(old_only)}):")
                print(f"    ℹ {', '.join(old_only)}")
                print(f"    (Not forwarded - new version doesn't support these)")

    if succeeded:
        print("\nNext steps:")
        print("  1. Review generated Cargo.toml files")
        if any(analyses.get(v, {}).get('attention_features') for v in succeeded):
            print("  2. Consider manually adding features marked ⚠ if needed")
            print("  3. Run 'cargo metadata' to verify")
            print("  4. Run 'cargo build' to test")
            print("  5. Verify dependency graph with 'cargo tree -d'")
        else:
            print("  2. Run 'cargo metadata' to verify")
            print("  3. Run 'cargo build' to test")
            print("  4. Verify dependency graph with 'cargo tree -d'")

    # Exit with error code if all failed
    if not succeeded:
        sys.exit(1)


if __name__ == '__main__':
    main()
