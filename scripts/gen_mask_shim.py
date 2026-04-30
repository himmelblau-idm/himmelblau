#!/usr/bin/env python3
"""
Generate dependency mask shim scaffolding.

This script creates replacement crates that mimic the package name and version
of crates that are present in metadata but are not actually used by the build.
The generated crate has no dependencies and an empty lib.rs.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple


def validate_crate_name(name: str) -> bool:
    """Validate that crate name contains only valid characters."""
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', name))


def validate_version(version: str) -> bool:
    """Validate that version string looks like semver (basic check)."""
    return bool(re.match(r'^\d+\.\d+(\.\d+)?', version))


def fetch_feature_names(crate_name: str, version: str) -> Tuple[bool, List[str], str]:
    """
    Fetch feature names from crates.io.

    The generated shim defines these features as empty arrays so dependency
    declarations that request them still resolve without pulling dependencies.
    """
    try:
        url = f'https://crates.io/api/v1/crates/{crate_name}/{version}'
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'himmelblau-gen-mask-shim/1.0')

        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                return False, [], f'HTTP {resp.status} from crates.io'

            data = json.loads(resp.read().decode('utf-8'))
            features = data.get('version', {}).get('features', {})
            return True, sorted(features.keys()), ''

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, [], f'Crate {crate_name}@{version} not found on crates.io'
        return False, [], f'HTTP error {e.code}: {e.reason}'
    except urllib.error.URLError as e:
        return False, [], f'Network error: {e.reason}'
    except json.JSONDecodeError:
        return False, [], 'Invalid JSON response from crates.io'
    except Exception as e:
        return False, [], f'Unexpected error: {str(e)}'


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate dependency mask shim scaffolding',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mask a single crate version
  %(prog)s --crate-name core-foundation --managed-version 0.9.4

  # Mask multiple versions of the same crate
  %(prog)s --crate-name getrandom \
    --managed-version 0.2.16 --managed-version 0.3.3

  # Do not fetch feature names from crates.io
  %(prog)s --crate-name core-foundation --managed-version 0.9.4 --no-auto-features
        """
    )

    parser.add_argument(
        '--crate-name',
        required=True,
        help='The crate being masked (e.g., "core-foundation")'
    )
    parser.add_argument(
        '--managed-version',
        action='append',
        dest='managed_versions',
        required=True,
        help='Version(s) being masked (can be specified multiple times)'
    )
    parser.add_argument(
        '--no-auto-features',
        action='store_true',
        help='Disable automatic feature detection (generate no [features] section)'
    )

    args = parser.parse_args()

    if not validate_crate_name(args.crate_name):
        parser.error(f'Invalid crate name: {args.crate_name}')

    for version in args.managed_versions:
        if not validate_version(version):
            parser.error(f'Invalid version format: {version}')

    return args


def generate_cargo_toml(crate_name: str, version: str, features: List[str]) -> str:
    """Generate Cargo.toml content for the mask shim package."""
    content = f"""[package]
name = "{crate_name}"
version = "{version}"
authors.workspace = true
rust-version.workspace = true
edition.workspace = true
license.workspace = true
homepage.workspace = true
repository.workspace = true
"""

    if features:
        content += '\n[features]\n'
        for feature in features:
            content += f'{feature} = []\n'

    return content


def create_shim_files(
    crate_name: str,
    version: str,
    auto_detect_features: bool = True
) -> Tuple[bool, str, Dict]:
    """Create mask shim directory structure and files for one version."""
    base_dir = Path(f'src/overrides/{crate_name}/{version}')
    src_dir = base_dir / 'src'
    info = {
        'features': [],
        'fetch_error': None,
    }

    if base_dir.exists():
        return False, f'Directory already exists: {base_dir}', info

    if auto_detect_features:
        success, features, error = fetch_feature_names(crate_name, version)
        if success:
            info['features'] = features
        else:
            info['fetch_error'] = error

    try:
        src_dir.mkdir(parents=True, exist_ok=False)
        (base_dir / 'Cargo.toml').write_text(
            generate_cargo_toml(crate_name, version, info['features'])
        )
        (src_dir / 'lib.rs').write_text('')
        return True, '', info
    except Exception as e:
        return False, str(e), info


def update_root_cargo_toml(crate_name: str, managed_versions: List[str]) -> Tuple[bool, str]:
    """Update root Cargo.toml with replace entries."""
    cargo_toml_path = Path('./Cargo.toml')

    if not cargo_toml_path.exists():
        return False, 'Root Cargo.toml not found'

    try:
        content = cargo_toml_path.read_text()
        if not re.search(r'\[replace\]', content):
            return False, 'No [replace] section found in Cargo.toml'

        lines = content.split('\n')
        replace_idx = None
        for i, line in enumerate(lines):
            if line.strip() == '[replace]':
                replace_idx = i
                break

        if replace_idx is None:
            return False, 'Could not locate [replace] section'

        existing_entries = []
        insert_idx = replace_idx + 1
        for i in range(replace_idx + 1, len(lines)):
            line = lines[i].strip()
            if line.startswith('[') or (not line and i > replace_idx + 1):
                insert_idx = i
                break
            if line and not line.startswith('#'):
                existing_entries.append(line)
                insert_idx = i + 1

        new_entries = [
            f'"{crate_name}:{version}" = {{ path = "src/overrides/{crate_name}/{version}" }}'
            for version in managed_versions
        ]
        all_entries = sorted(set(existing_entries + new_entries))

        new_lines = lines[:replace_idx + 1]
        new_lines.extend(all_entries)
        new_lines.extend(lines[insert_idx:])
        cargo_toml_path.write_text('\n'.join(new_lines))
        return True, ''

    except Exception as e:
        return False, str(e)


def main() -> None:
    """Main entry point."""
    args = parse_args()
    crate_name = args.crate_name
    managed_versions = args.managed_versions
    auto_features = not args.no_auto_features

    print(f'Creating mask shims for {crate_name}\n')

    succeeded = []
    failed = []
    infos = {}

    for version in managed_versions:
        if auto_features:
            print(f'Fetching feature names for {crate_name} {version}...')

        success, error, info = create_shim_files(
            crate_name, version, auto_detect_features=auto_features
        )
        if success:
            succeeded.append(version)
            infos[version] = info
        else:
            failed.append((version, error))

    if succeeded:
        success, error = update_root_cargo_toml(crate_name, succeeded)
        if not success:
            print(f'ERROR: Failed to update root Cargo.toml: {error}', file=sys.stderr)
            sys.exit(1)

    if succeeded:
        print('\nSuccessfully scaffolded:')
        for version in succeeded:
            info = infos.get(version, {})
            feature_count = len(info.get('features', []))
            suffix = ''
            if info.get('fetch_error'):
                suffix = ' (feature fetch failed; no [features] section generated)'
            elif feature_count:
                suffix = f' ({feature_count} empty feature stubs generated)'

            print(f'  - {version}{suffix}')
            print(f'    - src/overrides/{crate_name}/{version}/Cargo.toml')
            print(f'    - src/overrides/{crate_name}/{version}/src/lib.rs')

        print('\nUpdated:')
        entry_word = 'entry' if len(succeeded) == 1 else 'entries'
        print(f'  - ./Cargo.toml [replace] section ({len(succeeded)} {entry_word} added)')

    if failed:
        print('\nFailed:')
        for version, error in failed:
            print(f'  - {version} - {error}')

    if succeeded:
        print('\nNext steps:')
        print('  1. Review generated Cargo.toml files for empty feature stubs')
        print('  2. Run cargo metadata to verify')
        print('  3. Run cargo build or the relevant package build to test')

    if not succeeded:
        sys.exit(1)


if __name__ == '__main__':
    main()
