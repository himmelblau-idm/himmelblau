#!/usr/bin/env python3
"""
Himmelblau local installer

Usage:
  python install_local.py [--destdir /] [--build] [--no-build]

Installs himmelblau from local sources based on Cargo.toml asset metadata.
Used for Gentoo and other source-based installations.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Python 3.11+ has tomllib in the stdlib; older Pythons can use tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


def load_toml(path: Path) -> dict:
    """Load a TOML file into a Python dict."""
    if tomllib is None:
        raise RuntimeError("tomllib/tomli not available - install tomli for Python <3.11")
    with path.open("rb") as f:
        return tomllib.load(f)


def find_cargo_toml_files(root: Path):
    """Recursively find Cargo.toml files under root."""
    for dirpath, dirnames, filenames in os.walk(root):
        basename = os.path.basename(dirpath)
        if basename in {".git", ".hg", ".svn", "target"}:
            dirnames[:] = []
            continue
        if "Cargo.toml" in filenames:
            yield Path(dirpath) / "Cargo.toml"


def extract_rpm_assets(toml_data: dict, cargo_path: Path, repo_root: Path) -> list:
    """Extract assets from [package.metadata.generate-rpm] section."""
    pkg = toml_data.get("package") or {}
    metadata = pkg.get("metadata") or {}
    gen_rpm = metadata.get("generate-rpm")

    if gen_rpm is None:
        return []

    assets = gen_rpm.get("assets", [])
    result = []
    crate_dir = cargo_path.parent

    for asset in assets:
        src = asset.get("source", "")
        dest = asset.get("dest", "")
        mode = asset.get("mode", "755")

        # Resolve source path relative to crate or repo root
        if src.startswith("target/") or src.startswith("platform/"):
            resolved_src = src
        else:
            abs_src = (crate_dir / src).resolve()
            try:
                resolved_src = abs_src.relative_to(repo_root).as_posix()
            except ValueError:
                resolved_src = src

        result.append({
            "source": resolved_src,
            "dest": dest,
            "mode": mode,
        })

    return result


def collect_all_assets(repo_root: Path, crate_names: list) -> list:
    """Collect all assets from specified crates' Cargo.toml files."""
    all_assets = []

    for cargo_path in find_cargo_toml_files(repo_root):
        try:
            data = load_toml(cargo_path)
        except Exception:
            continue

        pkg = data.get("package") or {}
        name = pkg.get("name")

        if name not in crate_names:
            continue

        assets = extract_rpm_assets(data, cargo_path, repo_root)
        all_assets.extend(assets)

    return all_assets


def build_project(repo_root: Path, features: list = None):
    """Build the project with cargo."""
    print("Building from local sources...")

    # Generate service files first
    subprocess.run(
        ["python3", "scripts/gen_servicefiles.py", "--out", "./platform/opensuse/"],
        cwd=repo_root,
        check=True
    )

    # Build with cargo
    cmd = ["cargo", "build", "--release"]
    if features:
        cmd.extend(["--features", ",".join(features)])

    subprocess.run(cmd, cwd=repo_root, check=True)

    # Strip binaries
    binaries = [
        "target/release/aad-tool",
        "target/release/himmelblaud",
        "target/release/himmelblaud_tasks",
        "target/release/broker",
        "target/release/linux-entra-sso",
    ]
    libs = [
        "target/release/libnss_himmelblau.so",
        "target/release/libpam_himmelblau.so",
    ]

    for binary in binaries + libs:
        path = repo_root / binary
        if path.exists():
            subprocess.run(["strip", "-s", str(path)], check=False)


def install_assets(repo_root: Path, destdir: Path):
    """Install all assets to destdir."""
    crate_names = ["himmelblaud", "nss_himmelblau", "pam_himmelblau", "sshd-config", "sso", "qr-greeter", "o365"]

    assets = collect_all_assets(repo_root, crate_names)

    if not assets:
        print("Warning: No assets found in Cargo.toml files, using fallback")
        install_fallback(repo_root, destdir)
        return

    print(f"Installing to {destdir}...")

    for asset in assets:
        src = asset["source"]
        dest = asset["dest"]
        mode = asset["mode"]

        # Skip selinux assets
        if "selinux" in src.lower() or "selinux" in dest.lower():
            continue

        # Skip wildcards - handle them specially
        if "*" in src:
            import glob
            src_pattern = str(repo_root / src)
            for src_file in glob.glob(src_pattern):
                src_path = Path(src_file)
                if dest.endswith("/"):
                    dest_path = destdir / dest.lstrip("/") / src_path.name
                else:
                    dest_path = destdir / dest.lstrip("/")
                install_file(src_path, dest_path, mode)
            continue

        src_path = repo_root / src

        # Handle destination
        if dest.endswith("/"):
            dest_path = destdir / dest.lstrip("/") / os.path.basename(src)
        else:
            dest_path = destdir / dest.lstrip("/")

        install_file(src_path, dest_path, mode)


def install_file(src: Path, dest: Path, mode: str):
    """Install a single file."""
    if not src.exists():
        print(f"  Warning: source not found: {src}")
        return

    # Create destination directory
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Convert mode string to octal
    try:
        mode_int = int(mode, 8)
    except ValueError:
        mode_int = 0o644

    # Copy file
    import shutil
    shutil.copy2(src, dest)
    os.chmod(dest, mode_int)

    print(f"  {src} -> {dest}")


def install_fallback(repo_root: Path, destdir: Path):
    """Fallback installation if TOML parsing fails."""
    fallback_assets = [
        ("target/release/aad-tool", "/usr/bin/aad-tool", "755"),
        ("target/release/linux-entra-sso", "/usr/bin/linux-entra-sso", "755"),
        ("target/release/himmelblaud", "/usr/sbin/himmelblaud", "755"),
        ("target/release/himmelblaud_tasks", "/usr/sbin/himmelblaud_tasks", "755"),
        ("target/release/broker", "/usr/sbin/broker", "755"),
        ("target/release/libnss_himmelblau.so", "/usr/lib64/libnss_himmelblau.so.2", "755"),
        ("target/release/libpam_himmelblau.so", "/usr/lib64/security/pam_himmelblau.so", "755"),
        ("platform/opensuse/himmelblaud.service", "/usr/lib/systemd/system/himmelblaud.service", "644"),
        ("platform/opensuse/himmelblaud-tasks.service", "/usr/lib/systemd/system/himmelblaud-tasks.service", "644"),
        ("src/config/himmelblau.conf.example", "/etc/himmelblau/himmelblau.conf", "644"),
    ]

    for src, dest, mode in fallback_assets:
        src_path = repo_root / src
        dest_path = destdir / dest.lstrip("/")
        install_file(src_path, dest_path, mode)


def main():
    ap = argparse.ArgumentParser(description="Install himmelblau from local sources")
    ap.add_argument("--destdir", default="/", help="Destination root directory (default: /)")
    ap.add_argument("--repo-root", default=None, help="Repository root (defaults to parent of script dir)")
    ap.add_argument("--build", dest="build", action="store_true", default=True,
                    help="Build before installing (default)")
    ap.add_argument("--no-build", dest="build", action="store_false",
                    help="Skip build, only install")
    ap.add_argument("--features", default="tpm", help="Cargo features to enable (default: tpm)")
    args = ap.parse_args()

    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        repo_root = Path(__file__).parent.parent.resolve()

    destdir = Path(args.destdir).resolve()

    features = [f.strip() for f in args.features.split(",") if f.strip()] if args.features else []

    if args.build:
        build_project(repo_root, features)

    install_assets(repo_root, destdir)

    print("\nInstall complete.")
    print("Next steps:")
    print("  1. Edit /etc/himmelblau/himmelblau.conf")
    print("  2. systemctl enable --now himmelblaud")


if __name__ == "__main__":
    main()
