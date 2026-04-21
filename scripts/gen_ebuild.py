#!/usr/bin/env python3
"""
Himmelblau Gentoo ebuild generator

Usage:
  python gen_ebuild.py --out ./packaging/

Generates a Gentoo ebuild file based on metadata from Cargo.toml files.
"""

import argparse
import os
from pathlib import Path

# Python 3.11+ has tomllib in the stdlib; older Pythons can use tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


# ---- Gentoo ebuild package categories ----------------------------------------

GENTOO_DEPEND = [
    "app-crypt/mit-krb5",
    "dev-db/sqlite",
    "dev-libs/openssl:=",
    "sys-apps/dbus",
    "sys-libs/pam",
    "sys-libs/libcap",
    "virtual/libudev",
]

GENTOO_RDEPEND = [
    "sys-apps/systemd",
]

GENTOO_BDEPEND = [
    "dev-build/cmake",
    "dev-libs/libpcre2",
    "dev-libs/libunistring",
    "llvm-core/clang",
    "virtual/pkgconfig",
]

GENTOO_TPM_DEPEND = [
    "app-crypt/tpm2-tss",
]


# ---- TOML parsing ------------------------------------------------------------

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


def get_workspace_metadata(repo_root: Path) -> dict:
    """Extract version and license from workspace Cargo.toml."""
    cargo_toml = repo_root / "Cargo.toml"
    if not cargo_toml.exists():
        return {"version": "0.0.0", "license": "GPL-3.0-or-later", "rust_version": "1.70"}

    try:
        data = load_toml(cargo_toml)
    except Exception:
        return {"version": "0.0.0", "license": "GPL-3.0-or-later", "rust_version": "1.70"}

    workspace = data.get("workspace", {})
    package = workspace.get("package", {})

    return {
        "version": package.get("version", "0.0.0"),
        "license": package.get("license", "GPL-3.0-or-later"),
        "rust_version": package.get("rust-version", "1.70"),
        "homepage": package.get("homepage", "https://github.com/himmelblau-idm/himmelblau"),
    }


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


# ---- Ebuild generation -------------------------------------------------------

def generate_install_commands(repo_root: Path) -> str:
    """Generate src_install() commands for ebuild based on Cargo.toml assets."""
    crate_names = ["himmelblaud", "nss_himmelblau", "pam_himmelblau", "sshd-config", "sso", "sso-policies", "qr-greeter", "o365"]

    try:
        assets = collect_all_assets(repo_root, crate_names)
    except RuntimeError:
        return _fallback_install()

    if not assets:
        return _fallback_install()

    lines = []

    # Group assets by type for cleaner output
    binaries = []
    sbinaries = []
    libraries = []
    pam_modules = []
    configs = []
    systemd_units = []
    man_pages = []
    other = []

    for asset in assets:
        src = asset["source"]
        dest = asset["dest"]

        # Skip selinux assets
        if "selinux" in src.lower() or "selinux" in dest.lower():
            continue

        # Skip wildcards for now - handle manually
        if "*" in src:
            continue

        # Categorize by destination and source filename
        src_basename = os.path.basename(src)
        if dest.startswith("/usr/bin/") or dest.endswith("/usr/bin/"):
            binaries.append((src, dest))
        elif dest.startswith("/usr/sbin/") or dest.endswith("/usr/sbin/"):
            sbinaries.append((src, dest))
        elif "/security/" in dest and (dest.endswith(".so") or src_basename.endswith(".so")):
            pam_modules.append((src, dest))
        elif dest.endswith(".so") or dest.endswith(".so.2"):
            libraries.append((src, dest))
        elif "/systemd/system/" in dest and src_basename.endswith(".service"):
            # Only actual .service files, not drop-in configs
            systemd_units.append((src, dest))
        elif dest.startswith("/etc/"):
            configs.append((src, dest))
        elif "/man/" in dest:
            man_pages.append((src, dest))
        else:
            other.append((src, dest))

    # Generate install commands
    if binaries:
        lines.append("\t# Install binaries")
        for src, dest in binaries:
            lines.append(f'\tdobin "${{S}}/{src}"')

    if sbinaries:
        lines.append("\n\t# Install system binaries")
        for src, dest in sbinaries:
            lines.append(f'\tdosbin "${{S}}/{src}"')

    if libraries:
        lines.append("\n\t# Install NSS library")
        for src, dest in libraries:
            lib_name = os.path.basename(dest)
            lines.append('\tinto /usr')
            lines.append(f'\tdolib.so "${{S}}/{src}"')
            if lib_name != os.path.basename(src):
                lines.append(f'\tdosym "{os.path.basename(src)}" "/usr/$(get_libdir)/{lib_name}"')

    if pam_modules:
        lines.append("\n\t# Install PAM module")
        for src, dest in pam_modules:
            lines.append(f'\tdopammod "${{S}}/{src}"')

    if systemd_units:
        lines.append("\n\t# Install systemd units")
        for src, dest in systemd_units:
            lines.append(f'\tsystemd_dounit "${{S}}/{src}"')

    if configs:
        lines.append("\n\t# Install configuration files")
        for src, dest in configs:
            # Handle directory destinations (ending with /)
            if dest.endswith('/'):
                dest_dir = dest.rstrip('/')
                src_name = os.path.basename(src)
                lines.append(f'\tinsinto "{dest_dir}"')
                lines.append(f'\tdoins "${{S}}/{src}"')
            else:
                dest_dir = os.path.dirname(dest)
                dest_name = os.path.basename(dest)
                src_name = os.path.basename(src)
                lines.append(f'\tinsinto "{dest_dir}"')
                if dest_name != src_name:
                    # Use newins to rename the file during installation
                    lines.append(f'\tnewins "${{S}}/{src}" "{dest_name}"')
                else:
                    lines.append(f'\tdoins "${{S}}/{src}"')

    if man_pages:
        lines.append("\n\t# Install man pages")
        for src, dest in man_pages:
            lines.append(f'\tdoman "${{S}}/{src}"')

    if other:
        lines.append("\n\t# Install other files")
        for src, dest in other:
            # Handle directory destinations (ending with /)
            if dest.endswith('/'):
                dest_dir = dest.rstrip('/')
                src_name = os.path.basename(src)
                lines.append(f'\tinsinto "{dest_dir}"')
                lines.append(f'\tdoins "${{S}}/{src}"')
            else:
                dest_dir = os.path.dirname(dest)
                dest_name = os.path.basename(dest)
                src_name = os.path.basename(src)
                lines.append(f'\tinsinto "{dest_dir}"')
                if dest_name != src_name:
                    # Use newins to rename the file during installation
                    lines.append(f'\tnewins "${{S}}/{src}" "{dest_name}"')
                else:
                    lines.append(f'\tdoins "${{S}}/{src}"')

    return "\n".join(lines)


def _fallback_install() -> str:
    """Fallback install commands if TOML parsing unavailable."""
    return """\t# Install binaries
\tdobin target/release/aad-tool
\tdosbin target/release/himmelblaud
\tdosbin target/release/himmelblaud_tasks
\tdobin target/release/broker
\tdobin target/release/linux-entra-sso

\t# Install NSS library
\tinto /usr
\tdolib.so target/release/libnss_himmelblau.so
\tdosym libnss_himmelblau.so "/usr/$(get_libdir)/libnss_himmelblau.so.2"

\t# Install PAM module
\tdopammod target/release/libpam_himmelblau.so

\t# Install systemd units
\tsystemd_dounit platform/opensuse/himmelblaud.service
\tsystemd_dounit platform/opensuse/himmelblaud-tasks.service

\t# Install configuration
\tinsinto /etc/himmelblau
\tdoins src/config/himmelblau.conf.example"""


EBUILD_TEMPLATE = """\
# Copyright 2024-2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cargo pam systemd

DESCRIPTION="Entra ID authentication for Linux"
HOMEPAGE="{homepage}"
SRC_URI="https://github.com/himmelblau-idm/himmelblau/archive/refs/tags/${{PV}}.tar.gz -> ${{P}}.tar.gz"

LICENSE="{license}"
SLOT="0"
KEYWORDS="~amd64"
IUSE="+tpm"

# Allow network access for cargo to fetch dependencies
# For inclusion in ::gentoo, CRATES variable should be populated instead
RESTRICT="network-sandbox"

DEPEND="
{depend}
"
RDEPEND="${{DEPEND}}
{rdepend}
"
BDEPEND="
{bdepend}
\t>=virtual/rust-{rust_version}
"

S="${{WORKDIR}}/${{PN}}-${{PV}}"

src_configure() {{
\tlocal myfeatures=(
\t\t$(usev tpm)
\t)
\tcargo_src_configure
}}

src_compile() {{
\t# Generate service files
\tpython3 scripts/gen_servicefiles.py --out ./platform/opensuse/ || die

\tcargo_src_compile
}}

src_install() {{
{install_commands}

\t# Documentation
\tdodoc README.md
}}

pkg_postinst() {{
\tewarn "After installation, you need to:"
\tewarn "  1. Configure /etc/himmelblau/himmelblau.conf"
\tewarn "  2. Enable the himmelblaud service: systemctl enable --now himmelblaud"
\tewarn "  3. Configure PAM and NSS (see documentation)"
}}
"""


def generate_ebuild(repo_root: Path) -> str:
    """Generate a Gentoo ebuild file for himmelblau."""
    metadata = get_workspace_metadata(repo_root)

    # Format license for ebuild (convert SPDX to Gentoo format)
    license_map = {
        "GPL-3.0-or-later": "GPL-3+",
        "GPL-3.0": "GPL-3",
        "MIT": "MIT",
        "Apache-2.0": "Apache-2.0",
    }
    ebuild_license = license_map.get(metadata["license"], "GPL-3+")

    # Format dependency lists
    depend = "\n".join(f"\t{pkg}" for pkg in sorted(GENTOO_DEPEND))
    depend += "\n\ttpm? ( " + " ".join(GENTOO_TPM_DEPEND) + " )"

    rdepend = "\n".join(f"\t{pkg}" for pkg in sorted(GENTOO_RDEPEND))

    bdepend = "\n".join(f"\t{pkg}" for pkg in sorted(GENTOO_BDEPEND))

    # Generate install commands
    install_commands = generate_install_commands(repo_root)

    return EBUILD_TEMPLATE.format(
        homepage=metadata["homepage"],
        license=ebuild_license,
        rust_version=metadata["rust_version"],
        depend=depend,
        rdepend=rdepend,
        bdepend=bdepend,
        install_commands=install_commands,
    )


def main():
    ap = argparse.ArgumentParser(description="Generate Gentoo ebuild for himmelblau")
    ap.add_argument("--out", default="./packaging", help="Output directory")
    ap.add_argument("--repo-root", default=None, help="Repository root (defaults to parent of script dir)")
    args = ap.parse_args()

    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        repo_root = Path(__file__).parent.parent.resolve()

    metadata = get_workspace_metadata(repo_root)
    version = metadata["version"]

    os.makedirs(args.out, exist_ok=True)

    ebuild_content = generate_ebuild(repo_root)
    ebuild_filename = f"himmelblau-{version}.ebuild"
    ebuild_path = os.path.join(args.out, ebuild_filename)

    with open(ebuild_path, "w", encoding="utf-8") as f:
        f.write(ebuild_content)

    print(f"Generated ebuild: {ebuild_path}")


if __name__ == "__main__":
    main()
