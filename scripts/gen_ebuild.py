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

EBUILD_TEMPLATE = """\
# Copyright 2024-2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

CRATES=""

inherit cargo pam systemd tmpfiles

DESCRIPTION="Entra ID authentication for Linux"
HOMEPAGE="{homepage}"

RUST_MIN_VER="1.93"

if [[ ${{PV}} != 9999 ]]; then
\tSRC_URI="https://github.com/himmelblau-idm/himmelblau/archive/refs/tags/${{PV}}.tar.gz -> ${{P}}.tar.gz"
else
\tinherit git-r3
\tEGIT_REPO_URI="https://github.com/himmelblau-idm/himmelblau.git"
\tEGIT_BRANCH="main"

\tsrc_unpack() {{
\t\tcargo_src_unpack
\t\tgit-r3_src_unpack
\t}}
fi

SRC_URI+=" ${{CARGO_CRATE_URIS}}"
SRC_URI+=" https://github.com/siemens/linux-entra-sso/releases/download/v1.8.0/linux_entra_sso-1.8.0.xpi"

LICENSE="{license}"
# Dependent crate licenses
LICENSE+="..."

SLOT="0"
KEYWORDS="~amd64"
IUSE="tpm"

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
\t|| ( >=dev-lang/rust-bin-{rust_version} >=dev-lang/rust-{rust_version} )
"

S="${{WORKDIR}}/${{PN}}-${{PV}}"

src_configure() {{
\tlocal myfeatures=(
\t\t$(usev tpm)
\t)
\texport GNOME_VERSION=48
\texport HIMMELBLAU_ALLOW_MISSING_SELINUX=1
\tcargo_src_configure
\tcargo_gen_config
}}

src_compile() {{
\t# Generate service files
\tpython3 scripts/gen_servicefiles.py --out ./platform/opensuse/ || die

\tcargo_src_compile
}}

src_install() {{
\temake DESTDIR="${{D}}" install
\tdosym libnss_himmelblau.so.2 "/usr/$(get_libdir)/libnss_himmelblau.so"

\tnewsbin "${{S}}/./target/release/broker" "himmelblau_broker"
\tinsinto "/usr/share/dbus-1/services"
\tdoins "${{S}}/src/broker/platform/com.microsoft.identity.broker1.service"
\tsystemd_douserunit "${{S}}/src/broker/platform/himmelblau-broker.service"

\t# Add linux-entra-sso under its Manifest name, then FF will use it
\t# without additional policy config.
\tinsinto "/usr/$(get_libdir)/firefox/distribution/extensions"
\tnewins "${{DISTDIR}}"/linux_entra_sso-1.8.0.xpi "linux-entra-sso@example.com.xpi"

\t# Documentation
\tdodoc README.md
\tmv "${{D}}"/usr/share/doc/himmelblau/* "${{D}}/usr/share/doc/himmelblau-${{PVR}}"
\trmdir "${{D}}"/usr/share/doc/himmelblau
}}

pkg_postinst() {{
\ttmpfiles_process "himmelblau-policies.conf" "himmelblaud.conf" "nss-himmelblau.conf"

\tewarn "After installation, you need to:"
\tewarn "  1. Configure /etc/himmelblau/himmelblau.conf"
\tewarn "  2. Enable the himmelblaud services:"
\tewarn "    systemctl enable --now himmelblaud.socket himmelblaud-tasks.socket himmelblaud-broker.socket"
\tewarn "    systemctl enable --now himmelblaud.service himmelblaud-tasks.service himmelblau-hsm-pin-init.service"
\tewarn "  3. Configure PAM and NSS (see documentation)"
\tewarn "Finally, relogin with your user"
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

    return EBUILD_TEMPLATE.format(
        homepage=metadata["homepage"],
        license=ebuild_license,
        rust_version=metadata["rust_version"],
        depend=depend,
        rdepend=rdepend,
        bdepend=bdepend,
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
    os.system(f"pycargoebuild -i {ebuild_path} src/daemon src/cli src/common src/pam src/nss "
              "src/policies src/idmap src/broker src/sshd-config src/sso src/sso-policies "
              "src/qr-greeter src/broker-client src/selinux src/o365 fuzz src/fxhash "
              "src/serde_cbor src/paste src/sshkey-attest src/kanidm_build_profiles src/picky-krb")
    print(f"Generated ebuild: {ebuild_path}")


if __name__ == "__main__":
    main()
