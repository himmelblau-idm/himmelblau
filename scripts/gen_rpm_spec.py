#!/usr/bin/env python3
import argparse
from datetime import datetime
import json
import os
import sys
from pathlib import Path
import importlib.util

# Python 3.11+ has tomllib in the stdlib; older Pythons can use tomli
try:
    import tomllib  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore[assignment]
    except ImportError:
        print("Error: Python <3.11 detected and 'tomli' is not installed.\n"
              "Install it with: pip install tomli", file=sys.stderr)
        sys.exit(1)


def find_cargo_toml_files(root: Path):
    """
    Recursively find Cargo.toml files under root, skipping some obvious junk.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip target dirs and VCS metadata for speed/noise reduction
        basename = os.path.basename(dirpath)
        if basename in {".git", ".hg", ".svn", "target"}:
            dirnames[:] = []  # don't descend further
            continue

        if "Cargo.toml" in filenames:
            yield Path(dirpath) / "Cargo.toml"


def load_toml(path: Path) -> dict:
    """
    Load a TOML file into a Python dict.
    """
    with path.open("rb") as f:
        return tomllib.load(f)


def extract_package_metadata(toml_data: dict, cargo_path: Path) -> dict | None:
    """
    Extract the bits we care about from a Cargo.toml dict.

    We look for:
      [package]
      [package.metadata.generate-rpm]

    Returns None if no generate-rpm metadata is present.
    """
    pkg = toml_data.get("package") or {}
    metadata = pkg.get("metadata") or {}
    gen_rpm = metadata.get("generate-rpm")

    # Some people put generate-rpm under [workspace.metadata], support that too.
    if gen_rpm is None:
        workspace = toml_data.get("workspace") or {}
        ws_meta = workspace.get("metadata") or {}
        gen_rpm = ws_meta.get("generate-rpm")

    if gen_rpm is None:
        # Not relevant for RPM generation.
        return None

    # Normalize and collect what we know
    name = pkg.get("name")
    version = pkg.get("version")
    description = pkg.get("description")
    license_ = pkg.get("license")
    homepage = pkg.get("homepage")
    repository = pkg.get("repository")

    return {
        "cargo_toml_path": str(cargo_path),
        "crate_name": name,
        "crate_version": version,
        "crate_description": description,
        "crate_license": license_,
        "crate_homepage": homepage,
        "crate_repository": repository,
        # The raw generate-rpm table, untouched, is the key thing:
        "generate_rpm": gen_rpm,
    }


def collect_all_metadata(root: Path) -> list[dict]:
    """
    Walk root, collect RPM metadata from all Cargo.toml files that define it.
    """
    results: list[dict] = []
    for cargo_path in find_cargo_toml_files(root):
        try:
            data = load_toml(cargo_path)
        except Exception as e:  # pragma: no cover
            print(f"Warning: failed to parse {cargo_path}: {e}", file=sys.stderr)
            continue

        meta = extract_package_metadata(data, cargo_path)
        if meta is not None:
            results.append(meta)

    # Sort for deterministic output (by crate_name, then path)
    results.sort(key=lambda m: (m.get("crate_name") or "", m["cargo_toml_path"]))
    return results

SCRIPT_KEYS = [
    "post_install_script",
    "post_uninstall_script",
    "pre_install_script",
    "pre_uninstall_script",
    "post_trans_script",
    "post_untrans_script",
    "pre_untrans_script",
    "pre_trans_script",
]
REL_KEYS = [
    "requires",
    "provides",
    "obsoletes",
    "conflicts",
    "recommends",
    "supplements",
    "suggests",
    "enhances",
]

def _strip_shebang_and_set(text: str) -> str:
    """Remove a leading shebang line if present."""
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("set -")]
    if lines and lines[0].lstrip().startswith("#!"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "exit 0":
        lines = lines[:-1]
    # Normalize to a single trailing newline
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def _load_script_value(raw_value: str, crate_dir: Path) -> str:
    """
    Decide if raw_value is a filename or an inline script.

    Heuristic:
      - If it's a single line AND a file with that path exists relative
        to crate_dir, treat it as a filename.
      - Otherwise treat raw_value as inline script.
    """
    if not raw_value:
        return ""

    raw_value = raw_value.strip()
    if not raw_value:
        return ""

    # Single-line and matching an existing file => filename
    if "\n" not in raw_value:
        candidate = (crate_dir / raw_value).resolve()
        if candidate.is_file():
            contents = candidate.read_text(encoding="utf-8")
            return _strip_shebang_and_set(contents)

    # Fallback: inline script
    return _strip_shebang_and_set(raw_value)

def extract_generate_rpm_scripts(crate: dict) -> dict:
    """
    Given a crate dict with:
      crate["cargo_toml_path"]
      crate["generate_rpm"][<script_type>]
    return a dict {script_type: script_body} with shebangs stripped.
    """
    crate_dir = Path(crate["cargo_toml_path"]).parent
    gr = crate.get("generate_rpm", {})

    scripts = {}
    for key in SCRIPT_KEYS:
        raw = gr.get(key, "") or ""
        scripts[key] = _load_script_value(raw, crate_dir)

    return scripts

def merge_metadata(crate_names: list[str], metadata: list[dict], repo_root: Path) -> dict:
    res = {}
    for crate in metadata:
        if crate["crate_name"] not in crate_names:
            continue

        crate_dir = Path(crate["cargo_toml_path"]).parent

        assets = []
        for asset in crate["generate_rpm"]["assets"]:
            src = asset["source"]
            if src.startswith("target/") or src.startswith("platform/"):
                assets.append(asset)
                continue # target is already a path relative to the root
            abs_src = (crate_dir / src).resolve()
            try:
                rel_src = abs_src.relative_to(repo_root)
            except ValueError:
                rel_src = abs_src
            new_asset = dict(asset)
            new_asset["source"] = rel_src.as_posix()
            assets.append(new_asset)

        scripts = extract_generate_rpm_scripts(crate)

        if "generate_rpm" not in res:
            res["generate_rpm"] = {
                "assets": [],
            }
            for script in SCRIPT_KEYS:
                res["generate_rpm"][script] = ""
            for rel in REL_KEYS:
                res["generate_rpm"][rel] = []

        res["generate_rpm"]["assets"].extend(assets)
        for key, body in scripts.items():
            if not body:
                continue  # nothing to append
            # Append with a separator, or just overwrite, up to you
            existing = res["generate_rpm"].get(key, "")
            if existing:
                res["generate_rpm"][key] = existing.rstrip() + "\n\n" + body
            else:
                res["generate_rpm"][key] = body
        for rel in REL_KEYS:
            if rel in crate["generate_rpm"]:
                res["generate_rpm"][rel].extend(list(crate["generate_rpm"][rel].keys()))
    return res

def load_gen_dockerfiles(py_path: Path):
    """Dynamically import gen_dockerfiles.py as a module."""
    spec = importlib.util.spec_from_file_location("gen_dockerfiles", py_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot import gen_dockerfiles.py")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def collect_zypper_deps(mod):
    """Replicate build_pkg_list() logic for all zypper-based distros."""
    results = {}

    # Exactly the function used by gen_dockerfiles.py
    build_pkg_list = mod.build_pkg_list

    for distname, cfg in mod.DISTS.items():
        if cfg["family"] != "zypper":
            continue

        selinux = bool(cfg.get("selinux", False))
        pkgs = build_pkg_list(cfg, selinux)

        # build_pkg_list returns a multi-line string with \n and indent,
        # so split and clean it:
        final_pkgs = []
        for line in pkgs.split("\n"):
            pkg = line.strip().rstrip("\\").strip()
            if pkg:
                # Some packages may be space-separated (e.g., "selinux-tools selinux-policy-devel")
                for p in pkg.split():
                    if p:
                        final_pkgs.append(p)

        # Apply SUSE-specific package name fixes
        if cfg["family"] == "zypper":
            fixed_pkgs = []
            for p in final_pkgs:
                # systemd should be systemd-mini for build requirements on SUSE
                if p == "systemd":
                    fixed_pkgs.append("systemd-mini")
                # selinux-policy-targeted should be split into selinux-policy-devel and selinux-tools
                elif p == "selinux-policy-targeted":
                    fixed_pkgs.append("selinux-policy-devel")
                    fixed_pkgs.append("selinux-tools")
                else:
                    fixed_pkgs.append(p)
            final_pkgs = fixed_pkgs

        results[distname] = {
            "packages": final_pkgs,
            "image": cfg.get("image"),
            "selinux": selinux,
            "tpm": cfg.get("tpm", False),
        }

    return results

def dep_gen(metadata):
    lines = []
    rpm_meta = metadata.get("generate_rpm", {})

    for key in REL_KEYS:
        deps = rpm_meta.get(key, [])
        if not deps:
            continue

        tag = key.capitalize() + ":"  # e.g. "Requires:"
        for dep in deps:
            dep = dep.strip()
            if dep == 'nss-himmelblau':
                dep = 'libnss_himmelblau2'
            if dep:
                lines.append(f"{tag:<15} {dep}")

    return "\n".join(lines)

def install_line(asset, dest_replace):
    src = asset["source"]
    dest = asset["dest"]
    for key, val in dest_replace.items():
        dest = dest.replace(key, val)
    mode = asset.get("mode", "755")
    # Desktop files, icons, and other data files should not be executable
    if src.endswith('.desktop') or src.endswith('.png') or src.endswith('.css'):
        mode = "644"
    mode = '0'+mode if mode[0] != '0' else mode
    dest_dir, dest_name = os.path.split(dest)
    return f"install -m {mode} {src} %{{buildroot}}{dest}"

def file_line(asset, dest_replace):
    dest = asset["dest"]
    if dest[0] == '/':
        dest = dest[1:]
    if dest[-1] == '/':
        # Get the final path segment from the src
        filename = os.path.basename(asset["source"])
        dest += filename
    for key, val in dest_replace.items():
        dest = dest.replace(key, val)
    prefix = ""
    suffix = ""
    # Only files in /etc should be marked as %config
    # Check if dest is in /etc (via %{_sysconfdir} or literal etc/)
    is_etc_file = dest.startswith("%{_sysconfdir}") or dest.startswith("etc/")
    # Check if this is a man page or doc file - these should never be marked as config
    is_manpage = "%{_mandir}" in dest or "/man/man" in dest
    is_doc = "doc/" in dest
    if is_etc_file and '/himmelblau.conf' in dest and not is_manpage and not is_doc and "ssh/" not in dest:
        prefix = "%config(noreplace) "
    elif is_etc_file and ('.conf' in dest or '.json' in dest) and not is_manpage and not is_doc:
        prefix = "%config "
    # Man pages may be compressed, so use wildcard
    if "%{_mandir}" in dest or "/man/man" in dest:
        suffix = "*"
    return f"{prefix}{dest}{suffix}"

FILE_REPLACE = {
        "usr/share/man": "%{_mandir}",  # Must come before usr/share
        "usr/lib/tmpfiles.d": "%{_tmpfilesdir}",
        "usr/lib64/security": "%{_pam_moduledir}",
        "etc/opt/chrome/native-messaging-hosts": "%{chrome_nm_dir}",
        "etc/chromium/native-messaging-hosts": "%{chromium_nm_dir}",
        "etc/opt/chrome/policies/managed": "%{chrome_policy_dir}",
        "etc/chromium/policies/managed": "%{chromium_policy_dir}",
        "usr/share/google-chrome/extensions": "%{chrome_ext_dir}",
        "usr/share/selinux/packages": "%{_selinux_pkgdir}",
        "usr/share/selinux": "%{_selinux_sharedir}",
        "usr/share/doc/himmelblau-selinux/selinux": "%{_selinux_docdir}",
        "usr/lib/systemd/system": "%{_unitdir}",
        "usr/share/icons": "%{_iconsdir}",
        "usr/share": "%{_datadir}",
        "usr/lib64": "%{_libdir}",
        "usr/bin": "%{_bindir}",
        "usr/sbin": "%{_sbindir}",
        "usr/libexec": "%{_libexecdir}",
        "usr/include": "%{_includedir}",
        "etc/init.d": "%{_initddir}",
        "etc": "%{_sysconfdir}",
        "var/lib": "%{_sharedstatedir}",   # more specific first
        "var": "%{_localstatedir}",        # then the generic /var
        "run": "%{_rundir}",
    }

def generate_install_section(metadata):
    assets = metadata["generate_rpm"]["assets"]

    lines = []

    selinux = False
    authselect = False
    for asset in assets:
        if 'selinux' in asset["source"] or 'selinux' in asset["dest"]:
            selinux = True
            continue
        if 'authselect' in asset["source"] or 'authselect' in asset["dest"]:
            authselect = True
            continue
        lines.append(install_line(asset, FILE_REPLACE))

    # authselect is not available on SUSE
    if authselect:
        lines.append("%if !0%{?suse_version}")
        lines.append("install -D -d -m 0755 %{buildroot}/%{_datadir}/authselect/vendor/himmelblau/")
        for asset in assets:
            if 'authselect' in asset["source"] or 'authselect' in asset["dest"]:
                lines.append(install_line(asset, FILE_REPLACE))
        lines.append("%endif")

    # SELinux is only available on newer SUSE versions
    if selinux:
        lines.append("%if 0%{?suse_version} > 1600 || 0%{?sle_version} >= 160000")
        lines.append("install -D -d -m 0755 %{buildroot}/%{_selinux_pkgdir}")
        lines.append("install -D -d -m 0755 %{buildroot}/%{_selinux_docdir}")
        for asset in assets:
            if 'selinux' in asset["source"] or 'selinux' in asset["dest"]:
                lines.append(install_line(asset, FILE_REPLACE))
        lines.append("%endif")

    return "\n".join(lines)

def rpm_script_section(script_key: str) -> str:
    """
    Convert a cargo-rpm-generate script key into an RPM spec section name.
    """
    mapping = {
        "pre_install_script": "%pre",
        "post_install_script": "%post",
        "pre_uninstall_script": "%preun",
        "post_uninstall_script": "%postun",
        "pre_trans_script": "%pretrans",
        "post_trans_script": "%posttrans",
        "pre_untrans_script": "%preuntrans",
        "post_untrans_script": "%postuntrans",
    }

    return mapping.get(script_key)

def generate_files_section(metadata, name=None, dirs=[], extras=[]):
    assets = metadata["generate_rpm"]["assets"]

    lines = []

    lines.append("%%files%s" % (" -n %s" % name if name else ""))

    selinux = False
    authselect = False
    for _dir in dirs:
        if 'selinux' in _dir:
            selinux = True
            continue
        if 'authselect' in _dir:
            authselect = True
            continue
        lines.append(f"%dir {_dir}")

    for asset in assets:
        if 'selinux' in asset["source"] or 'selinux' in asset["dest"]:
            selinux = True
            continue
        if 'authselect' in asset["source"] or 'authselect' in asset["dest"]:
            authselect = True
            continue
        lines.append(file_line(asset, FILE_REPLACE))

    # authselect is not available on SUSE
    if authselect:
        lines.append("%if !0%{?suse_version}")
        for _dir in dirs:
            if 'authselect' in _dir:
                lines.append(f"%dir {_dir}")
        for asset in assets:
            if 'authselect' in asset["source"] or 'authselect' in asset["dest"]:
                lines.append(file_line(asset, FILE_REPLACE))
        lines.append("%endif")

    # SELinux is only available on newer SUSE versions
    if selinux:
        lines.append("%if 0%{?suse_version} > 1600 || 0%{?sle_version} >= 160000")
        for _dir in dirs:
            if 'selinux' in _dir:
                lines.append(f"%dir {_dir}")
        for asset in assets:
            if 'selinux' in asset["source"] or 'selinux' in asset["dest"]:
                lines.append(file_line(asset, FILE_REPLACE))
        lines.append("%endif")

    for line in extras:
        for key, val in FILE_REPLACE.items():
            line = line.replace(key, val)
        lines.append(line)

    return "\n".join(lines)

def generate_script_sections(metadata, name=None, extras={}):
    res = ''
    for script in SCRIPT_KEYS:
        contents = ''
        if script in extras.keys():
            contents += extras[script]
        if script in metadata['generate_rpm'].keys():
            contents += "\n\n" + metadata['generate_rpm'][script].strip()
        contents = contents.strip()

        section = rpm_script_section(script)
        if contents and len(contents.split('\n')) == 1 and contents[0] != '%':
            res += "%s %s-p %s" % (section, ("-n %s " % name if name else ""), contents)
            res += "\n\n"
        elif contents:
            res += "%s%s\n" % (section, (" -n %s" % name if name else ""))
            res += contents
            res += "\n\n"

    return res.strip()

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract [package.metadata.generate-rpm] from Cargo.toml files."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Root directory of the workspace (default: current directory).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output RPM Spec file (default: print to stdout).",
    )
    parser.add_argument(
        "--target",
        "-t",
        default="tumbleweed",
        help="The SUSE version this spec file is intended for (default: tumbleweed).",
    )

    args = parser.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"Error: root {root} is not a directory", file=sys.stderr)
        return 1

    workspace_cargo = root / "Cargo.toml"
    try:
        workspace_metadata = load_toml(workspace_cargo)
    except Exception as e:  # pragma: no cover
        print(f"Warning: failed to parse {workspace_cargo}: {e}", file=sys.stderr)
        raise e
    metadata = collect_all_metadata(root)

    gen_py = args.root / "scripts/gen_dockerfiles.py"
    if not gen_py.exists():
        print(f"Error: {gen_py} does not exist", file=sys.stderr)
        return 1

    mod = load_gen_dockerfiles(gen_py)
    deps = collect_zypper_deps(mod)

    if args.target not in deps.keys():
        print(f"Target {args.target} not found in {gen_py}. Valid options: {list(deps.keys())}", file=sys.stderr)
        return 1

    # Wrap the statement in version tags, disabling SELinux where not present
    def sel_wrap(line):
        if "selinux" in line:
            return f"""\
%if 0%{{?suse_version}} > 1600 || 0%{{?sle_version}} >= 160000
{line}
%endif"""
        else:
            return line

    # Wrap in non-SUSE conditional (for packages like authselect that don't exist on SUSE)
    def non_suse_wrap(line):
        return f"""\
%if !0%{{?suse_version}}
{line}
%endif"""

    # Generate BuildRequires lines with appropriate conditionals
    def generate_build_requires(packages):
        lines = []
        selinux_pkgs = []
        authselect_pkgs = []
        normal_pkgs = []

        for dep in packages:
            dep = dep.strip()
            if "authselect" in dep:
                authselect_pkgs.append(dep)
            elif "selinux" in dep:
                selinux_pkgs.append(dep)
            else:
                normal_pkgs.append(dep)

        # authselect packages (non-SUSE conditional)
        if authselect_pkgs:
            lines.append("%if !0%{?suse_version}")
            for dep in authselect_pkgs:
                lines.append(f"BuildRequires:  {dep}")
            lines.append("%endif")

        # Normal packages
        for dep in normal_pkgs:
            lines.append(f"BuildRequires:  {dep}")

        # SELinux packages (SUSE-only conditional)
        if selinux_pkgs:
            lines.append("%if 0%{?suse_version} > 1600 || 0%{?sle_version} >= 160000")
            for dep in selinux_pkgs:
                lines.append(f"BuildRequires:  {dep}")
            lines.append("%endif")

        return "\n".join(lines)

    himmelblau_metadata = merge_metadata(["himmelblaud", "selinux"], metadata, root)
    nss_metadata = merge_metadata(["nss_himmelblau"], metadata, root)
    pam_metadata = merge_metadata(["pam_himmelblau"], metadata, root)
    sso_metadata = merge_metadata(["sso", "o365"], metadata, root)
    sshd_metadata = merge_metadata(["sshd-config"], metadata, root)
    qr_metadata = merge_metadata(["qr-greeter"], metadata, root)
    desc = """Himmelblau is an interoperability suite for Microsoft Azure Entra Id
and Intune, which allows users to sign into a Linux machine using Azure
Entra Id credentials."""

    spec_contents = f"""\
#
# spec file for package himmelblau
#
# Copyright (c) {datetime.now().year} SUSE LLC and contributors
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%define chrome_nm_dir       /etc/opt/chrome/native-messaging-hosts
%define chromium_nm_dir     /etc/chromium/native-messaging-hosts
%define chrome_policy_dir   /etc/opt/chrome/policies/managed
%define chromium_policy_dir /etc/chromium/policies/managed
%define chrome_ext_dir      /usr/share/google-chrome/extensions

# SELinux macros
%if 0%{{?suse_version}} > 1600 || 0%{{?sle_version}} >= 160000
%define _selinux_sharedir   /usr/share/selinux
%define _selinux_pkgdir     %{{_selinux_sharedir}}/packages
%define _selinux_docdir     %{{_docdir}}/himmelblau-selinux/selinux
%endif

Name:           himmelblau
Version:        {workspace_metadata['workspace']['package']['version']}
Release:        0
Summary:        Interoperability suite for Microsoft Azure Entra Id
License:        {workspace_metadata['workspace']['package']['license']}
URL:            {workspace_metadata['workspace']['package']['repository']}
Group:          Productivity/Networking/Security
Source:         %{{name}}-%{{version}}.tar.bz2
Source1:        vendor.tar.zst
Source2:        cargo_config
BuildRequires:  binutils
BuildRequires:  cargo
BuildRequires:  cargo-packaging
BuildRequires:  clang-devel
BuildRequires:  patchelf
BuildRequires:  systemd-rpm-macros
{generate_build_requires(deps[args.target]['packages'])}
ExclusiveArch:  %{{rust_tier1_arches}}
{dep_gen(himmelblau_metadata)}

%description
{desc}

%package -n pam-himmelblau
Summary:        Azure Entra Id authentication PAM module
Requires:       %{{name}} = %{{version}}
{dep_gen(pam_metadata)}
Suggests:       authselect

%description -n pam-himmelblau
{desc}

%package -n libnss_himmelblau2
Summary:        Azure Entra Id authentication NSS module
Requires:       %{{name}} = %{{version}}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
{dep_gen(nss_metadata)}
Provides:       nss-himmelblau

%description -n libnss_himmelblau2
{desc}

%package -n himmelblau-sshd-config
Summary:        Azure Entra Id SSHD Configuration
Requires:       %{{name}} = %{{version}}
{dep_gen(sshd_metadata)}
BuildRequires:  openssh-server
BuildArch:      noarch

%description -n himmelblau-sshd-config
{desc}

%package -n himmelblau-sso
Summary:        Azure Entra Id Browser SSO
Requires:       %{{name}} = %{{version}}
{dep_gen(sso_metadata)}

%description -n himmelblau-sso
Himmelblau SSO provides Azure Entra Id browser single sign-on via
Firefox, Chromium, Google Chrome, and Microsoft Edge (where installed),
using native messaging and managed browser policies. It also provides
web apps for common Office 365 applications (Teams, Outlook, etc).

%package -n himmelblau-qr-greeter
Summary:        Azure Entra Id DAG URL QR code GNOME Shell extension
{dep_gen(qr_metadata)}
BuildArch:      noarch

%description -n himmelblau-qr-greeter
GNOME Shell extension that adds a QR code to authentication prompts
when a MS DAG URL is detected.

%prep
%autosetup -a1

%build
make rpm-servicefiles
%if !(0%{{?suse_version}} > 1600 || 0%{{?sle_version}} >= 160000)
export HIMMELBLAU_ALLOW_MISSING_SELINUX=1
%endif
%{{cargo_build}} --workspace --exclude himmelblau-fuzz
%if !0%{{?suse_version}}
make authselect
%endif

%check
%if !(0%{{?suse_version}} > 1600 || 0%{{?sle_version}} >= 160000)
export HIMMELBLAU_ALLOW_MISSING_SELINUX=1
%endif
%{{cargo_test}} --workspace --exclude himmelblau-fuzz

%install
# NSS
install -D -d -m 0755 %{{buildroot}}/%{{_libdir}}
install -D -d -m 0755 %{{buildroot}}/%{{_tmpfilesdir}}
strip --strip-unneeded target/release/libnss_himmelblau.so
patchelf --set-soname libnss_himmelblau.so.2 target/release/libnss_himmelblau.so
{generate_install_section(nss_metadata)}

# PAM
install -D -d -m 0755 %{{buildroot}}/%{{_pam_moduledir}}
strip --strip-unneeded target/release/libpam_himmelblau.so
{generate_install_section(pam_metadata)}

# Himmelblau
install -D -d -m 0755 %{{buildroot}}%{{_sbindir}}
install -D -d -m 0755 %{{buildroot}}%{{_bindir}}
install -D -d -m 0755 %{{buildroot}}%{{_unitdir}}
install -D -d -m 0755 %{{buildroot}}/%{{_sysconfdir}}/himmelblau
install -D -d -m 0755 %{{buildroot}}%{{_datarootdir}}/dbus-1/services
install -D -d -m 0755 %{{buildroot}}%{{_sysconfdir}}/ssh/sshd_config.d
install -D -d -m 0755 %{{buildroot}}%{{_sysconfdir}}/krb5.conf.d
install -D -d -m 0755 %{{buildroot}}/%{{_unitdir}}/display-manager.service.d/
install -d -m 0600 %{{buildroot}}%{{_localstatedir}}/cache/himmelblau-policies
install -D -d -m 0755 %{{buildroot}}%{{_datadir}}/doc/himmelblau/
install -D -d -m 0755 %{{buildroot}}/%{{_tmpfilesdir}}/
install -D -d -m 0755 %{{buildroot}}%{{_mandir}}/man1
install -D -d -m 0755 %{{buildroot}}%{{_mandir}}/man5
install -D -d -m 0755 %{{buildroot}}%{{_mandir}}/man8
strip --strip-unneeded target/release/himmelblaud
strip --strip-unneeded target/release/himmelblaud_tasks
strip --strip-unneeded target/release/broker
strip --strip-unneeded target/release/aad-tool
{generate_install_section(himmelblau_metadata)}
pushd %{{buildroot}}%{{_sbindir}}
ln -s himmelblaud rchimmelblaud
ln -s himmelblaud_tasks rchimmelblaud_tasks
ln -s broker rcbroker
popd

# SSHD Config
install -D -d -m 0755 %{{buildroot}}%{{_sysconfdir}}/ssh/sshd_config.d
{generate_install_section(sshd_metadata)}

# Single Sign On
strip --strip-unneeded target/release/linux-entra-sso
install -D -d -m 0755 %{{buildroot}}%{{_libdir}}/mozilla/native-messaging-hosts
install -D -d -m 0755 %{{buildroot}}%{{_sysconfdir}}/firefox/policies
install -D -d -m 0755 %{{buildroot}}%{{chrome_nm_dir}}
install -D -d -m 0755 %{{buildroot}}%{{chromium_nm_dir}}
install -D -d -m 0755 %{{buildroot}}%{{chrome_ext_dir}}
install -D -d -m 0755 %{{buildroot}}%{{chrome_policy_dir}}
install -D -d -m 0755 %{{buildroot}}%{{chromium_policy_dir}}
install -D -d -m 0755 %{{buildroot}}%{{_datadir}}/applications/
%{{!?_iconsdir:%global _iconsdir %{{_datadir}}/icons}}
install -D -d -m 0755 %{{buildroot}}%{{_iconsdir}}/hicolor/256x256/apps
{generate_install_section(sso_metadata)}

# QR Greeter
install -D -d -m 0755 %{{buildroot}}%{{_datarootdir}}/gnome-shell/extensions/qr-greeter@himmelblau-idm.org
{generate_install_section(qr_metadata)}

{generate_script_sections(nss_metadata, name="libnss_himmelblau2", extras={"post_uninstall_script": "/sbin/ldconfig", "post_install_script": "/sbin/ldconfig"})}

{generate_script_sections(pam_metadata, name="pam-himmelblau")}

{generate_script_sections(himmelblau_metadata, name=None, extras={"post_uninstall_script": "%service_del_postun himmelblaud.service himmelblaud-tasks.service", "pre_uninstall_script": "%service_del_preun himmelblaud.service himmelblaud-tasks.service", "post_install_script": "%service_add_post himmelblaud.service himmelblaud-tasks.service", "pre_install_script": "%service_add_pre himmelblaud.service himmelblaud-tasks.service"})}

{generate_script_sections(sshd_metadata, name="himmelblau-sshd-config")}

{generate_script_sections(sso_metadata, name="himmelblau-sso")}

{generate_script_sections(qr_metadata, name="himmelblau-qr-greeter")}

{generate_files_section(himmelblau_metadata, name=None, dirs=["%{_sysconfdir}/himmelblau", "%{_localstatedir}/cache/himmelblau-policies", "%{_unitdir}/display-manager.service.d", "%{_datadir}/doc/himmelblau", "%{_docdir}/himmelblau-selinux", "%{_selinux_docdir}"], extras=["%{_sbindir}/rchimmelblaud", "%{_sbindir}/rchimmelblaud_tasks", "%ghost %dir /var/lib/private/himmelblaud"])}

{generate_files_section(nss_metadata, name="libnss_himmelblau2", dirs=["%{_tmpfilesdir}"], extras=["%ghost %attr(0755,root,root) /var/cache/nss-himmelblau"])}

{generate_files_section(pam_metadata, name="pam-himmelblau", dirs=["%{_datadir}/authselect", "%{_datadir}/authselect/vendor", "%{_datadir}/authselect/vendor/himmelblau"])}

{generate_files_section(sshd_metadata, name="himmelblau-sshd-config", extras=["%if 0%{?sle_version} <= 150500\n%dir %{_sysconfdir}/ssh/sshd_config.d\n%endif"])}

{generate_files_section(sso_metadata, name="himmelblau-sso", dirs=["%{_libdir}/mozilla", "%{_libdir}/mozilla/native-messaging-hosts", "%{_sysconfdir}/firefox", "%{_sysconfdir}/firefox/policies", "/etc/chromium", "/etc/chromium/native-messaging-hosts", "/etc/chromium/policies", "/etc/chromium/policies/managed", "/etc/opt/chrome", "/etc/opt/chrome/native-messaging-hosts", "/etc/opt/chrome/policies", "/etc/opt/chrome/policies/managed", "/usr/share/google-chrome", "%{chrome_nm_dir}", "%{chromium_nm_dir}", "%attr(0555,root,root) %{chrome_policy_dir}", "%attr(0555,root,root) %{chromium_policy_dir}", "%{chrome_ext_dir}", "%{_iconsdir}/hicolor", "%{_iconsdir}/hicolor/256x256", "%{_iconsdir}/hicolor/256x256/apps"], extras=["%{_sbindir}/rcbroker"])}

{generate_files_section(qr_metadata, name="himmelblau-qr-greeter", dirs=["%{_datarootdir}/gnome-shell", "%{_datarootdir}/gnome-shell/extensions", "%{_datarootdir}/gnome-shell/extensions/qr-greeter@himmelblau-idm.org"])}

%changelog
""".rstrip() + "\n"
    if args.output:
        with open(args.output, 'w') as w:
            w.write(spec_contents)
    else:
        print(spec_contents)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
