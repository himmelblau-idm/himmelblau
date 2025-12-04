#!/usr/bin/env python3
"""
Generate a Himmelblau authselect vendor profile from the host's default.

Steps:
  1. Detect the active authselect profile on the host.
  2. Create a temporary custom profile based on it.
  3. Run `aad-tool configure-pam` against that profile directory.
  4. Ensure NSS is configured to include `himmelblau` in nsswitch.conf.
  5. Copy the resulting profile files into <root>/<output-dir>.

This script is meant to be run on a build host/container that matches
the target environment (EL, SLE, etc.).
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_TEMP_PROFILE_NAME = "himmelblau"


def run(cmd, *, check=True, capture_output=False, text=True, **kwargs):
    """
    Wrapper around subprocess.run with compatibility for Python 3.6.

    - Python 3.6 does not support capture_output or text parameters.
    - When capture_output=True, we explicitly set stdout/stderr to PIPE.
    - When text=True, we set universal_newlines=True.
    """
    # Show command
    print(f"+ {' '.join(cmd)}", file=sys.stderr)

    # Handle capture_output manually
    if capture_output:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)

    # Handle text=True using universal_newlines=True
    if text:
        kwargs.setdefault("universal_newlines", True)

    return subprocess.run(
        cmd,
        check=check,
        **kwargs
    )


def detect_current_profile():
    """Return (profile_id, features_list) from `authselect current --raw`."""
    try:
        result = run(["authselect", "current", "--raw"], capture_output=True)
    except subprocess.CalledProcessError as e:
        print("ERROR: failed to query authselect current profile.", file=sys.stderr)
        sys.exit(1)

    raw = result.stdout.strip()
    if not raw:
        print("ERROR: empty output from authselect current --raw.", file=sys.stderr)
        sys.exit(1)

    parts = raw.split()
    profile_id, features = parts[0], parts[1:]
    print(f"Detected authselect profile: {profile_id} (features: {features})",
          file=sys.stderr)
    return profile_id, features


def create_temp_profile(temp_profile_name, base_profile):
    """Create a custom authselect profile based on base_profile."""
    custom_dir = Path("/etc/authselect/custom") / temp_profile_name

    if custom_dir.exists():
        print(f"Removing old custom profile at {custom_dir}", file=sys.stderr)
        shutil.rmtree(custom_dir)

    run(["authselect", "create-profile", temp_profile_name, "-b", base_profile])

    if not custom_dir.is_dir():
        print(f"ERROR: expected profile directory {custom_dir} missing.", file=sys.stderr)
        sys.exit(1)

    print(f"Created temporary profile at {custom_dir}", file=sys.stderr)
    return custom_dir


def run_aad_tool_configure_pam(aad_tool, profile_dir, extra_args=None):
    """Call aad-tool configure-pam against the profile directory."""
    if extra_args is None:
        extra_args = []

    system_auth = profile_dir / "system-auth"
    password_auth = profile_dir / "password-auth"
    for pam_file in [system_auth, password_auth]:
        cmd = [
            aad_tool,
            "configure-pam",
            "--auth-file=%s" % pam_file,
            "--account-file=%s" % pam_file,
            "--session-file=%s" % pam_file,
            "--password-file=%s" % pam_file,
            "--really",
        ] + extra_args

        try:
            run(cmd)
        except FileNotFoundError:
            print(f"ERROR: {aad_tool} not found in PATH.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print("ERROR: aad-tool configure-pam failed.", file=sys.stderr)
            sys.exit(1)


def patch_nsswitch_for_himmelblau(nsswitch_path: Path):
    """Ensure 'himmelblau' is present on passwd/group/shadow lines in nsswitch templates.

    - If 'himmelblau' is already present, the line is left unchanged.
    - If there are trailing `{exclude ...}` macros, 'himmelblau' is inserted
      before the first `{exclude` token.
    - Otherwise, 'himmelblau' is appended at the end of the line.
    """
    if not nsswitch_path.exists():
        print(f"WARNING: {nsswitch_path} missing; NSS patch skipped.", file=sys.stderr)
        return

    original = nsswitch_path.read_text(encoding="utf-8").splitlines()
    result = []

    def patch_line(line: str, key: str) -> str:
        stripped = line.lstrip()
        if not stripped.startswith(key + ":"):
            return line

        # Preserve leading whitespace and the `key:` part
        leading_ws = line[: len(line) - len(stripped)]
        prefix, rest = stripped.split(":", 1)

        # Work on the "body" (everything after the colon), normalized
        body = rest.strip()
        if not body:
            # Nothing to do if there is no config after the colon
            return line

        tokens = body.split()

        # If himmelblau is already present anywhere, do nothing
        if "himmelblau" in tokens:
            return line

        # Split tokens into "service" part and trailing `{exclude ...}` macros
        excl_idx = None
        for i, t in enumerate(tokens):
            if t.startswith("{exclude"):
                excl_idx = i
                break

        if excl_idx is None:
            service_tokens = tokens
            tail_tokens = []
        else:
            service_tokens = tokens[:excl_idx]
            tail_tokens = tokens[excl_idx:]

        # Add himmelblau to the service tokens
        service_tokens.append("himmelblau")

        new_tokens = service_tokens + tail_tokens
        new_body = " ".join(new_tokens)

        return f"{leading_ws}{prefix}: {new_body}"

    for line in original:
        for key in ("passwd", "group", "shadow"):
            line = patch_line(line, key)
        result.append(line)

    backup = nsswitch_path.with_suffix(".bak")
    shutil.copy2(nsswitch_path, backup)
    print(f"Backed up original nsswitch.conf to {backup}", file=sys.stderr)

    nsswitch_path.write_text("\n".join(result) + "\n", encoding="utf-8")
    print(f"Patched NSS entries in {nsswitch_path}", file=sys.stderr)


def normalize_readme(root_dir: Path, readme_path: Path):
    readme_replace = root_dir / "scripts/authselect_README"
    shutil.copy2(readme_replace, readme_path)


def copy_profile_to_source(profile_dir: Path, output_dir: Path, keep_extra=False):
    """Copy profile files into the source tree."""
    if output_dir.exists():
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    allowed = {
        "README",
        "system-auth",
        "password-auth",
        "smartcard-auth",
        "fingerprint-auth",
        "postlogin",
        "nsswitch.conf",
        "dconf-db",
        "dconf-locks",
    }

    for item in profile_dir.iterdir():
        if not keep_extra and item.name not in allowed:
            print(f"Skipping extra file {item.name}", file=sys.stderr)
            continue

        dest = output_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    print(f"Copied profile into {output_dir}", file=sys.stderr)


def parse_args():
    p = argparse.ArgumentParser(
        description="Generate a Himmelblau authselect vendor profile"
    )
    p.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Root directory of the workspace (default: current directory).",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory relative to --root, or absolute.",
    )
    p.add_argument(
        "--aad-tool",
        type=str,
        required=True,
        help="Path or name of the aad-tool binary to execute.",
    )
    p.add_argument(
        "--temp-profile-name",
        default=DEFAULT_TEMP_PROFILE_NAME,
        help="Temporary custom profile name.",
    )
    p.add_argument(
        "--aad-tool-extra-arg",
        action="append",
        default=[],
        help="Extra arg(s) passed to aad-tool configure-pam.",
    )
    p.add_argument(
        "--keep-extra",
        action="store_true",
        help="Keep nonstandard files from the profile.",
    )
    return p.parse_args()


def ensure_authselect():
    """Verify that authselect exists and is configured; exit gracefully if not."""
    try:
        run(["authselect", "check"])
    except FileNotFoundError:
        # authselect binary not installed – nothing to do, but don't crash noisily
        print(
            "authselect not found in PATH; skipping authselect profile generation.",
            file=sys.stderr,
        )
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        # authselect is present but misconfigured – this *is* an error
        print(
            "ERROR: 'authselect check' failed; is the system configured with authselect?",
            file=sys.stderr,
        )
        sys.exit(e.returncode)


def main():
    args = parse_args()

    # Compute output path (resolve relative paths under --root).
    if args.output_dir.is_absolute():
        output_path = args.output_dir
    else:
        output_path = args.root / args.output_dir

    # Ensure authselect is functional
    ensure_authselect()

    profile_id, _ = detect_current_profile()
    custom_dir = create_temp_profile(args.temp_profile_name, profile_id)

    run_aad_tool_configure_pam(args.aad_tool, custom_dir, args.aad_tool_extra_arg)

    patch_nsswitch_for_himmelblau(custom_dir / "nsswitch.conf")
    normalize_readme(args.root, custom_dir / "README")

    copy_profile_to_source(custom_dir, output_path, keep_extra=args.keep_extra)

    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
