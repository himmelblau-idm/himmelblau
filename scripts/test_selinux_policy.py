#!/usr/bin/env python3
"""
SELinux Policy Compatibility Tester for Himmelblau

This script tests whether the Himmelblau SELinux policy can be installed
on various Linux distributions using containers.

Usage:
    # Test all supported distros
    ./test_selinux_policy.py

    # Test specific distros
    ./test_selinux_policy.py --distros rocky10,fedora42

    # Build policy from source and test
    ./test_selinux_policy.py --build

    # Test with an existing .pp file
    ./test_selinux_policy.py --policy-file /path/to/himmelblaud.pp

    # Automatically diagnose and suggest fixes for failures
    ./test_selinux_policy.py --fix

    # Keep containers running for debugging
    ./test_selinux_policy.py --keep-containers
"""

import argparse
import subprocess
import sys
import os
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import json


def print_color(text: str, color: str):
    """Print colored text."""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")


# Distros that have SELinux support (exclude Debian-based which don't typically use SELinux)
SELINUX_DISTROS = {
    "rocky8": {
        "base_image": "rockylinux/rockylinux:8",
        "pkg_manager": "dnf",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "policycoreutils-devel"],
        "extra_setup": "dnf install -y 'dnf-command(config-manager)' && dnf config-manager --set-enabled powertools",
        "requires_scc": False,
    },
    "rocky9": {
        "base_image": "rockylinux/rockylinux:9",
        "pkg_manager": "dnf",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "policycoreutils-devel"],
        "extra_setup": "dnf install -y 'dnf-command(config-manager)' && dnf config-manager --set-enabled crb",
        "requires_scc": False,
    },
    "rocky10": {
        "base_image": "rockylinux/rockylinux:10",
        "pkg_manager": "dnf",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "policycoreutils-devel"],
        "extra_setup": "dnf install -y 'dnf-command(config-manager)' && dnf config-manager --set-enabled crb && sed -i -e 's|$rltype||g' /etc/yum.repos.d/rocky*.repo",
        "requires_scc": False,
    },
    "fedora42": {
        "base_image": "fedora:42",
        "pkg_manager": "dnf",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "policycoreutils-devel"],
        "extra_setup": None,
        "requires_scc": False,
    },
    "fedora43": {
        "base_image": "fedora:43",
        "pkg_manager": "dnf",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "policycoreutils-devel"],
        "extra_setup": None,
        "requires_scc": False,
    },
    "rawhide": {
        "base_image": "fedora:rawhide",
        "pkg_manager": "dnf",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "policycoreutils-devel"],
        "extra_setup": None,
        "requires_scc": False,
    },
    "tumbleweed": {
        "base_image": "opensuse/tumbleweed",
        "pkg_manager": "zypper",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel"],
        "extra_setup": None,
        "requires_scc": False,
    },
    "sle16": {
        "base_image": "registry.suse.com/bci/bci-base:16.0",
        "pkg_manager": "zypper",
        "selinux_pkgs": ["policycoreutils", "selinux-policy-targeted", "selinux-policy-devel", "selinux-tools"],
        "extra_setup": None,
        "requires_scc": True,  # Requires ~/.secrets/scc_regcode
    },
}

# Default distros to test (excludes SLE which requires SCC credentials)
DEFAULT_DISTROS = [d for d, c in SELINUX_DISTROS.items() if not c.get("requires_scc")]

# Path to the SELinux source directory
SELINUX_SRC = Path(__file__).parent.parent / "src" / "selinux" / "src"

# Path to the selinux_fix.py script
SELINUX_FIX_SCRIPT = Path(__file__).parent / "selinux_fix.py"

@dataclass
class TestResult:
    """Result of a policy installation test."""
    distro: str
    success: bool
    build_output: str
    install_output: str
    error_details: Optional[str] = None
    is_policy_error: bool = True  # False if the error was in container/image setup, not policy


def find_container_runtime() -> str:
    """Find available container runtime (podman or docker)."""
    for runtime in ["podman", "docker"]:
        if shutil.which(runtime):
            return runtime
    raise RuntimeError("No container runtime found. Install podman or docker.")


def run_command(cmd: list[str], capture: bool = True, timeout: int = 300) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        else:
            result = subprocess.run(cmd, timeout=timeout)
            return result.returncode, "", ""
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def build_test_image(runtime: str, distro: str, config: dict) -> tuple[bool, str]:
    """Build a minimal test image for the distro."""
    image_name = f"himmelblau-selinux-test-{distro}"

    # Check for SCC credentials if required
    scc_regcode_path = Path.home() / ".secrets" / "scc_regcode"
    if config.get("requires_scc"):
        if not scc_regcode_path.exists():
            return False, f"SLE requires SCC credentials at {scc_regcode_path}\nCreate file with: email=<email>\\nregcode=<code>"

    # Create Dockerfile
    dockerfile_content = f"""FROM {config['base_image']}

# Setup package manager
"""
    if config.get('extra_setup'):
        dockerfile_content += f"RUN {config['extra_setup']}\n"

    # SLE16 requires SUSEConnect registration
    if config.get("requires_scc"):
        dockerfile_content += """
# Install SUSEConnect for registration
RUN zypper --non-interactive refresh && \\
    zypper --non-interactive install --no-recommends SUSEConnect ca-certificates && \\
    zypper clean --all

# Register with SCC (requires --secret during build)
RUN --mount=type=secret,id=scc_regcode,dst=/run/secrets/scc_regcode \\
    set -e && \\
    source /run/secrets/scc_regcode && \\
    SUSEConnect --email "$email" --regcode "$regcode" && \\
    SUSEConnect -p PackageHub/16.0/x86_64

"""

    if config['pkg_manager'] == 'dnf':
        pkgs = " ".join(config['selinux_pkgs'] + ["make", "m4", "checkpolicy"])
        dockerfile_content += f"""
RUN dnf -y update && dnf -y install {pkgs} && dnf clean all
"""
    elif config['pkg_manager'] == 'zypper':
        pkgs = " ".join(config['selinux_pkgs'] + ["make", "m4", "checkpolicy"])
        dockerfile_content += f"""
RUN zypper --non-interactive refresh && zypper --non-interactive install --no-recommends {pkgs} && zypper clean --all
"""

    dockerfile_content += """
WORKDIR /selinux
"""

    # Write Dockerfile to temp location
    with tempfile.NamedTemporaryFile(mode='w', suffix='.dockerfile', delete=False) as f:
        f.write(dockerfile_content)
        dockerfile_path = f.name

    try:
        # Build the image
        cmd = [runtime, "build", "-t", image_name, "-f", dockerfile_path, "."]

        # Add secret mount for SLE
        if config.get("requires_scc"):
            cmd = [runtime, "build",
                   "--secret", f"id=scc_regcode,src={scc_regcode_path}",
                   "-t", image_name, "-f", dockerfile_path, "."]

        rc, stdout, stderr = run_command(cmd, timeout=600)

        if rc != 0:
            return False, f"Failed to build image:\n{stderr}\n{stdout}"

        return True, image_name
    finally:
        os.unlink(dockerfile_path)


def build_policy_in_container(runtime: str, image_name: str, selinux_src: Path) -> tuple[bool, str]:
    """Build the SELinux policy inside a container."""
    container_name = f"himmelblau-selinux-build-{os.getpid()}"

    # The build command - uses the system Makefile to compile the policy
    build_cmd = """
set -x  # Show commands being executed for debugging
cd /selinux

# Clean previous build artifacts to avoid version mismatch errors
# (different distros have different policy module version requirements)
echo "=== Cleaning previous build artifacts ==="
rm -f himmelblaud.pp tmp/himmelblaud.* 2>/dev/null || true
rm -rf tmp 2>/dev/null || true

# Check if we have the necessary files
echo "=== Source files ==="
ls -la *.te *.fc *.if 2>/dev/null || echo "Warning: Some source files missing"

# Check if the devel Makefile exists
if [ ! -f /usr/share/selinux/devel/Makefile ]; then
    echo "ERROR: /usr/share/selinux/devel/Makefile not found!"
    echo "The selinux-policy-devel package may not be installed."
    exit 1
fi

# Build the policy module
echo "=== Building policy module ==="
if make -f /usr/share/selinux/devel/Makefile NAME=himmelblaud 2>&1; then
    echo ""
    echo "=== Build successful! ==="
    ls -la himmelblaud.pp
else
    BUILD_RC=$?
    echo ""
    echo "=== BUILD FAILED (exit code: $BUILD_RC) ==="
    echo ""
    # Show tmp directory contents if they exist
    if [ -d /selinux/tmp ]; then
        echo "=== Temp files created ==="
        ls -la /selinux/tmp/
    fi
    # Show any error files
    if [ -f /selinux/tmp/himmelblaud.mod.fc ]; then
        echo "=== File contexts ==="
        cat /selinux/tmp/himmelblaud.mod.fc
    fi
    exit $BUILD_RC
fi
"""

    cmd = [
        runtime, "run", "--rm",
        "--name", container_name,
        "--security-opt", "label=disable",
        "-v", f"{selinux_src}:/selinux:Z",
        image_name,
        "/bin/bash", "-c", build_cmd
    ]

    rc, stdout, stderr = run_command(cmd, timeout=300)

    if rc != 0:
        return False, f"Build failed:\n{stdout}\n{stderr}"

    return True, stdout


def test_policy_install(runtime: str, image_name: str, selinux_src: Path) -> tuple[bool, str]:
    """Test installing the SELinux policy in a container."""
    container_name = f"himmelblau-selinux-test-{os.getpid()}"

    # Test command - try to install the policy and verify it loaded
    # Note: We set up a tmpfs at /var/lib/selinux to avoid "Invalid cross-device link" errors
    # that occur in containers due to overlayfs limitations with atomic renames.
    test_cmd = """
set -x  # Show commands being executed for debugging
cd /selinux

# Check if .pp file exists
if [ ! -f himmelblaud.pp ]; then
    echo "ERROR: himmelblaud.pp not found"
    exit 1
fi

echo "=== Testing policy installation ==="
echo "Policy file: $(ls -la himmelblaud.pp)"

# Set up a tmpfs for the SELinux store to avoid cross-device link errors in containers
# First, preserve the existing policy store structure
echo "=== Setting up SELinux store for container environment ==="
if [ -d /var/lib/selinux ]; then
    cp -a /var/lib/selinux /tmp/selinux-store-backup
    mount -t tmpfs tmpfs /var/lib/selinux
    if [ -d /tmp/selinux-store-backup ] && [ "$(ls -A /tmp/selinux-store-backup 2>/dev/null)" ]; then
        cp -a /tmp/selinux-store-backup/. /var/lib/selinux/
    fi
    rm -rf /tmp/selinux-store-backup
    echo "SELinux store mounted on tmpfs"
fi

# Try to install with verbose output
echo "=== Running semodule -vv -i himmelblaud.pp ==="
semodule -vv -i himmelblaud.pp 2>&1
SEMODULE_RC=$?
echo "semodule exit code: $SEMODULE_RC"

# Verify it's actually loaded (this is the real test of success)
echo ""
echo "=== Verifying module is loaded ==="
if semodule -l | grep -q himmelblaud; then
    echo "MODULE LOADED: himmelblaud"
    echo ""
    echo "=== Installation successful! ==="
    # Show some info about the installed module
    echo "=== Module info ==="
    semodule -lfull | grep himmelblaud || true
    exit 0
else
    echo "MODULE NOT FOUND: himmelblaud"
    echo ""
    echo "=== Installation FAILED ==="
    exit 1
fi
"""

    cmd = [
        runtime, "run", "--rm",
        "--name", container_name,
        "--privileged",  # Needed to mount tmpfs for SELinux store
        "--security-opt", "label=disable",
        "-v", f"{selinux_src}:/selinux:Z",
        image_name,
        "/bin/bash", "-c", test_cmd
    ]

    rc, stdout, stderr = run_command(cmd, timeout=300)

    combined = f"{stdout}\n{stderr}"

    # Check if the module was actually loaded (the definitive test)
    if "MODULE LOADED: himmelblaud" in stdout:
        return True, combined

    return False, combined


def extract_error_details(output: str) -> Optional[str]:
    """Extract meaningful error details from semodule output."""
    lines = output.split('\n')
    errors = []

    for i, line in enumerate(lines):
        if 'Failed to resolve' in line and 'himmelblaud' in line:
            errors.append(line)
            # Get context
            if i + 1 < len(lines):
                errors.append(lines[i + 1])
        elif 'Problem at' in line and 'himmelblaud' in line:
            errors.append(line)
        elif 'semodule:' in line and 'Failed' in line:
            errors.append(line)

    return '\n'.join(errors) if errors else None


class AIRunner:
    """Run AI CLI to fix SELinux policy issues."""

    PROMPT_TEMPLATE = """I need your help fixing SELinux policy compatibility issues in the Himmelblau project.

## About Himmelblau SELinux Policy
The SELinux policy is defined in: src/selinux/src/himmelblaud.te
It defines types and rules for the himmelblaud daemon.

## The Problem
The policy fails to build/install on {distro} with this error:

```
{error_output}
```

## Common Issues and Fixes

1. **Unknown type errors** (e.g., "unknown type chkpwd_t"):
   - The type doesn't exist on this distro
   - Fix: Wrap rules referencing that type in `optional {{ }}` blocks
   - Example:
     ```
     optional {{
         allow chkpwd_t himmelblau_etc_t:file {{ getattr open read }};
     }}
     ```

2. **Macro expansion failures** (e.g., init_nnp_daemon_domain):
   - The macro references types that don't exist
   - Fix: Wrap the macro call in `optional {{ }}` block

3. **Type attribute errors**:
   - Usually from macros referencing internal attributes
   - Fix: Wrap in optional block

## Your Task

1. Read the current policy file: src/selinux/src/himmelblaud.te
2. Identify which rules/statements are causing the error
3. Wrap problematic rules in `optional {{ }}` blocks so they gracefully skip on systems that don't have those types
4. Make sure to:
   - Group related rules for the same external type in a single optional block
   - Add a comment explaining why the optional block is needed
   - Preserve the existing structure and comments

## Important Notes
- Do NOT remove rules - wrap them in optional blocks instead
- External types like chkpwd_t, policykit_auth_t, accountsd_t, xdm_t etc. may not exist on all distros
- The goal is cross-distro compatibility - the policy should install on Rocky 8/9/10, Fedora, openSUSE, and SLE

Please fix the policy file now.

**IMPORTANT**: When you have finished making changes, inform the user to exit this interactive session (using /exit, Ctrl+C, or Ctrl+D) so the test script can continue and retest the policy.
"""

    def __init__(self, provider: str = "claude"):
        self.provider = provider
        self.cli_path = provider

    def is_available(self) -> bool:
        """Check if the AI CLI is available."""
        return shutil.which(self.cli_path) is not None

    def create_prompt(self, distro: str, error_output: str) -> str:
        """Create the prompt for the AI."""
        return self.PROMPT_TEMPLATE.format(
            distro=distro,
            error_output=error_output[-3000:],  # Truncate if too long
        )

    def run_interactive(self, distro: str, error_output: str) -> bool:
        """Run the AI CLI interactively to fix the policy."""
        prompt = self.create_prompt(distro, error_output)

        print_color(f"\nLaunching {self.provider} CLI to fix SELinux policy...", "green")
        print_color("The AI will analyze the error and fix himmelblaud.te", "yellow")
        print_color("Use /exit, Ctrl+C, or Ctrl+D when done.\n", "yellow")

        try:
            subprocess.run([self.cli_path, prompt])
            return True
        except KeyboardInterrupt:
            print("\n")
            return True
        except FileNotFoundError:
            print_color(f"Error: {self.provider} CLI not found", "red")
            print_color("Install with: npm install -g @anthropic-ai/claude-code", "yellow")
            return False
        except Exception as e:
            print_color(f"Error running {self.provider}: {e}", "red")
            return False


def run_selinux_fix_diagnosis(install_output: str, distro: str) -> Optional[str]:
    """
    Call selinux_fix.py to diagnose policy installation errors.

    Returns the diagnosis output or None if the script isn't available.
    """
    if not SELINUX_FIX_SCRIPT.exists():
        return None

    try:
        result = subprocess.run(
            [sys.executable, str(SELINUX_FIX_SCRIPT), "--semodule-stdin"],
            input=install_output,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return f"Failed to run selinux_fix.py: {e}"


def run_selinux_fix_analyze() -> Optional[str]:
    """
    Call selinux_fix.py --analyze to get recommendations for the policy file.

    Returns the analysis output or None if the script isn't available.
    """
    if not SELINUX_FIX_SCRIPT.exists():
        return None

    try:
        result = subprocess.run(
            [sys.executable, str(SELINUX_FIX_SCRIPT), "--analyze"],
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return f"Failed to run selinux_fix.py: {e}"


def run_test(runtime: str, distro: str, config: dict, build: bool = True) -> TestResult:
    """Run a complete test for a single distro."""
    print(f"\n{'=' * 60}")
    print(f"Testing: {distro}")
    print(f"Base image: {config['base_image']}")
    print('=' * 60)

    # Build test image
    print(f"  Building test image...")
    success, result = build_test_image(runtime, distro, config)
    if not success:
        return TestResult(
            distro=distro,
            success=False,
            build_output=result,
            install_output="",
            error_details="Failed to build test image",
            is_policy_error=False  # Container setup issue, not policy
        )

    image_name = result

    # Build policy if requested
    build_output = ""
    if build:
        print(f"  Building SELinux policy...")
        success, build_output = build_policy_in_container(runtime, image_name, SELINUX_SRC)
        if not success:
            return TestResult(
                distro=distro,
                success=False,
                build_output=build_output,
                install_output="",
                error_details="Failed to build policy"
            )

    # Test installation
    print(f"  Testing policy installation...")
    success, install_output = test_policy_install(runtime, image_name, SELINUX_SRC)

    error_details = None
    if not success:
        error_details = extract_error_details(install_output)

    return TestResult(
        distro=distro,
        success=success,
        build_output=build_output,
        install_output=install_output,
        error_details=error_details
    )


def cleanup_images(runtime: str, distros: list[str]):
    """Clean up test images (force remove)."""
    for distro in distros:
        image_name = f"himmelblau-selinux-test-{distro}"
        print(f"  Removing {image_name}...")
        # Force remove, ignore errors if image doesn't exist
        rc, stdout, stderr = run_command([runtime, "rmi", "-f", image_name])
        if rc != 0 and "no such image" not in stderr.lower() and "image not known" not in stderr.lower():
            # Try removing any containers using this image first
            run_command([runtime, "rm", "-f", "-a", "--filter", f"ancestor={image_name}"])
            run_command([runtime, "rmi", "-f", image_name])


def print_summary(results: list[TestResult]):
    """Print a summary of all test results."""
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    passed = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    print(f"\nTotal: {len(results)} | Passed: {len(passed)} | Failed: {len(failed)}")

    if passed:
        print("\nPASSED:")
        for r in passed:
            print(f"  {r.distro}")

    if failed:
        print("\nFAILED:")
        for r in failed:
            print(f"  {r.distro}")
            if r.error_details:
                for line in r.error_details.split('\n'):
                    print(f"    {line}")

    print()


def save_results(results: list[TestResult], output_file: str):
    """Save results to a JSON file."""
    data = []
    for r in results:
        data.append({
            "distro": r.distro,
            "success": r.success,
            "error_details": r.error_details,
            "build_output": r.build_output[-2000:] if r.build_output else None,
            "install_output": r.install_output[-2000:] if r.install_output else None,
        })

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"Results saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Test Himmelblau SELinux policy across distributions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Available distros: {', '.join(SELINUX_DISTROS.keys())}

Examples:
  # Test all distros (AI fixing enabled by default)
  %(prog)s

  # Test specific distros
  %(prog)s --distros rocky10,fedora42

  # Test with verbose output
  %(prog)s --verbose

  # Test without AI fixing (just report failures)
  %(prog)s --no-ai-fix

  # Clean up cached images and test fresh
  %(prog)s --cleanup-first

  # Save results to file
  %(prog)s --output results.json
        """
    )

    parser.add_argument("--distros", "-d",
                        help=f"Comma-separated list of distros to test (default: all)")
    parser.add_argument("--build", "-b", action="store_true", default=True,
                        help="Build policy from source (default: True)")
    parser.add_argument("--no-build", action="store_false", dest="build",
                        help="Skip building, assume policy .pp file exists")
    parser.add_argument("--output", "-o",
                        help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed output for each test")
    parser.add_argument("--cleanup", "-c", action="store_true",
                        help="Clean up test images after running")
    parser.add_argument("--cleanup-first", action="store_true",
                        help="Clean up test images before running (forces rebuild)")
    parser.add_argument("--cleanup-only", action="store_true",
                        help="Only clean up test images, don't run tests")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List available distros and exit")
    parser.add_argument("--fix", "-f", action="store_true",
                        help="Run selinux_fix.py to diagnose and suggest fixes for failures")
    parser.add_argument("--no-ai-fix", action="store_true",
                        help="Disable automatic AI fixing (AI fixing is enabled by default)")
    parser.add_argument("--ai-provider", type=str, default="claude",
                        help="AI CLI to use for fixing (default: claude)")

    args = parser.parse_args()

    if args.list:
        print("Available distributions for testing:")
        for distro, config in SELINUX_DISTROS.items():
            scc_note = " (requires SCC credentials)" if config.get("requires_scc") else ""
            default_note = " [default]" if distro in DEFAULT_DISTROS else ""
            print(f"  {distro}: {config['base_image']}{scc_note}{default_note}")
        print(f"\nDefault distros (no SCC required): {', '.join(DEFAULT_DISTROS)}")
        print(f"To test SLE, ensure ~/.secrets/scc_regcode exists with email= and regcode= lines")
        sys.exit(0)

    # Determine distros to test
    if args.distros:
        distros = [d.strip() for d in args.distros.split(',')]
        for d in distros:
            if d not in SELINUX_DISTROS:
                print(f"Error: Unknown distro '{d}'")
                print(f"Available: {', '.join(SELINUX_DISTROS.keys())}")
                sys.exit(1)
    else:
        distros = DEFAULT_DISTROS.copy()
        print(f"Note: Using default distros (excludes SLE which requires SCC credentials)")
        print(f"      To include SLE: --distros {','.join(DEFAULT_DISTROS)},sle16")

    # Find container runtime
    try:
        runtime = find_container_runtime()
        print(f"Using container runtime: {runtime}")
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Check SELinux source exists
    if not SELINUX_SRC.exists():
        print(f"Error: SELinux source directory not found: {SELINUX_SRC}")
        sys.exit(1)

    print(f"SELinux source: {SELINUX_SRC}")
    print(f"Testing distros: {', '.join(distros)}")

    # Handle cleanup-only mode
    if args.cleanup_only:
        print("\nCleaning up test images...")
        cleanup_images(runtime, distros)
        print("Done.")
        sys.exit(0)

    # Clean up first if requested (forces image rebuild)
    if args.cleanup_first:
        print("\nCleaning up existing test images...")
        cleanup_images(runtime, distros)

    # Setup AI runner (enabled by default)
    ai_runner = None
    ai_enabled = not args.no_ai_fix

    if ai_enabled:
        ai_runner = AIRunner(args.ai_provider)
        if not ai_runner.is_available():
            print_color(f"Warning: {args.ai_provider} CLI not found, AI fixing disabled", "yellow")
            print_color("Install with: npm install -g @anthropic-ai/claude-code", "yellow")
            ai_enabled = False
        else:
            print_color(f"AI-assisted fixing enabled using {args.ai_provider}", "green")

    # Run tests for each distro, fixing issues before moving on
    results = []

    for distro in distros:
        config = SELINUX_DISTROS[distro]

        # Keep testing this distro until it passes (or user skips)
        while True:
            result = run_test(runtime, distro, config, build=args.build)

            if args.verbose:
                print(f"\n--- Build Output ---")
                print(result.build_output[-1000:] if result.build_output else "(none)")
                print(f"\n--- Install Output ---")
                print(result.install_output[-1000:] if result.install_output else "(none)")

            if result.success:
                print_color(f"  Result: PASSED", "green")
                results.append(result)
                break  # Move to next distro

            print_color(f"  Result: FAILED", "red")

            # If AI fixing is disabled, just record failure and move on
            if not ai_enabled:
                results.append(result)
                break

            # Check if this is a policy error (vs container setup error)
            if not result.is_policy_error:
                print_color(f"  Error is not related to SELinux policy (container/image issue)", "yellow")
                print_color(f"  Details: {result.error_details}", "yellow")
                results.append(result)
                break

            # Get error output for AI - provide both build and install output for full context
            error_parts = []
            if result.build_output and result.build_output.strip():
                error_parts.append("=== BUILD OUTPUT ===\n" + result.build_output)
            if result.install_output and result.install_output.strip():
                error_parts.append("=== INSTALL OUTPUT ===\n" + result.install_output)

            if not error_parts:
                print_color("  No error output to analyze, skipping", "yellow")
                results.append(result)
                break

            error_output = "\n\n".join(error_parts)

            # Launch AI to fix
            print_color(f"\n{'=' * 70}", "cyan")
            print_color(f"LAUNCHING AI TO FIX: {distro}", "cyan")
            print_color(f"{'=' * 70}", "cyan")

            ai_runner.run_interactive(distro, error_output)

            # After AI exits, ask what to do
            print()
            print_color("AI session complete. What would you like to do?", "cyan")
            print("  [r] Retest this distro (default)")
            print("  [s] Skip this distro, move to next")
            print("  [q] Quit")

            try:
                choice = input("Choice [r/s/q] (default: r): ").strip().lower() or 'r'
            except (KeyboardInterrupt, EOFError):
                choice = 'q'

            if choice == 'r':
                print_color(f"\nRetesting {distro}...", "green")
                continue  # Retest same distro
            elif choice == 's':
                print_color(f"\nSkipping {distro}, moving to next...", "yellow")
                results.append(result)
                break  # Move to next distro
            elif choice == 'q':
                print_color("\nExiting.", "yellow")
                results.append(result)
                print_summary(results)
                sys.exit(1)
            else:
                # Default to retest
                print_color(f"\nRetesting {distro}...", "green")
                continue

    # Print final summary
    print_summary(results)

    # Run selinux_fix.py diagnosis if requested and there were failures
    failed_results = [r for r in results if not r.success]
    if args.fix and failed_results:
        print("\n" + "=" * 70)
        print("RUNNING SELINUX_FIX.PY DIAGNOSIS")
        print("=" * 70)

        # First, run --analyze to show general recommendations
        print("\n--- Policy Analysis (general recommendations) ---\n")
        analysis = run_selinux_fix_analyze()
        if analysis:
            print(analysis)

        # Then diagnose each failure
        for result in failed_results:
            if result.install_output:
                print(f"\n--- Diagnosis for {result.distro} ---\n")
                diagnosis = run_selinux_fix_diagnosis(result.install_output, result.distro)
                if diagnosis:
                    # Filter to show just the key parts (skip redundant analysis)
                    lines = diagnosis.split('\n')
                    in_diagnosis = False
                    for line in lines:
                        if 'DIAGNOSIS' in line or 'PROBLEMATIC LINES' in line or 'SUGGESTED FIXES' in line:
                            in_diagnosis = True
                        if in_diagnosis:
                            # Skip the "SPECIFIC RECOMMENDATIONS" section as we already showed analyze output
                            if 'SPECIFIC RECOMMENDATIONS' in line:
                                break
                            print(line)

    # Save results if requested
    if args.output:
        save_results(results, args.output)

    # Cleanup if requested
    if args.cleanup:
        print("Cleaning up test images...")
        cleanup_images(runtime, distros)

    # Exit with appropriate code
    if all(r.success for r in results):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
