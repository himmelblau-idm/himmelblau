#!/usr/bin/env python3
"""
SELinux Fix Helper for Himmelblau

This script helps diagnose and fix SELinux issues in Himmelblau by:
1. SSHing into a test machine and collecting audit denials
2. Accepting audit logs submitted by users
3. Parsing the denials and generating policy fixes
4. Diagnosing policy installation failures (semodule errors)
5. Updating the SELinux policy source files

Usage:
    # Interactive mode - SSH to machine and collect denials
    ./selinux_fix.py --host <hostname> [--user <username>]

    # Process audit logs from a file
    ./selinux_fix.py --audit-file <path>

    # Process audit logs from stdin
    cat audit.log | ./selinux_fix.py --stdin

    # Diagnose policy installation error from file
    ./selinux_fix.py --semodule-error <path>

    # Diagnose policy installation error from stdin
    semodule -vv -i himmelblaud.pp 2>&1 | ./selinux_fix.py --semodule-stdin
"""

import argparse
import subprocess
import sys
import re
import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


HIMMELBLAU_SERVICES = [
    "himmelblaud.service",
    "himmelblaud-tasks.service",
    "himmelblau-hsm-pin-init.service",
]

SELINUX_TE_PATH = Path(__file__).parent.parent / "src" / "selinux" / "src" / "himmelblaud.te"
SELINUX_SRC_DIR = Path(__file__).parent.parent / "src" / "selinux" / "src"

# Known Himmelblau domains that we manage
HIMMELBLAU_DOMAINS = {"himmelblaud_t", "himmelblaud_tasks_t"}

# Known Himmelblau types that we manage
HIMMELBLAU_TYPES = {
    "himmelblaud_t",
    "himmelblaud_tasks_t",
    "himmelblaud_exec_t",
    "himmelblaud_tasks_exec_t",
    "himmelblau_etc_t",
    "himmelblau_var_run_t",
    "himmelblau_var_cache_t",
    "himmelblau_nss_cache_t",
    "himmelblau_var_lib_t",
}


@dataclass
class AVCDenial:
    """Represents a parsed AVC denial from audit logs."""
    source_domain: str
    target_type: str
    object_class: str
    permissions: set = field(default_factory=set)
    raw_line: str = ""

    def __hash__(self):
        return hash((self.source_domain, self.target_type, self.object_class))

    def __eq__(self, other):
        if not isinstance(other, AVCDenial):
            return False
        return (self.source_domain == other.source_domain and
                self.target_type == other.target_type and
                self.object_class == other.object_class)


@dataclass
class PolicyInstallError:
    """Represents a parsed semodule installation error."""
    error_type: str  # e.g., "typeattributeset", "allow", "typetransition"
    cil_file: str
    cil_line: int
    raw_error: str
    context_lines: list[str] = field(default_factory=list)


def needs_sudo(user: Optional[str]) -> bool:
    """Check if we need to use sudo for privileged operations."""
    # If user is explicitly root, no sudo needed
    if user == "root":
        return False
    # If no user specified, we don't know - assume sudo is needed
    return True


def run_ssh_command(host: str, user: str, command: str, sudo: bool = False) -> tuple[int, str, str]:
    """Run a command on a remote host via SSH."""
    ssh_target = f"{user}@{host}" if user else host
    if sudo and needs_sudo(user):
        command = f"sudo {command}"

    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new", ssh_target, command],
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def run_ssh_interactive(host: str, user: str, command: str, sudo: bool = False) -> int:
    """Run a command on a remote host interactively (for password prompts, etc.)."""
    ssh_target = f"{user}@{host}" if user else host
    if sudo and needs_sudo(user):
        command = f"sudo {command}"

    result = subprocess.run(
        ["ssh", "-t", "-o", "StrictHostKeyChecking=accept-new", ssh_target, command]
    )
    return result.returncode


def run_ssh_interactive_capture(host: str, user: str, command: str, sudo: bool = False) -> tuple[int, str]:
    """
    Run a command interactively (with TTY for sudo) but also capture output.

    Uses a temp file on the remote host to capture output while still allowing
    interactive password prompts.

    Returns (returncode, output).
    """
    ssh_target = f"{user}@{host}" if user else host
    temp_file = "/tmp/selinux_fix_output.txt"

    # Build the command that saves output to a temp file
    if sudo and needs_sudo(user):
        # Run with sudo, tee output to temp file so user sees it AND it's captured
        wrapper_cmd = f"sudo sh -c '{command}' 2>&1 | tee {temp_file}; echo \"__EXIT_CODE__${{PIPESTATUS[0]}}__\" >> {temp_file}"
    else:
        wrapper_cmd = f"sh -c '{command}' 2>&1 | tee {temp_file}; echo \"__EXIT_CODE__${{PIPESTATUS[0]}}__\" >> {temp_file}"

    # Run interactively (user sees output and can enter password)
    subprocess.run(
        ["ssh", "-t", "-o", "StrictHostKeyChecking=accept-new", ssh_target, wrapper_cmd]
    )

    # Now fetch the captured output from the temp file
    rc, stdout, _ = run_ssh_command(host, user, f"cat {temp_file} 2>/dev/null; rm -f {temp_file}", sudo=False)

    # Extract exit code from output
    exit_code = 1  # Default to failure
    output_lines = []
    for line in stdout.split('\n'):
        if line.startswith("__EXIT_CODE__") and line.endswith("__"):
            try:
                exit_code = int(line.replace("__EXIT_CODE__", "").replace("__", ""))
            except ValueError:
                pass
        else:
            output_lines.append(line)

    return exit_code, '\n'.join(output_lines)


def check_selinux_status(host: str, user: str) -> tuple[bool, str]:
    """Check if SELinux is enabled and get its mode."""
    # getenforce is typically in /usr/sbin which may not be in PATH for non-root users
    rc, stdout, _ = run_ssh_command(host, user, "/usr/sbin/getenforce 2>/dev/null || getenforce", sudo=False)
    if rc != 0:
        return False, "unknown"
    mode = stdout.strip().lower()
    return mode != "disabled", mode


def detect_distro(host: str, user: str) -> dict:
    """Detect the Linux distribution on the remote host."""
    distro_info = {
        "id": "unknown",
        "version": "",
        "name": "Unknown",
        "family": "unknown",  # rhel, suse
    }

    # Try to read /etc/os-release
    rc, stdout, _ = run_ssh_command(host, user, "cat /etc/os-release 2>/dev/null", sudo=False)
    if rc == 0 and stdout:
        for line in stdout.split('\n'):
            if line.startswith('ID='):
                distro_info["id"] = line.split('=', 1)[1].strip('"').lower()
            elif line.startswith('VERSION_ID='):
                distro_info["version"] = line.split('=', 1)[1].strip('"')
            elif line.startswith('NAME='):
                distro_info["name"] = line.split('=', 1)[1].strip('"')

    # Determine family (only RHEL and SUSE families supported)
    rhel_family = ["rhel", "centos", "rocky", "almalinux", "fedora", "oracle"]
    suse_family = ["opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"]

    distro_id = distro_info["id"]
    if any(d in distro_id for d in rhel_family):
        distro_info["family"] = "rhel"
    elif any(d in distro_id for d in suse_family):
        distro_info["family"] = "suse"

    return distro_info


def check_selinux_installed(host: str, user: str) -> tuple[bool, str]:
    """Check if SELinux packages are installed."""
    # Check if getenforce exists (typically in /usr/sbin which may not be in PATH)
    rc, stdout, _ = run_ssh_command(host, user, "test -x /usr/sbin/getenforce || which getenforce 2>/dev/null", sudo=False)
    if rc != 0:
        return False, "getenforce command not found"

    # Check if /etc/selinux/config exists
    rc, stdout, _ = run_ssh_command(host, user, "test -f /etc/selinux/config && echo exists", sudo=False)
    if rc != 0 or "exists" not in stdout:
        return False, "/etc/selinux/config not found"

    # Check if policy is installed
    rc, stdout, _ = run_ssh_command(host, user, "test -d /etc/selinux/targeted && echo exists", sudo=False)
    if rc != 0 or "exists" not in stdout:
        return False, "SELinux targeted policy not installed"

    return True, "SELinux appears to be installed"


def get_selinux_packages(distro: dict) -> tuple[str, list[str]]:
    """Get the package manager command and SELinux packages for the distro."""
    family = distro["family"]

    if family == "rhel":
        # Use dnf for Fedora and RHEL 8+, yum for older
        use_dnf = distro["id"] == "fedora" or (distro["version"] and int(distro["version"].split('.')[0]) >= 8)
        pkg_cmd = "dnf install -y" if use_dnf else "yum install -y"
        packages = [
            "selinux-policy-targeted",
            "selinux-policy-devel",
            "policycoreutils",
            "policycoreutils-python-utils",
            "libselinux-utils",
        ]
        return pkg_cmd, packages

    elif family == "suse":
        packages = [
            "selinux-policy-targeted",
            "selinux-policy-devel",
            "policycoreutils",
            "selinux-tools",
        ]
        return "zypper install -y", packages

    else:
        return "", []


def install_selinux(host: str, user: str) -> tuple[bool, str]:
    """Install SELinux packages on the remote host."""
    print("\n=== Installing SELinux ===")

    # Detect distro
    distro = detect_distro(host, user)
    print(f"  Detected: {distro['name']} ({distro['id']} {distro['version']})")
    print(f"  Family: {distro['family']}")

    if distro["family"] == "unknown":
        return False, "Could not detect distribution. Please install SELinux manually."

    pkg_cmd, packages = get_selinux_packages(distro)
    if not packages:
        return False, f"No SELinux packages defined for {distro['name']}. Please install manually."

    print(f"\n  The following packages will be installed:")
    for pkg in packages:
        print(f"    - {pkg}")

    confirm = input("\n  Proceed with installation? [Y/n]: ").strip().lower()
    if confirm == 'n':
        return False, "Installation cancelled by user."

    # Build the install command
    install_cmd = f"{pkg_cmd} {' '.join(packages)}"
    print(f"\n  Running: {install_cmd}")
    print("  (This may take a while...)\n")

    # Use interactive SSH for package installation (needs sudo password)
    rc = run_ssh_interactive(host, user, install_cmd, sudo=True)

    if rc != 0:
        return False, "Package installation failed. Please check the output above."

    return True, "SELinux packages installed successfully."


def enable_selinux(host: str, user: str) -> tuple[bool, str]:
    """
    Attempt to enable SELinux on the target system.

    Returns (success, message) tuple.
    """
    print("\n=== Attempting to enable SELinux ===")

    # First check if SELinux is installed
    installed, status_msg = check_selinux_installed(host, user)
    if not installed:
        print(f"\n  SELinux does not appear to be fully installed: {status_msg}")
        install_choice = input("  Would you like to install SELinux packages? [Y/n]: ").strip().lower()
        if install_choice != 'n':
            success, msg = install_selinux(host, user)
            if not success:
                return False, msg
            print(f"\n  {msg}")
        else:
            return False, "SELinux is not installed. Please install manually."

    # Check current config
    rc, stdout, _ = run_ssh_command(
        host, user,
        "cat /etc/selinux/config 2>/dev/null | grep -E '^SELINUX='",
        sudo=False  # Try without sudo first - file should be world-readable
    )

    current_config = stdout.strip() if rc == 0 and stdout.strip() else ""
    if not current_config:
        # Try with sudo
        rc, stdout, _ = run_ssh_command(host, user, "cat /etc/selinux/config 2>/dev/null | grep -E '^SELINUX='", sudo=True)
        current_config = stdout.strip() if rc == 0 else ""

    print(f"  Current config: {current_config or 'Could not read (file may not exist)'}")

    if not current_config:
        print("\n  /etc/selinux/config may not exist or is empty.")
        print("  This typically means SELinux was never configured on this system.")
        return False, "SELinux config file not found. Please ensure SELinux is properly installed."

    # Check what mode to enable
    print("\n  SELinux can be enabled in:")
    print("    1. Permissive mode (logs violations but doesn't block)")
    print("    2. Enforcing mode (logs and blocks violations)")
    print()
    choice = input("  Select mode [1/2] (default: 1 - Permissive): ").strip() or "1"

    new_mode = "permissive" if choice == "1" else "enforcing"

    # Update /etc/selinux/config using interactive SSH (for sudo password)
    print(f"\n  Setting SELINUX={new_mode} in /etc/selinux/config...")

    # Use interactive SSH for the sed command since it needs sudo
    rc = run_ssh_interactive(
        host, user,
        f"sed -i 's/^SELINUX=.*/SELINUX={new_mode}/' /etc/selinux/config",
        sudo=True
    )

    if rc != 0:
        return False, "Failed to update /etc/selinux/config"

    # Verify the change
    rc, stdout, _ = run_ssh_command(
        host, user,
        "grep -E '^SELINUX=' /etc/selinux/config",
        sudo=False
    )

    new_config = stdout.strip() if rc == 0 else ""
    print(f"  Updated config: {new_config}")

    if f"SELINUX={new_mode}" not in new_config:
        return False, "Config update may have failed - please verify manually"

    # Check if we can enable it immediately (only if transitioning from permissive)
    # Note: If SELinux was disabled at boot, a reboot is required
    rc, stdout, _ = run_ssh_command(host, user, "/usr/sbin/getenforce 2>/dev/null || getenforce", sudo=False)
    current_mode = stdout.strip().lower() if rc == 0 else "unknown"

    if current_mode == "disabled" or current_mode == "unknown":
        print("\n  SELinux is currently disabled at the kernel level.")
        print("  A REBOOT is required to enable SELinux.")
        print()
        reboot = input("  Would you like to reboot now? [y/N]: ").strip().lower()
        if reboot == 'y':
            print("  Rebooting system...")
            run_ssh_interactive(host, user, "reboot", sudo=True)
            return True, "System is rebooting. Please wait and reconnect after reboot."
        else:
            return True, f"Config updated to {new_mode}. Please reboot to enable SELinux."

    elif current_mode == "permissive" and new_mode == "enforcing":
        # Can switch to enforcing immediately
        print("  Switching to enforcing mode...")
        rc = run_ssh_interactive(host, user, "/usr/sbin/setenforce 1", sudo=True)
        if rc != 0:
            return False, "Failed to set enforcing mode"
        return True, "SELinux is now in enforcing mode."

    elif current_mode == "enforcing" and new_mode == "permissive":
        # Can switch to permissive immediately
        print("  Switching to permissive mode...")
        rc = run_ssh_interactive(host, user, "/usr/sbin/setenforce 0", sudo=True)
        if rc != 0:
            return False, "Failed to set permissive mode"
        return True, "SELinux is now in permissive mode."

    return True, f"SELinux config updated to {new_mode}."


def restart_services(host: str, user: str) -> bool:
    """Restart Himmelblau services on the remote host."""
    print("\n=== Restarting Himmelblau services ===")
    for service in HIMMELBLAU_SERVICES:
        print(f"  Restarting {service}...")
        rc, output = run_ssh_interactive_capture(host, user, f"systemctl restart {service}", sudo=True)
        if rc != 0:
            # Some services might not exist or might be oneshot that completed
            if "not found" in output.lower() or "could not be found" in output.lower():
                print(f"    Service {service} not found, skipping")
            else:
                print(f"    Warning: {service} returned code {rc}")
    return True


def check_service_status(host: str, user: str) -> dict[str, tuple[bool, str]]:
    """Check the status of Himmelblau services."""
    statuses = {}
    for service in HIMMELBLAU_SERVICES:
        rc, stdout, _ = run_ssh_command(host, user, f"systemctl is-active {service}", sudo=False)
        is_active = stdout.strip() == "active"
        statuses[service] = (is_active, stdout.strip())
    return statuses


def collect_audit_denials(host: str, user: str, since: str = "5 minutes ago") -> str:
    """Collect SELinux audit denials from the remote host."""
    print(f"\n=== Collecting audit denials (since {since}) ===")

    # Try ausearch first (more reliable for SELinux) - needs sudo for audit log access
    rc, stdout = run_ssh_interactive_capture(
        host, user,
        f"ausearch -m avc -ts recent 2>/dev/null || journalctl -t audit --since '{since}' 2>/dev/null || cat /var/log/audit/audit.log 2>/dev/null | tail -500",
        sudo=True
    )

    if rc == 0 and stdout.strip():
        return stdout

    # Fallback: try to get from audit.log directly
    rc, stdout = run_ssh_interactive_capture(
        host, user,
        "tail -1000 /var/log/audit/audit.log 2>/dev/null | grep -E 'avc:|AVC'",
        sudo=True
    )
    return stdout


def parse_audit2allow_output(audit_log: str) -> str:
    """Run audit2allow on the audit log and return the generated rules."""
    try:
        result = subprocess.run(
            ["audit2allow", "-m", "himmelblaud"],
            input=audit_log,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout
        else:
            # audit2allow can fail for various reasons (missing policy file, etc.)
            # Just skip it silently - our own parsing is the primary method
            return ""
    except FileNotFoundError:
        # audit2allow not installed - that's fine, we don't require it
        return ""


def parse_avc_denials(audit_log: str) -> list[AVCDenial]:
    """Parse AVC denials from audit log content."""
    denials = {}

    # Pattern to match AVC denial lines
    # Example: type=AVC msg=audit(...): avc:  denied  { read } for  pid=1234 comm="himmelblaud" name="passwd" dev="dm-0" ino=123 scontext=system_u:system_r:himmelblaud_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file
    avc_pattern = re.compile(
        r'avc:\s+denied\s+\{\s*([^}]+)\s*\}.*?'
        r'scontext=\S+:(\w+):(\w+):\S+\s+'
        r'tcontext=\S+:\w+:(\w+):\S+\s+'
        r'tclass=(\w+)',
        re.IGNORECASE
    )

    for line in audit_log.split('\n'):
        match = avc_pattern.search(line)
        if match:
            permissions = set(match.group(1).split())
            source_role = match.group(2)
            source_domain = match.group(3)
            target_type = match.group(4)
            object_class = match.group(5)

            key = (source_domain, target_type, object_class)
            if key in denials:
                denials[key].permissions.update(permissions)
            else:
                denials[key] = AVCDenial(
                    source_domain=source_domain,
                    target_type=target_type,
                    object_class=object_class,
                    permissions=permissions,
                    raw_line=line
                )

    return list(denials.values())


def categorize_denials(denials: list[AVCDenial]) -> dict[str, list[AVCDenial]]:
    """Categorize denials by their relevance to Himmelblau."""
    categories = {
        "himmelblau_outbound": [],      # Himmelblau domain accessing other types
        "himmelblau_inbound": [],       # Other domains accessing Himmelblau types
        "himmelblau_internal": [],      # Himmelblau domains accessing Himmelblau types
        "unrelated": [],                # No Himmelblau involvement
    }

    for denial in denials:
        is_himmelblau_source = denial.source_domain in HIMMELBLAU_DOMAINS
        is_himmelblau_target = denial.target_type in HIMMELBLAU_TYPES

        if is_himmelblau_source and is_himmelblau_target:
            categories["himmelblau_internal"].append(denial)
        elif is_himmelblau_source:
            categories["himmelblau_outbound"].append(denial)
        elif is_himmelblau_target:
            categories["himmelblau_inbound"].append(denial)
        else:
            categories["unrelated"].append(denial)

    return categories


def generate_allow_rules(denials: list[AVCDenial]) -> list[str]:
    """Generate SELinux allow rules from denials."""
    rules = []
    for denial in denials:
        perms = " ".join(sorted(denial.permissions))
        rule = f"allow {denial.source_domain} {denial.target_type}:{denial.object_class} {{ {perms} }};"
        rules.append(rule)
    return rules


def format_rules_for_policy(rules: list[str], category: str) -> str:
    """Format rules with appropriate comments for the policy file."""
    if not rules:
        return ""

    output = []
    output.append(f"\n# {category}")
    output.append("# Generated by selinux_fix.py - please review before committing")
    for rule in sorted(rules):
        output.append(rule)

    return "\n".join(output)


def read_current_policy() -> str:
    """Read the current SELinux policy file."""
    if SELINUX_TE_PATH.exists():
        return SELINUX_TE_PATH.read_text()
    return ""


def find_insertion_point(policy_content: str) -> int:
    """Find the best place to insert new rules in the policy."""
    # Look for the "Audit2allow discovered rules" section
    marker = "# Audit2allow discovered rules"
    idx = policy_content.find(marker)
    if idx != -1:
        # Find the end of this section (next major section or EOF)
        lines = policy_content[idx:].split('\n')
        offset = 0
        for i, line in enumerate(lines[1:], 1):  # Skip the marker line
            # Look for end of file or a line that starts a new major section
            if line.startswith("# ") and not line.startswith("# allow") and not line.startswith("# Generated"):
                break
            offset = idx + sum(len(l) + 1 for l in lines[:i])
        return offset

    # Fallback: insert before the last line
    return len(policy_content.rstrip())


def check_rule_exists(policy_content: str, denial: AVCDenial) -> set[str]:
    """Check which permissions from a denial are already covered by existing rules."""
    # Pattern to find existing allow rules for this source/target/class combination
    pattern = re.compile(
        rf'allow\s+{re.escape(denial.source_domain)}\s+{re.escape(denial.target_type)}:{re.escape(denial.object_class)}\s+\{{\s*([^}}]+)\s*\}}'
    )

    existing_perms = set()
    for match in pattern.finditer(policy_content):
        existing_perms.update(match.group(1).split())

    return existing_perms


@dataclass
class RuleLocation:
    """Information about a rule's location in the policy file."""
    line_num: int
    start_pos: int
    end_pos: int
    full_match: str
    permissions: set[str]
    in_optional_block: bool = False
    optional_block_start: int = 0


def find_existing_rule(policy_content: str, source: str, target: str, obj_class: str) -> Optional[RuleLocation]:
    """
    Find an existing allow rule for the given source/target/class combination.

    Returns RuleLocation with position info, or None if not found.
    """
    pattern = re.compile(
        rf'allow\s+{re.escape(source)}\s+{re.escape(target)}:{re.escape(obj_class)}\s+\{{\s*([^}}]+)\s*\}};'
    )

    for match in pattern.finditer(policy_content):
        # Calculate line number
        line_num = policy_content[:match.start()].count('\n') + 1
        permissions = set(match.group(1).split())

        # Check if this rule is inside an optional block
        # Look backwards for 'optional {' without a closing '}'
        before_match = policy_content[:match.start()]
        in_optional = False
        optional_start = 0

        # Find the last 'optional {' before this rule
        opt_pattern = re.compile(r'optional\s*\{')
        for opt_match in opt_pattern.finditer(before_match):
            # Check if there's a closing '}' between this optional and our rule
            between = before_match[opt_match.end():]
            # Count braces to see if we're still inside
            brace_count = 1
            for i, char in enumerate(between):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        break
            if brace_count > 0:
                in_optional = True
                optional_start = opt_match.start()

        return RuleLocation(
            line_num=line_num,
            start_pos=match.start(),
            end_pos=match.end(),
            full_match=match.group(0),
            permissions=permissions,
            in_optional_block=in_optional,
            optional_block_start=optional_start
        )

    return None


def find_optional_block_for_type(policy_content: str, type_name: str) -> Optional[tuple[int, int]]:
    """
    Find an optional block that requires the given type.

    Returns (block_start_pos, block_end_pos) or None if not found.
    """
    # Pattern to find optional blocks with require for this type
    # Looking for:
    # optional {
    #     require {
    #         type type_name;
    #     }
    #     ...
    # }
    pattern = re.compile(
        rf'optional\s*\{{\s*require\s*\{{\s*type\s+{re.escape(type_name)}\s*;',
        re.MULTILINE
    )

    match = pattern.search(policy_content)
    if not match:
        return None

    # Find the end of this optional block by counting braces
    block_start = match.start()
    brace_count = 0
    block_end = block_start

    for i, char in enumerate(policy_content[block_start:]):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                block_end = block_start + i + 1
                break

    return (block_start, block_end)


def find_insertion_point_in_optional_block(policy_content: str, block_start: int, block_end: int) -> int:
    """
    Find the best place to insert a new rule within an optional block.

    Returns position just before the closing brace of the block.
    """
    # Find the last '}' which closes the block
    block_content = policy_content[block_start:block_end]

    # Find the position just before the final '}'
    # We want to insert before the closing brace but after the last rule
    last_brace = block_content.rfind('}')
    if last_brace == -1:
        return block_end

    # Find the last newline before the closing brace
    insert_pos = block_start + last_brace
    # Back up to include proper indentation
    while insert_pos > block_start and policy_content[insert_pos - 1] in ' \t':
        insert_pos -= 1

    return insert_pos


def merge_permissions_into_rule(policy_content: str, rule_loc: RuleLocation, new_perms: set[str]) -> str:
    """
    Merge new permissions into an existing rule.

    Returns the updated policy content.
    """
    # Combine existing and new permissions
    all_perms = rule_loc.permissions | new_perms
    sorted_perms = " ".join(sorted(all_perms))

    # Build the new rule (we need to reconstruct it from the match)
    # Extract source, target, class from the original match
    rule_pattern = re.compile(
        r'allow\s+(\S+)\s+(\S+):(\S+)\s+\{\s*[^}]+\s*\};'
    )
    match = rule_pattern.match(rule_loc.full_match)
    if not match:
        # Fallback: just return unchanged
        return policy_content

    source, target, obj_class = match.groups()
    new_rule = f"allow {source} {target}:{obj_class} {{ {sorted_perms} }};"

    # Replace the old rule with the new one
    return policy_content[:rule_loc.start_pos] + new_rule + policy_content[rule_loc.end_pos:]


def get_indent_at_position(policy_content: str, position: int) -> str:
    """Get the indentation used at a given position in the file."""
    # Find the start of the line
    line_start = policy_content.rfind('\n', 0, position)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    # Extract leading whitespace
    indent = ""
    for char in policy_content[line_start:position]:
        if char in ' \t':
            indent += char
        else:
            break

    return indent if indent else "\t"


def create_optional_block_for_type(type_name: str, rules: list[str], indent: str = "") -> str:
    """
    Create a new optional block for rules involving an external type.

    Args:
        type_name: The external type that needs to be required
        rules: List of allow rules to include
        indent: Base indentation for the block
    """
    lines = [
        f"{indent}#============= {type_name} ==============",
        f"{indent}optional {{",
        f"{indent}\trequire {{",
        f"{indent}\t\ttype {type_name};",
        f"{indent}\t}}",
    ]

    for rule in sorted(rules):
        lines.append(f"{indent}\t{rule}")

    lines.append(f"{indent}}}")
    lines.append("")

    return "\n".join(lines)


def prompt_test_authentication(host: str, user: str):
    """Prompt the user to authenticate on the remote system to exercise the code."""
    print("\n=== Authentication Test ===")
    print("To generate SELinux denials, you may want to test authentication.")
    print("Options:")
    print("  1. Run 'su - <entra_user>' to test PAM authentication")
    print("  2. Run 'getent passwd <entra_user>' to test NSS")
    print("  3. Run 'id <entra_user>' to test user lookup")
    print("  4. Skip authentication test")
    print()

    choice = input("Enter choice (1-4) [4]: ").strip() or "4"

    if choice == "1":
        entra_user = input("Enter Entra user to authenticate as: ").strip()
        if entra_user:
            print(f"\nConnecting to {host} to run 'su - {entra_user}'...")
            print("(You will be prompted for the user's password)")
            run_ssh_interactive(host, user, f"su - {entra_user} -c 'id; exit'", sudo=True)
    elif choice == "2":
        entra_user = input("Enter Entra user to look up: ").strip()
        if entra_user:
            rc, stdout, stderr = run_ssh_command(host, user, f"getent passwd {entra_user}")
            print(f"Result: {stdout or stderr}")
    elif choice == "3":
        entra_user = input("Enter Entra user to look up: ").strip()
        if entra_user:
            rc, stdout, stderr = run_ssh_command(host, user, f"id {entra_user}")
            print(f"Result: {stdout or stderr}")


def interactive_mode(host: str, user: str, apply: bool = False):
    """Run in interactive mode, SSHing to a machine and collecting denials."""
    print(f"=== SELinux Fix Helper for Himmelblau ===")
    print(f"Target host: {host}")
    print(f"User: {user or '(current user)'}")

    # Check SELinux status
    enabled, mode = check_selinux_status(host, user)
    if not enabled:
        print("\nWarning: SELinux is disabled on the target system.")
        print("Options:")
        print("  1. Attempt to enable SELinux")
        print("  2. Continue anyway (limited functionality)")
        print("  3. Exit")
        choice = input("Select option [1/2/3] (default: 1): ").strip() or "1"

        if choice == "1":
            success, message = enable_selinux(host, user)
            print(f"\n{message}")
            if not success:
                print("Failed to enable SELinux. Please fix manually and retry.")
                return
            if "reboot" in message.lower():
                # System is rebooting or needs reboot
                return
            # Re-check status after enabling
            enabled, mode = check_selinux_status(host, user)
            if not enabled:
                print("SELinux is still not enabled. A reboot may be required.")
                return
        elif choice == "3":
            return
        # choice == "2" falls through to continue

    print(f"SELinux mode: {mode}")

    # Check if policy is installed
    print("\n=== Checking Policy Installation ===")
    installed, version = check_policy_installed(host, user)
    if installed:
        print(f"Policy module installed: {version}")
    else:
        print("Policy module is NOT installed!")
        print("\nWould you like to diagnose the installation issue?")
        choice = input("Diagnose policy installation? [Y/n]: ").strip().lower()
        if choice != 'n':
            diagnose_policy_installation(host, user)
            return

    # Restart services
    restart_services(host, user)

    # Check service status
    print("\n=== Service Status ===")
    statuses = check_service_status(host, user)
    for service, (is_active, status) in statuses.items():
        indicator = "✓" if is_active else "✗"
        print(f"  {indicator} {service}: {status}")

    # Prompt for authentication test
    prompt_test_authentication(host, user)

    # Collect denials
    audit_log = collect_audit_denials(host, user)
    if not audit_log.strip():
        print("\nNo audit denials found. The services may be working correctly,")
        print("or SELinux auditing may not be capturing the events.")
        return

    process_audit_log(audit_log, apply)


def process_audit_log(audit_log: str, apply: bool = False):
    """Process audit log content and generate/apply fixes."""
    print("\n=== Parsing Audit Denials ===")

    # Parse denials
    denials = parse_avc_denials(audit_log)
    if not denials:
        print("No AVC denials found in the audit log.")
        # Try audit2allow as a fallback
        print("\nTrying audit2allow for additional analysis...")
        audit2allow_output = parse_audit2allow_output(audit_log)
        if audit2allow_output:
            print("\naudit2allow suggests:")
            print(audit2allow_output)
        return

    print(f"Found {len(denials)} unique denial(s)")

    # Categorize
    categories = categorize_denials(denials)

    # Read current policy
    current_policy = read_current_policy()

    # Process each category
    all_new_rules = []

    for category_name, category_denials in categories.items():
        if not category_denials:
            continue

        if category_name == "unrelated":
            print(f"\n=== Unrelated denials (not Himmelblau) - {len(category_denials)} ===")
            for d in category_denials:
                print(f"  {d.source_domain} -> {d.target_type}:{d.object_class} {{ {' '.join(d.permissions)} }}")
            continue

        print(f"\n=== {category_name.replace('_', ' ').title()} - {len(category_denials)} ===")

        for denial in category_denials:
            existing_perms = check_rule_exists(current_policy, denial)
            new_perms = denial.permissions - existing_perms

            if existing_perms:
                print(f"  {denial.source_domain} -> {denial.target_type}:{denial.object_class}")
                print(f"    Existing permissions: {' '.join(sorted(existing_perms))}")
                if new_perms:
                    print(f"    NEW permissions needed: {' '.join(sorted(new_perms))}")
                    denial.permissions = new_perms
                    all_new_rules.append(denial)
                else:
                    print(f"    All permissions already covered")
            else:
                print(f"  NEW: {denial.source_domain} -> {denial.target_type}:{denial.object_class} {{ {' '.join(sorted(denial.permissions))} }}")
                all_new_rules.append(denial)

    if not all_new_rules:
        print("\n=== No new rules needed ===")
        print("All detected denials are already covered by the existing policy.")
        return

    # Generate rules
    print("\n=== Generated Rules ===")
    rules = generate_allow_rules(all_new_rules)
    for rule in sorted(rules):
        print(f"  {rule}")

    # Also show audit2allow output for comparison (if available)
    audit2allow_output = parse_audit2allow_output(audit_log)
    if audit2allow_output:
        print("\n=== audit2allow output (for reference) ===")
        # Extract just the allow rules
        for line in audit2allow_output.split('\n'):
            if line.strip().startswith('allow ') or line.strip().startswith('#'):
                print(f"  {line}")

    if apply:
        print("\n=== Applying rules to policy ===")
        apply_rules_to_policy(all_new_rules, current_policy)
    else:
        print("\n=== To apply these rules ===")
        print(f"Run with --apply flag, or manually add to:")
        print(f"  {SELINUX_TE_PATH}")
        print("\nAlternatively, copy these rules:")
        print("-" * 60)
        for rule in sorted(rules):
            print(rule)
        print("-" * 60)


def apply_rules_to_policy(denials: list[AVCDenial], current_policy: str):
    """
    Apply the generated rules to the policy file by merging with existing rules.

    Strategy:
    1. For denials where a matching rule exists: merge new permissions into existing rule
    2. For denials where an optional block exists for the source type: add rule to that block
    3. For completely new types: create new optional blocks or append at end
    """
    if not SELINUX_TE_PATH.exists():
        print(f"Error: Policy file not found at {SELINUX_TE_PATH}")
        return

    updated_policy = current_policy
    merged_count = 0
    added_to_block_count = 0
    new_block_rules: dict[str, list[str]] = {}  # type -> rules needing new optional blocks
    append_rules: list[str] = []  # Rules for Himmelblau's own types (no optional block needed)

    for denial in denials:
        rule_str = f"allow {denial.source_domain} {denial.target_type}:{denial.object_class} {{ {' '.join(sorted(denial.permissions))} }};"

        # Strategy 1: Try to find and merge with existing rule
        rule_loc = find_existing_rule(
            updated_policy,
            denial.source_domain,
            denial.target_type,
            denial.object_class
        )

        if rule_loc:
            # Merge permissions into existing rule
            updated_policy = merge_permissions_into_rule(updated_policy, rule_loc, denial.permissions)
            print(f"  Merged: {denial.source_domain} -> {denial.target_type}:{denial.object_class} "
                  f"(added: {' '.join(sorted(denial.permissions))})")
            merged_count += 1
            continue

        # Strategy 2: Check if source is a Himmelblau domain (no optional block needed)
        if denial.source_domain in HIMMELBLAU_DOMAINS:
            # This is a rule for himmelblaud accessing something - doesn't need optional block
            # unless the target is an external type
            if denial.target_type not in HIMMELBLAU_TYPES:
                # External target type - needs optional block keyed by target
                if denial.target_type not in new_block_rules:
                    new_block_rules[denial.target_type] = []
                new_block_rules[denial.target_type].append(rule_str)
            else:
                # Both source and target are Himmelblau types - just append
                append_rules.append(rule_str)
            continue

        # Strategy 3: Try to find an existing optional block for this source type
        block_loc = find_optional_block_for_type(updated_policy, denial.source_domain)

        if block_loc:
            # Add rule to existing optional block
            block_start, block_end = block_loc
            insert_pos = find_insertion_point_in_optional_block(updated_policy, block_start, block_end)
            indent = get_indent_at_position(updated_policy, insert_pos)

            # Insert the new rule
            new_rule_line = f"\n{indent}{rule_str}"
            updated_policy = updated_policy[:insert_pos] + new_rule_line + updated_policy[insert_pos:]

            print(f"  Added to existing block: {denial.source_domain} -> {denial.target_type}:{denial.object_class}")
            added_to_block_count += 1
            continue

        # Strategy 4: Need to create a new optional block for this external source type
        if denial.source_domain not in new_block_rules:
            new_block_rules[denial.source_domain] = []
        new_block_rules[denial.source_domain].append(rule_str)

    # Now handle rules that need new optional blocks
    if new_block_rules:
        # Find the best place to add new optional blocks
        # Look for the last optional block in the file and add after it
        last_optional_end = 0
        opt_pattern = re.compile(r'optional\s*\{')
        for match in opt_pattern.finditer(updated_policy):
            # Find the end of this optional block
            brace_count = 0
            for i, char in enumerate(updated_policy[match.start():]):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = match.start() + i + 1
                        if end_pos > last_optional_end:
                            last_optional_end = end_pos
                        break

        # If we found optional blocks, insert after the last one
        # Otherwise, use the standard insertion point
        if last_optional_end > 0:
            insertion_point = last_optional_end
            # Skip any trailing whitespace/newlines
            while insertion_point < len(updated_policy) and updated_policy[insertion_point] in ' \t\n':
                insertion_point += 1
            # Back up to include one newline
            if insertion_point > last_optional_end:
                insertion_point = last_optional_end
        else:
            insertion_point = find_insertion_point(updated_policy)

        # Create new optional blocks
        new_blocks = []
        for type_name, rules in sorted(new_block_rules.items()):
            block = create_optional_block_for_type(type_name, rules)
            new_blocks.append(block)
            print(f"  Created new optional block for {type_name} with {len(rules)} rule(s)")

        # Insert all new blocks
        new_content = "\n\n" + "\n".join(new_blocks)
        updated_policy = updated_policy[:insertion_point] + new_content + updated_policy[insertion_point:]

    # Handle rules that don't need optional blocks (Himmelblau internal rules)
    if append_rules:
        # These go in a general section, not in optional blocks
        insertion_point = find_insertion_point(updated_policy)
        formatted = format_rules_for_policy(append_rules, "Himmelblau internal rules added by selinux_fix.py")
        updated_policy = updated_policy[:insertion_point] + formatted + "\n" + updated_policy[insertion_point:]
        print(f"  Appended {len(append_rules)} internal rule(s)")

    # Write back
    SELINUX_TE_PATH.write_text(updated_policy)

    # Summary
    total = merged_count + added_to_block_count + sum(len(r) for r in new_block_rules.values()) + len(append_rules)
    print(f"\nUpdated {SELINUX_TE_PATH}")
    print(f"  - Merged into existing rules: {merged_count}")
    print(f"  - Added to existing optional blocks: {added_to_block_count}")
    print(f"  - Created new optional blocks: {len(new_block_rules)}")
    if append_rules:
        print(f"  - Appended internal rules: {len(append_rules)}")
    print("\nPlease review the changes and rebuild the SELinux module.")


###############################################################################
# Policy Installation Error Diagnosis
###############################################################################

def parse_semodule_error(error_output: str) -> list[PolicyInstallError]:
    """Parse semodule error output to identify policy installation failures."""
    errors = []

    # Pattern for himmelblaud-specific errors (not in optional blocks)
    # Example: Failed to resolve typeattributeset statement at /var/lib/selinux/targeted/tmp/modules/400/himmelblaud/cil:56
    error_pattern = re.compile(
        r'Failed to resolve (\w+) statement at ([^:]+):(\d+)'
    )

    # Also look for the final failure line
    final_pattern = re.compile(
        r'Problem at ([^:]+):(\d+)'
    )

    lines = error_output.split('\n')
    for i, line in enumerate(lines):
        # Only care about himmelblaud errors (not optional blocks from other modules)
        if 'himmelblaud' not in line:
            continue

        match = error_pattern.search(line)
        if match:
            error = PolicyInstallError(
                error_type=match.group(1),
                cil_file=match.group(2),
                cil_line=int(match.group(3)),
                raw_error=line,
                context_lines=lines[max(0, i-2):i+3]
            )
            errors.append(error)
            continue

        match = final_pattern.search(line)
        if match and 'himmelblaud' in match.group(1):
            error = PolicyInstallError(
                error_type="unknown",
                cil_file=match.group(1),
                cil_line=int(match.group(2)),
                raw_error=line,
                context_lines=lines[max(0, i-2):i+3]
            )
            errors.append(error)

    return errors


def fetch_cil_context(host: str, user: str, cil_path: str, line_num: int, context: int = 10) -> str:
    """Fetch context around a specific line in a CIL file from a remote host."""
    start = max(1, line_num - context)
    end = line_num + context

    rc, stdout, stderr = run_ssh_command(
        host, user,
        f"sed -n '{start},{end}p' '{cil_path}' 2>/dev/null | cat -n | sed 's/^/{start + offset}\\t/' || echo 'Could not read CIL file'",
        sudo=True
    )

    if rc != 0 or not stdout.strip():
        # Try alternative approach
        rc, stdout, stderr = run_ssh_command(
            host, user,
            f"awk 'NR>={start} && NR<={end} {{print NR\": \"$0}}' '{cil_path}' 2>/dev/null",
            sudo=True
        )

    return stdout if stdout else f"Could not fetch CIL context from {cil_path}"


def map_cil_to_te_line(cil_line: int, te_content: str) -> tuple[int, str, str]:
    """
    Attempt to map a CIL line number back to the .te source.

    Returns (te_line_number, te_line_content, suspected_issue)
    """
    # The CIL file is generated from the .te file through m4 preprocessing.
    # Line numbers don't map 1:1, but we can make educated guesses based on
    # the structure.

    # Common patterns that cause issues:
    # 1. Macro calls like init_nnp_daemon_domain(type) that expand to multiple CIL statements
    # 2. require blocks that reference types not present on all systems
    # 3. allow rules referencing types that don't exist

    te_lines = te_content.split('\n')

    # Look for likely problem areas based on CIL line number
    # CIL output typically has:
    # - Module declaration first
    # - Type declarations
    # - Typeattribute assignments (from macros)
    # - Allow rules

    # If CIL line is low (< 100), likely in the domain/type declaration area
    if cil_line < 100:
        # Look for macro calls or require blocks in first 100 lines of .te
        for i, line in enumerate(te_lines[:100], 1):
            stripped = line.strip()
            # Macro calls that might reference missing types
            if ('_domain(' in stripped or '_daemon_domain(' in stripped) and not stripped.startswith('#'):
                return (i, line, "Macro call may reference types not available on all systems")
            # require blocks
            if stripped.startswith('require {'):
                return (i, line, "Require block may reference types not available on all systems")

    # For higher line numbers, look for allow rules with external types
    external_types = [
        'accountsd_t', 'xdm_t', 'policykit_t', 'postfix_pickup_t', 'postfix_qmgr_t',
        'avahi_t', 'sshd_session_t', 'systemd_logind_t', 'systemd_user_runtimedir_t',
        'NetworkManager_t', 'cupsd_t', 'colord_t', 'groupadd_t'
    ]

    for i, line in enumerate(te_lines, 1):
        stripped = line.strip()
        for ext_type in external_types:
            if ext_type in stripped and not stripped.startswith('#'):
                return (i, line, f"References external type '{ext_type}' which may not exist on all systems")

    return (0, "", "Could not map CIL line to .te source")


def analyze_policy_error(errors: list[PolicyInstallError], te_content: str) -> dict:
    """
    Analyze policy installation errors and provide diagnosis.

    Returns a dict with:
    - diagnosis: Human-readable explanation
    - problematic_lines: List of (line_num, content, issue) tuples
    - suggested_fixes: List of suggested code changes
    """
    if not errors:
        return {
            "diagnosis": "No policy installation errors found.",
            "problematic_lines": [],
            "suggested_fixes": []
        }

    diagnosis_parts = []
    problematic_lines = []
    suggested_fixes = []

    # Group errors by type
    error_types = {}
    for error in errors:
        if error.error_type not in error_types:
            error_types[error.error_type] = []
        error_types[error.error_type].append(error)

    diagnosis_parts.append(f"Found {len(errors)} policy installation error(s):\n")

    for error_type, type_errors in error_types.items():
        diagnosis_parts.append(f"\n## {error_type} errors ({len(type_errors)}):")

        if error_type == "typeattributeset":
            diagnosis_parts.append(
                "  This error occurs when the policy references a type attribute that\n"
                "  doesn't exist on the target system. This commonly happens when:\n"
                "  1. A macro like init_nnp_daemon_domain() is called on a type that\n"
                "     doesn't exist on the target system\n"
                "  2. The macro itself references internal type attributes that vary\n"
                "     between SELinux policy versions\n"
            )
            suggested_fixes.append({
                "type": "wrap_in_optional",
                "description": "Wrap macro calls that reference external types in optional blocks",
                "example": """
# Before:
init_nnp_daemon_domain(groupadd_t)

# After:
optional {
    init_nnp_daemon_domain(groupadd_t)
}
"""
            })

        elif error_type == "allow":
            diagnosis_parts.append(
                "  This error occurs when an allow rule references a type that doesn't\n"
                "  exist on the target system.\n"
            )
            suggested_fixes.append({
                "type": "wrap_in_optional",
                "description": "Wrap allow rules for external types in optional blocks",
                "example": """
# Before:
allow some_t external_type_t:file read;

# After:
optional {
    allow some_t external_type_t:file read;
}
"""
            })

        for error in type_errors:
            diagnosis_parts.append(f"  - CIL line {error.cil_line}: {error.raw_error}")

            # Try to map to .te source
            te_line, te_content_line, issue = map_cil_to_te_line(error.cil_line, te_content)
            if te_line > 0:
                problematic_lines.append((te_line, te_content_line, issue))
                diagnosis_parts.append(f"    Likely source: line {te_line}: {te_content_line.strip()}")
                diagnosis_parts.append(f"    Issue: {issue}")

    # Provide overall recommendation
    diagnosis_parts.append("\n## Recommended Fix:")
    diagnosis_parts.append(
        "The policy uses macros and references types that may not exist on all\n"
        "Linux distributions (e.g., RHEL 10, Rocky 10, older Fedora versions).\n"
        "\n"
        "To fix this, wrap statements that reference potentially missing types\n"
        "in 'optional { }' blocks. SELinux will then gracefully skip these\n"
        "statements if the referenced types don't exist.\n"
        "\n"
        "Key areas to wrap in optional blocks:\n"
        "1. init_nnp_daemon_domain(groupadd_t) calls\n"
        "2. require blocks that list external types\n"
        "3. allow rules for types like xdm_t, accountsd_t, etc.\n"
    )

    return {
        "diagnosis": "\n".join(diagnosis_parts),
        "problematic_lines": problematic_lines,
        "suggested_fixes": suggested_fixes
    }


def check_policy_installed(host: str, user: str) -> tuple[bool, str]:
    """Check if the himmelblaud SELinux policy module is installed."""
    rc, stdout, stderr = run_ssh_command(host, user, "/usr/sbin/semodule -l 2>/dev/null | grep -E '^himmelblaud'", sudo=False)
    if rc == 0 and 'himmelblaud' in stdout:
        return True, stdout.strip()
    return False, ""


def try_install_policy(host: str, user: str) -> tuple[bool, str]:
    """Attempt to install the policy and capture any errors."""
    print("\n=== Attempting to install/reinstall SELinux policy ===")

    # First check if the policy package file exists
    rc, stdout, stderr = run_ssh_command(
        host, user,
        "ls -la /usr/share/selinux/packages/himmelblaud.pp 2>/dev/null",
        sudo=False
    )

    if rc != 0:
        return False, "Policy package file not found at /usr/share/selinux/packages/himmelblaud.pp"

    # Try verbose installation - use interactive capture for sudo password prompt
    rc, output = run_ssh_interactive_capture(
        host, user,
        "/usr/sbin/semodule -vv -i /usr/share/selinux/packages/himmelblaud.pp",
        sudo=True
    )

    # Check for successful installation of the himmelblaud module specifically.
    # The verbose output will contain many "Failed to resolve" messages for other
    # modules' optional blocks - this is normal and doesn't indicate failure.
    # We need to look for success indicators for our specific module.
    himmelblaud_success = (
        "Attempting to install module '/usr/share/selinux/packages/himmelblaud.pp':" in output
        and "Ok: return value of 0." in output
        and "Committing changes:" in output
    )

    # Also check for himmelblaud-specific failures (not failures in other modules)
    himmelblaud_failed = False
    for line in output.split('\n'):
        if 'himmelblaud' in line.lower() and 'failed' in line.lower():
            # Check if it's a real failure for our module, not just a "Disabling optional"
            if 'Disabling optional' not in line:
                himmelblaud_failed = True
                break

    if rc == 0 and himmelblaud_success and not himmelblaud_failed:
        return True, output

    return False, output


def diagnose_policy_installation(host: str, user: str):
    """Diagnose SELinux policy installation issues on a remote host."""
    print("=== SELinux Policy Installation Diagnosis ===")
    print(f"Target host: {host}")

    # Check if SELinux is enabled
    enabled, mode = check_selinux_status(host, user)
    if not enabled:
        print("\nSELinux is disabled on this system.")
        print("Would you like to enable SELinux?")
        choice = input("Enable SELinux? [Y/n]: ").strip().lower()
        if choice != 'n':
            success, message = enable_selinux(host, user)
            print(f"\n{message}")
            if not success or "reboot" in message.lower():
                return
            # Re-check status
            enabled, mode = check_selinux_status(host, user)
            if not enabled:
                print("SELinux is still not enabled. A reboot may be required.")
                return
        else:
            print("Cannot diagnose policy issues with SELinux disabled.")
            return

    print(f"SELinux mode: {mode}")

    # Check if policy is installed
    installed, version = check_policy_installed(host, user)
    if installed:
        print(f"Policy is installed: {version}")
    else:
        print("Policy is NOT installed")

    # Try to install/reinstall and capture output
    success, output = try_install_policy(host, user)

    if success:
        print("\nPolicy installation successful!")
        return

    print("\nPolicy installation FAILED. Analyzing error...")

    # Parse the errors
    errors = parse_semodule_error(output)

    if not errors:
        print("\nCould not parse specific errors. Raw output:")
        print("-" * 60)
        print(output[-2000:] if len(output) > 2000 else output)  # Last 2000 chars
        print("-" * 60)
        return

    # Read the .te source for analysis
    te_content = read_current_policy()

    # Analyze
    analysis = analyze_policy_error(errors, te_content)

    print("\n" + "=" * 60)
    print("DIAGNOSIS")
    print("=" * 60)
    print(analysis["diagnosis"])

    if analysis["problematic_lines"]:
        print("\n" + "=" * 60)
        print("PROBLEMATIC LINES IN himmelblaud.te")
        print("=" * 60)
        for line_num, content, issue in analysis["problematic_lines"]:
            print(f"Line {line_num}: {content.strip()}")
            print(f"  Issue: {issue}")
            print()

    if analysis["suggested_fixes"]:
        print("\n" + "=" * 60)
        print("SUGGESTED FIXES")
        print("=" * 60)
        for fix in analysis["suggested_fixes"]:
            print(f"\n{fix['description']}:")
            print(fix["example"])


def process_semodule_error_output(error_output: str):
    """Process semodule error output provided directly (from file or stdin)."""
    print("=== Analyzing SELinux Policy Installation Error ===\n")

    errors = parse_semodule_error(error_output)

    if not errors:
        # Check if there's a himmelblaud error mentioned at all
        if 'himmelblaud' in error_output and 'Failed' in error_output:
            print("Found indication of himmelblaud policy failure but could not parse specific errors.")
            print("\nLooking for key patterns...")

            # Look for the specific failure line
            for line in error_output.split('\n'):
                if 'himmelblaud' in line and ('Failed' in line or 'Problem' in line):
                    print(f"  {line}")
        else:
            print("No himmelblaud-specific policy errors found in the output.")
            print("The errors shown may be from other modules (which use optional blocks).")
        return

    # Read the .te source for analysis
    te_content = read_current_policy()

    # Analyze
    analysis = analyze_policy_error(errors, te_content)

    print("=" * 60)
    print("DIAGNOSIS")
    print("=" * 60)
    print(analysis["diagnosis"])

    if analysis["problematic_lines"]:
        print("\n" + "=" * 60)
        print("PROBLEMATIC LINES IN himmelblaud.te")
        print("=" * 60)
        for line_num, content, issue in analysis["problematic_lines"]:
            print(f"Line {line_num}: {content.strip()}")
            print(f"  Issue: {issue}")
            print()

    if analysis["suggested_fixes"]:
        print("\n" + "=" * 60)
        print("SUGGESTED FIXES")
        print("=" * 60)
        for fix in analysis["suggested_fixes"]:
            print(f"\n{fix['description']}:")
            print(fix["example"])

    # Provide specific fix recommendations based on the .te file
    print("\n" + "=" * 60)
    print("SPECIFIC RECOMMENDATIONS FOR himmelblaud.te")
    print("=" * 60)
    provide_specific_recommendations(te_content)


def provide_specific_recommendations(te_content: str):
    """Analyze the .te file and provide specific recommendations."""
    lines = te_content.split('\n')

    recommendations = []

    # Track require blocks and their contents
    in_require = False
    require_start = 0
    require_types = []

    # External types that might not exist on all systems
    external_types = {
        'groupadd_t': 'May not exist on systems without shadow-utils SELinux module',
        'accountsd_t': 'Accounts daemon - may not be installed',
        'xdm_t': 'X Display Manager - may vary by display manager',
        'policykit_t': 'PolicyKit - may not be installed',
        'postfix_pickup_t': 'Postfix mail - may not be installed',
        'postfix_qmgr_t': 'Postfix mail - may not be installed',
        'avahi_t': 'Avahi/mDNS - may not be installed',
        'sshd_session_t': 'OpenSSH - may have different type on some systems',
        'systemd_logind_t': 'systemd-logind - type name may vary',
        'systemd_user_runtimedir_t': 'systemd user runtime - may not exist',
        'NetworkManager_t': 'NetworkManager - may not be installed',
        'cupsd_t': 'CUPS printing - may not be installed',
        'colord_t': 'Color management - may not be installed',
    }

    # Macros that might fail
    problematic_macros = [
        'init_nnp_daemon_domain',
        'accountsd_manage_lib_files',
        'userdom_manage_user_home_content',
    ]

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Track require blocks
        if stripped.startswith('require {'):
            in_require = True
            require_start = i
            require_types = []
            continue

        if in_require:
            if stripped == '}':
                in_require = False
                # Check if require block has external types
                ext_in_require = [t for t in require_types if t in external_types]
                if ext_in_require:
                    recommendations.append({
                        "line": require_start,
                        "type": "require_block",
                        "message": f"Require block references external types: {', '.join(ext_in_require)}",
                        "fix": "Consider using gen_require() inside optional blocks instead"
                    })
            else:
                # Check for type declarations in require
                type_match = re.match(r'type\s+(\w+);', stripped)
                if type_match:
                    require_types.append(type_match.group(1))
            continue

        # Check for problematic macro calls outside optional blocks
        for macro in problematic_macros:
            if macro + '(' in stripped and not stripped.startswith('#'):
                # Extract the argument
                match = re.search(rf'{macro}\(([^)]+)\)', stripped)
                if match:
                    arg = match.group(1)
                    if arg in external_types:
                        recommendations.append({
                            "line": i,
                            "type": "macro_call",
                            "message": f"Macro {macro}({arg}) may fail if {arg} doesn't exist",
                            "fix": f"Wrap in optional block:\n    optional {{\n        {stripped}\n    }}"
                        })

        # Check for allow rules with external types
        if stripped.startswith('allow ') and not stripped.startswith('#'):
            for ext_type, note in external_types.items():
                if ext_type in stripped:
                    recommendations.append({
                        "line": i,
                        "type": "allow_rule",
                        "message": f"Allow rule references {ext_type} ({note})",
                        "fix": f"Group with other {ext_type} rules in an optional block"
                    })
                    break

    # Print recommendations grouped by type
    if not recommendations:
        print("No specific issues found in the policy file.")
        return

    # Group by issue type
    by_type = {}
    for rec in recommendations:
        if rec["type"] not in by_type:
            by_type[rec["type"]] = []
        by_type[rec["type"]].append(rec)

    if "macro_call" in by_type:
        print("\n1. MACRO CALLS that should be wrapped in optional blocks:")
        for rec in by_type["macro_call"]:
            print(f"\n   Line {rec['line']}: {rec['message']}")
            print(f"   Fix: {rec['fix']}")

    if "require_block" in by_type:
        print("\n2. REQUIRE BLOCKS with external types:")
        for rec in by_type["require_block"]:
            print(f"\n   Line {rec['line']}: {rec['message']}")
            print(f"   Note: {rec['fix']}")

    if "allow_rule" in by_type:
        print("\n3. ALLOW RULES referencing external types:")
        print("   These should be grouped by source type and wrapped in optional blocks.")
        print("   Example structure:")
        print("""
   optional {
       # Rules for accountsd_t
       allow accountsd_t himmelblau_var_cache_t:lnk_file read;
       allow accountsd_t himmelblau_etc_t:file { getattr open read };
       ...
   }
""")
        # Group by external type
        by_ext_type = {}
        for rec in by_type["allow_rule"]:
            for ext_type in external_types:
                if ext_type in rec["message"]:
                    if ext_type not in by_ext_type:
                        by_ext_type[ext_type] = []
                    by_ext_type[ext_type].append(rec["line"])
                    break

        for ext_type, line_nums in by_ext_type.items():
            print(f"   - {ext_type}: lines {', '.join(map(str, sorted(set(line_nums))))}")


def main():
    parser = argparse.ArgumentParser(
        description="SELinux Fix Helper for Himmelblau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SSH to a machine and collect denials interactively
  %(prog)s --host testvm.example.com --user root

  # Process audit logs from a file
  %(prog)s --audit-file /tmp/audit.log

  # Process audit logs from stdin
  ausearch -m avc | %(prog)s --stdin

  # Apply fixes automatically
  %(prog)s --audit-file /tmp/audit.log --apply

  # Diagnose policy installation error from file
  %(prog)s --semodule-error /tmp/semodule_output.txt

  # Diagnose policy installation error from stdin
  semodule -vv -i himmelblaud.pp 2>&1 | %(prog)s --semodule-stdin

  # Analyze current policy file for potential issues
  %(prog)s --analyze
        """
    )

    parser.add_argument("--host", "-H", help="Remote host to SSH into")
    parser.add_argument("--user", "-u", help="SSH user (default: current user)")
    parser.add_argument("--audit-file", "-f", help="Path to audit log file to process")
    parser.add_argument("--stdin", "-s", action="store_true", help="Read audit log from stdin")
    parser.add_argument("--apply", "-a", action="store_true",
                        help="Automatically apply fixes to policy file")
    parser.add_argument("--semodule-error", "-e", help="Path to semodule error output file")
    parser.add_argument("--semodule-stdin", action="store_true",
                        help="Read semodule error output from stdin")
    parser.add_argument("--analyze", action="store_true",
                        help="Analyze current policy file for potential compatibility issues")
    parser.add_argument("--diagnose", "-d", action="store_true",
                        help="When used with --host, diagnose policy installation instead of collecting denials")

    args = parser.parse_args()

    # Determine mode
    modes_specified = sum([
        bool(args.host),
        bool(args.audit_file),
        args.stdin,
        bool(args.semodule_error),
        args.semodule_stdin,
        args.analyze
    ])

    if modes_specified == 0:
        parser.error("Must specify a mode: --host, --audit-file, --stdin, --semodule-error, --semodule-stdin, or --analyze")

    if modes_specified > 1:
        # Check for valid combinations
        if args.host and args.diagnose:
            pass  # This is valid
        elif args.audit_file and args.apply:
            pass  # This is valid
        else:
            parser.error("Cannot combine multiple input modes")

    # Process based on mode
    if args.analyze:
        print("=== Analyzing Policy File for Compatibility Issues ===\n")
        te_content = read_current_policy()
        if not te_content:
            print(f"Error: Could not read policy file at {SELINUX_TE_PATH}")
            sys.exit(1)
        provide_specific_recommendations(te_content)
    elif args.semodule_error:
        error_output = Path(args.semodule_error).read_text()
        process_semodule_error_output(error_output)
    elif args.semodule_stdin:
        error_output = sys.stdin.read()
        process_semodule_error_output(error_output)
    elif args.host:
        if args.diagnose:
            diagnose_policy_installation(args.host, args.user)
        else:
            interactive_mode(args.host, args.user, args.apply)
    elif args.audit_file:
        audit_log = Path(args.audit_file).read_text()
        process_audit_log(audit_log, args.apply)
    elif args.stdin:
        audit_log = sys.stdin.read()
        process_audit_log(audit_log, args.apply)


if __name__ == "__main__":
    main()
