#!/usr/bin/env python3
# Generate Himmelblau systemd unit files with version-gated directives.
#
# Example:
#   python3 gen_systemd_units.py --out-dir platform/generated \
#       --static-user himmelblaud --static-group himmelblaud \
#       --tss-group tss \
#       --assume-version 252
#
# If run without --assume-version, it will detect the host systemd version.

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path
from textwrap import dedent

# -------- Feature Matrix (adjust as needed) -------------------
# Conservative minimum versions for directives we toggle.
# If unsure about a directive, keep its min low and provide a flag to force-disable.
MINVER = {
    # Unit section
    "Upholds": 249,
    # Service section
    "TypeNotifyReload": 253,   # Use Type=notify-reload when >= this; else Type=notify
    "DynamicUser": 235,
    "ProtectSystemStrict": 214,
    "ReadWritePaths": 231,
    "CapabilityBoundingSet": 21,
    "NoNewPrivileges": 187,
    "PrivateTmp": 1,
    "PrivateDevices": 209,
    "ProtectHostname": 242,
    "ProtectClock": 245,
    "ProtectKernelTunables": 232,
    "ProtectKernelModules": 232,
    "ProtectKernelLogs": 244,
    "ProtectControlGroups": 232,
    "MemoryDenyWriteExecute": 231,
    "CacheRuntimeStateDirs": 235,  # CacheDirectory/RuntimeDirectory/StateDirectory
    "ConditionPathExists": 12,
    "LoadCredentialEncrypted": 250,
}

def detect_systemd_version():
    cmds = [
        ["systemctl", "--version"],
        ["systemd-analyze", "--version"],
    ]
    for cmd in cmds:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            # First line usually: "systemd 256 (256.6-1)"
            m = re.search(r"\bsystemd\s+(\d+)", out)
            if m:
                return int(m.group(1))
        except Exception:
            continue
    return None

def bool_env(val: str) -> bool:
    return val.lower() in ("1", "true", "yes", "on")

def main():
    ap = argparse.ArgumentParser(description="Generate Himmelblau systemd unit files.")
    ap.add_argument("--out-dir", default=".", help="Output directory for generated units.")
    ap.add_argument("--assume-version", type=int, default=None,
                    help="Assume this systemd version (skip detection).")
    ap.add_argument("--force-notify-reload", action="store_true",
                    help="Force Type=notify-reload regardless of detected version.")
    ap.add_argument("--disable-notify-reload", action="store_true",
                    help="Force Type=notify even if notify-reload is supported.")
    ap.add_argument("--disable-upholds", action="store_true",
                    help="Do not emit Upholds= (even if supported).")

    ap.add_argument("--static-user", default=None,
                    help="If set, use a fixed User= (and Group= if --static-group given) instead of DynamicUser.")
    ap.add_argument("--static-group", default=None, help="Group to set when using static user.")
    ap.add_argument("--tss-group", default="tss", help="Supplementary tss group (or empty to disable).")

    ap.add_argument("--after-extra", default="", help="Extra units/targets to include in After= (space-separated).")
    ap.add_argument("--wants-extra", default="", help="Extra units/targets to include in Wants= (space-separated).")

    args = ap.parse_args()

    # systemd version
    if args.assume_version is not None:
        ver = args.assume-version
    else:
        ver = detect_systemd_version()
    if ver is None:
        # If detection failed, be conservative and assume older version 229
        ver = 229

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    def supported(feature: str) -> bool:
        return ver >= MINVER[feature]

    # ---- Decide Type= ----
    if args.force_notify_reload:
        type_line = "Type=notify-reload"
    elif args.disable_notify_reload:
        type_line = "Type=notify"
    else:
        type_line = "Type=notify-reload" if supported("TypeNotifyReload") else "Type=notify"

    # ---- Decide DynamicUser vs static ----
    dyn_user_ok = supported("DynamicUser") and (args.static_user is None)
    service_user_block = []
    if dyn_user_ok:
        service_user_block.append("DynamicUser=yes")
    else:
        # Static user
        if not args.static_user:
            # If not provided, fall back to root like tasks unit (safe default)
            service_user_block.append("User=root")
        else:
            service_user_block.append(f"User={args.static_user}")
        if args.static_group:
            service_user_block.append(f"Group={args.static_group}")

    # SupplementaryGroups for tss (skip if empty or not desired)
    if args.tss_group:
        service_user_block.append(f"SupplementaryGroups={args.tss_group}")

    # ---- Directory helpers ----
    dirs_block = []
    if supported("CacheRuntimeStateDirs"):
        dirs_block.extend([
            "UMask=0027",
            "CacheDirectory=himmelblaud",
            "RuntimeDirectory=himmelblaud",
            "StateDirectory=himmelblaud",
        ])

    # ---- Security hardening (toggle by version) ----
    hardening = []
    if supported("NoNewPrivileges"):
        hardening.append("NoNewPrivileges=true")
    if supported("PrivateTmp"):
        hardening.append("PrivateTmp=true")
    # PrivateDevices: tasks wants true, daemon wants false (for TPM access)
    # We'll pass the value contextually when we compose units below.
    if supported("ProtectHostname"):
        hardening.append("ProtectHostname=true")
    if supported("ProtectClock"):
        hardening.append("ProtectClock=true")
    if supported("ProtectKernelTunables"):
        hardening.append("ProtectKernelTunables=true")
    if supported("ProtectKernelModules"):
        hardening.append("ProtectKernelModules=true")
    if supported("ProtectKernelLogs"):
        hardening.append("ProtectKernelLogs=true")
    if supported("ProtectControlGroups"):
        hardening.append("ProtectControlGroups=true")
    if supported("MemoryDenyWriteExecute"):
        hardening.append("MemoryDenyWriteExecute=true")
    if supported("ProtectSystemStrict"):
        hardening.append("ProtectSystem=strict")
    # ReadWritePaths only if ProtectSystem=strict available
    rw_paths_available = supported("ReadWritePaths") and supported("ProtectSystemStrict")

    # ---- Common headers ----
    # After= and Wants= lines vary slightly across distros; expose flags.
    base_after = ["chronyd.service", "nscd.service", "ntpd.service", "network-online.target", "suspend.target"]
    tasks_after = ["chronyd.service", "ntpd.service", "network-online.target", "suspend.target"]
    if args.after_extra.strip():
        base_after += args.after_extra.split()
        tasks_after += args.after_extra.split()

    base_before = ["systemd-user-sessions.service", "sshd.service", "nss-user-lookup.target"]
    base_wants = ["nss-user-lookup.target"]
    if args.wants_extra.strip():
        base_wants += args.wants_extra.split()

    # Upholds only if requested and supported
    upholds_line = ""
    if not args.disable_upholds and supported("Upholds"):
        upholds_line = "Upholds=himmelblaud-tasks.service"

    # ---- Compose himmelblaud.service ----
    daemon_private_devices = "PrivateDevices=false" if supported("PrivateDevices") else ""
    daemon_hardening = [h for h in hardening if h != "ProtectSystem=strict"] + ["ProtectSystem=strict"] if supported("ProtectSystemStrict") else [h for h in hardening if h != "ProtectSystem=strict"]

    daemon_rw_paths_comment = dedent("""\
        # Implied by dynamic user.
        # ProtectHome=
        # ProtectSystem=strict
        # ReadWritePaths=/var/run/himmelblaud /var/cache/himmelblaud
    """).rstrip()

    if rw_paths_available:
        # Keep comment but we don't add ReadWritePaths for daemon by default since the daemon primarily writes those dirs via XDG helpers.
        pass

    daemon_unit = f"""\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl edit himmelblaud.service

[Unit]
Description=Himmelblau Authentication Daemon
After={' '.join(base_after)}
Before={' '.join(base_before)}
Wants={' '.join(base_wants)}
# While it seems confusing, we need to be after nscd.service so that the
# Conflicts will trigger and then automatically stop it.
Conflicts=nscd.service
# `Upholds` like a `Wants` directive ensures that himmelblaud-tasks is started but also
# ensures it's kept running. This allows for a repeatable & fast way of starting 
# himmelblaud-tasks at the right time.
{upholds_line if upholds_line else ''}

[Service]
{os.linesep.join(service_user_block)}
{os.linesep.join(dirs_block)}

{type_line}
{'LoadCredentialEncrypted=hsm-pin:/var/lib/himmelblaud/hsm-pin.enc' if supported('LoadCredentialEncrypted') else ''}
{'Environment=HIMMELBLAU_HSM_PIN_PATH=%d/hsm-pin' if supported('LoadCredentialEncrypted') else ''}
ExecStart=/usr/sbin/himmelblaud

{daemon_rw_paths_comment}

# SystemCallFilter=@aio @basic-io @chown @file-system @io-event @network-io @sync
{os.linesep.join(daemon_hardening)}
PrivateTmp=true
# We have to disable this to allow tpmrm0 access for tpm binding.
{daemon_private_devices}

[Install]
WantedBy=multi-user.target
""".rstrip() + "\n"

    # ---- Compose himmelblaud-tasks.service ----
    tasks_hardening = list(hardening)  # copy
    # tasks requires PrivateDevices=true
    tasks_private_devices = "PrivateDevices=true" if supported("PrivateDevices") else ""
    # ReadWritePaths needed for tasks
    rw_paths = "/home /run/himmelblaud /tmp /etc/krb5.conf.d /etc /var/lib /var/cache/nss-himmelblau /var/cache/himmelblau-policies"
    rw_line = f"ReadWritePaths={rw_paths}" if rw_paths_available else ""

    tasks_unit = f"""\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl edit himmelblaud-tasks.service

[Unit]
Description=Himmelblau Local Tasks
After={' '.join(tasks_after)} himmelblaud.service
Requires=himmelblaud.service

# This prevents starting himmelblaud-tasks before himmelblaud is running and
# has created the socket necessary for communication.
# We need the check so that fs namespacing used by `ReadWritePaths` has a
# strict enough target to namespace. Without the check it fails in a more confusing way.
{'ConditionPathExists=/run/himmelblaud/task_sock' if supported('ConditionPathExists') else ''}

[Service]
User=root
Type=notify
ExecStart=/usr/sbin/himmelblaud_tasks

CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
# SystemCallFilter=@aio @basic-io @chown @file-system @io-event @network-io @sync
{ 'ProtectSystem=strict' if supported('ProtectSystemStrict') else '' }
{rw_line}
{os.linesep.join([h for h in tasks_hardening if not h.startswith('ProtectSystem=')])}
{tasks_private_devices}

[Install]
WantedBy=multi-user.target
""".rstrip() + "\n"

    # Clean extra blank lines from optional inserts
    def squeeze_blank_lines(s: str) -> str:
        s = re.sub(r"\n{3,}", "\n\n", s)
        s = re.sub(r"\n+\Z", "\n", s)
        # Remove lines that became empty placeholders (like a lone '# ...' line followed by blank)
        return s

    daemon_unit = squeeze_blank_lines(daemon_unit)
    tasks_unit  = squeeze_blank_lines(tasks_unit)

    (out_dir / "himmelblaud.service").write_text(daemon_unit)
    (out_dir / "himmelblaud-tasks.service").write_text(tasks_unit)

    print(f"[gen-systemd] systemd version detected/assumed: {ver}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblaud.service'}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblaud-tasks.service'}")

if __name__ == "__main__":
    main()
