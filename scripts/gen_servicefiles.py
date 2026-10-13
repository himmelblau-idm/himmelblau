#!/usr/bin/env python3
# Generate Himmelblau unit files for systemd 239 and newer.
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

# TODO: bump to 252 once RHEL/CentOS/Rocky/Alma 8 are EOL
BASELINE_VERSION = 239

# Only directives introduced after the baseline need version checks.
MINVER = {
    # Unit section
    "Upholds": 249,
    # Service section
    "FileDescriptorStorePreserve": 254,
    # systemd/systemd@941a12dc allows socket activation while the associated
    # service is stopped with resources pinned in its FD store.
    "PinnedFdStoreSocketActivation": 257,
    "TypeNotifyReload": 253,   # Use Type=notify-reload when >= this; else Type=notify
    "ProtectHostname": 242,
    "ProtectClock": 245,
    "ProtectKernelLogs": 244,
    "LoadCredentialEncrypted": 250,
}

def detect_systemd_version():
    cmds = [
        ["systemctl", "--version"],
        ["systemd-analyze", "--version"],
        ["systemd-hwdb", "--version"],
    ]
    for cmd in cmds:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            # First line usually: "systemd 256 (256.6-1)"
            m = re.search(r"\bsystemd\s+([^\s]+)", out)
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
                    help=f"Assume this systemd version, at least {BASELINE_VERSION} (skip detection).")
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
    ap.add_argument("--orchestrator-apparmor-profile", default="",
                    help="AppArmor profile name to pass to himmelblaud-orchestrator containers.")

    args = ap.parse_args()

    # systemd version
    if args.assume_version is not None:
        ver = args.assume_version
    else:
        ver = detect_systemd_version()
    if ver is None:
        ver = BASELINE_VERSION
        print(f"[gen-systemd] Could not detect systemd version; assuming {BASELINE_VERSION}.")
    if ver < BASELINE_VERSION:
        ap.error(f"systemd {BASELINE_VERSION} or newer is required (got {ver})")

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
    service_user_block = []
    if args.static_user is None:
        service_user_block.append("DynamicUser=yes")
        service_user_block.append("User=himmelblaud")
    else:
        service_user_block.append(f"User={args.static_user or 'root'}")
        if args.static_group:
            service_user_block.append(f"Group={args.static_group}")

    # SupplementaryGroups for tss (skip if empty or not desired)
    if args.tss_group:
        service_user_block.append(f"SupplementaryGroups={args.tss_group}")

    # ---- Security hardening (toggle by version) ----
    hardening = ["NoNewPrivileges=true", "PrivateTmp=true"]
    # PrivateDevices: tasks wants true, daemon wants false (for TPM access)
    # We'll pass the value contextually when we compose units below.
    if supported("ProtectHostname"):
        hardening.append("ProtectHostname=true")
    if supported("ProtectClock"):
        hardening.append("ProtectClock=true")
    hardening.extend(["ProtectKernelTunables=true", "ProtectKernelModules=true"])
    if supported("ProtectKernelLogs"):
        hardening.append("ProtectKernelLogs=true")
    hardening.extend([
        "ProtectControlGroups=true",
        "MemoryDenyWriteExecute=true",
        "ProtectSystem=strict",
    ])

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

    # HSM PIN init service dependency (only if LoadCredentialEncrypted is supported)
    hsm_pin_init_after = ""
    hsm_pin_init_wants = ""
    if supported("LoadCredentialEncrypted"):
        hsm_pin_init_after = "himmelblau-hsm-pin-init.service"
        hsm_pin_init_wants = "Wants=himmelblau-hsm-pin-init.service"

    # ---- Compose himmelblaud.service ----
    fd_store_preserve = ""
    if supported("FileDescriptorStorePreserve"):
        if supported("PinnedFdStoreSocketActivation"):
            fd_store_preserve = dedent("""\
                # systemd 257+ can reactivate sockets while this service is stopped
                # with resources pinned, so retain broker tokens across stop/start.
                FileDescriptorStorePreserve=yes
            """).rstrip()
        else:
            fd_store_preserve = dedent("""\
                # systemd 254-256 cannot reactivate sockets while this service is
                # pinned, so retain broker tokens across atomic restarts only.
                FileDescriptorStorePreserve=restart
            """).rstrip()

    daemon_unit = f"""\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl edit himmelblaud.service

[Unit]
Description=Himmelblau Authentication Daemon
After={' '.join(base_after)}{' ' + hsm_pin_init_after if hsm_pin_init_after else ''} himmelblaud.socket himmelblaud-tasks.socket himmelblaud-broker.socket
Requires=himmelblaud.socket himmelblaud-tasks.socket himmelblaud-broker.socket
Before={' '.join(base_before)}
Wants={' '.join(base_wants)}
{hsm_pin_init_wants}
# While it seems confusing, we need to be after nscd.service so that the
# Conflicts will trigger and then automatically stop it.
Conflicts=nscd.service
# `Upholds` like a `Wants` directive ensures that himmelblaud-tasks is started but also
# ensures it's kept running. This allows for a repeatable & fast way of starting
# himmelblaud-tasks at the right time.
{upholds_line if upholds_line else ''}
StartLimitIntervalSec=30s
StartLimitBurst=8

[Service]
{os.linesep.join(service_user_block)}
UMask=0027
CacheDirectory=himmelblaud
StateDirectory=himmelblaud
ConfigurationDirectory=himmelblau

{type_line}
{'LoadCredentialEncrypted=hsm-pin:/var/lib/himmelblaud/hsm-pin-nopcr.enc' if supported('LoadCredentialEncrypted') else ''}
{'Environment=HIMMELBLAU_HSM_PIN_PATH=%d/hsm-pin' if supported('LoadCredentialEncrypted') else ''}
ExecStart=/usr/sbin/himmelblaud
Sockets=himmelblaud.socket himmelblaud-tasks.socket himmelblaud-broker.socket
Restart=on-failure
RestartSec=500ms
WatchdogSec=120s
FileDescriptorStoreMax=1
{fd_store_preserve}

# Implied by dynamic user.
# ProtectHome=
# ProtectSystem=strict
# ReadWritePaths=/var/run/himmelblaud /var/cache/himmelblaud

# SystemCallFilter=@aio @basic-io @chown @file-system @io-event @network-io @sync
{os.linesep.join(hardening)}
PrivateTmp=true
# We have to disable this to allow tpmrm0 access for tpm binding.
PrivateDevices=false

[Install]
WantedBy=multi-user.target
""".rstrip() + "\n"

    # ---- Compose himmelblaud-tasks.service ----
    # Intune CustomCompliance discovery scripts commonly shell out to `mokutil`
    # (Microsoft's stock Secure Boot compliance script runs `mokutil --db`).
    #
    # mokutil's mok_get_variable() reads /sys/firmware/efi/mok-variables/<name>
    # first and only falls back to efivarfs if that open() fails. Those files are
    # mode 0400 root:root, so this unit (User=root) opens them successfully - but
    # the kernel's efi_mokvar_sysfs_read() returns 0 rather than -EPERM when the
    # reader lacks CAP_SYS_ADMIN, which our CapabilityBoundingSet drops. mokutil's
    # read loop has no ssz==0 guard, so it spins at 100% CPU forever, blocks the
    # task daemon's watchdog pings, and WatchdogSec SIGABRTs the whole service.
    #
    # Hiding the directory makes that open() fail so mokutil takes its normal
    # efivarfs fallback - the same path unprivileged callers already use. This is
    # preferable to granting CAP_SYS_ADMIN, and does not affect `mokutil
    # --sb-state`, which uses efi_get_variable() and never touches mok-variables.
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
ConditionPathExists=/run/himmelblaud/task_sock
StartLimitIntervalSec=30s
StartLimitBurst=8

[Service]
User=root
Type=notify
ExecStart=/usr/sbin/himmelblaud_tasks
Restart=on-failure
RestartSec=1s
WatchdogSec=120s

CacheDirectory=nss-himmelblau
ConfigurationDirectory=himmelblau
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_SETUID CAP_SETGID
# SystemCallFilter=@aio @basic-io @chown @file-system @io-event @network-io @sync
ProtectSystem=strict
ReadWritePaths=/home /run/himmelblaud /tmp /etc/krb5.conf.d /etc /var/lib /var/cache/nss-himmelblau /var/cache/himmelblau-policies
{os.linesep.join([h for h in hardening if not h.startswith('ProtectSystem=')])}
PrivateDevices=true
InaccessiblePaths=-/sys/firmware/efi/mok-variables

[Install]
WantedBy=multi-user.target
""".rstrip() + "\n"

    # ---- Compose himmelblau-hsm-pin-init.service ----
    # Always generate this file so cargo-deb can find it. On older systemd without
    # LoadCredentialEncrypted support, the service won't be started by himmelblaud.service.
    hsm_pin_init_unit = """\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl edit himmelblau-hsm-pin-init.service

[Unit]
Description=Himmelblau HSM PIN Initialization
Before=himmelblaud.service
DefaultDependencies=no
# systemd-tpm2-setup.service provisions the TPM Storage Root Key (SRK) at
# 0x81000001. Without it, systemd-creds encrypt --tpm2-device=auto silently
# falls back to a non-TPM-bound host key, so the HSM PIN is not TPM-protected.
# Wants= (not Requires=) so we degrade gracefully on TPM-less systems.
After=local-fs.target systemd-tpm2-setup.service
Wants=systemd-tpm2-setup.service

[Service]
Type=oneshot
StateDirectory=himmelblaud
StateDirectoryMode=0700
BindPaths=/run/systemd /var/lib/systemd
ExecStart=/usr/libexec/himmelblau-init-hsm-pin
RuntimeDirectory=himmelblau-hsm-pin
RuntimeDirectoryMode=0700
TemporaryFileSystem=/run/himmelblau-hsm-pin:rw,mode=0700
UMask=0077

[Install]
WantedBy=himmelblaud.service
"""

    # ---- Compose himmelblaud-orchestrator.service ----
    orchestrator_hardening = [
        h
        for h in hardening
        if not h.startswith("ProtectSystem=")
        and h != "NoNewPrivileges=true"
        and h != "ProtectControlGroups=true"
        and h != "ProtectKernelTunables=true"
        and h != "ProtectHostname=true"
        and h != "MemoryDenyWriteExecute=true"
    ]
    orchestrator_apparmor_line = (
        f"Environment=HIMMELBLAU_ORCHESTRATOR_APPARMOR_PROFILE={args.orchestrator_apparmor_profile.strip()}"
        if args.orchestrator_apparmor_profile.strip()
        else ""
    )

    orchestrator_unit = f"""\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl edit himmelblaud-orchestrator.service

[Unit]
Description=Himmelblau Browser Authentication Orchestrator
After=network-online.target himmelblaud.service
Wants=network-online.target
Requires=himmelblaud.service
PartOf=himmelblaud.service

[Service]
User=root
Group=tss
UMask=0007
Type=simple
Delegate=yes
{orchestrator_apparmor_line}
ExecStart=/usr/sbin/himmelblaud-orchestrator
Restart=on-failure
RestartPreventExitStatus=75
RestartSec=1s
KillMode=mixed
TimeoutStopSec=10s
ProtectSystem=strict
ReadWritePaths=/run/himmelblaud /run/lock /run/netns -/run/containers -/var/lib/containers -/run/libpod -/run/crun -/run/runc -/etc/containers/networks -/var/cache/himmelblaud/orchestrator -/var/cache/private/himmelblaud/orchestrator
{os.linesep.join(orchestrator_hardening)}
PrivateDevices=false

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
    hsm_pin_init_unit = squeeze_blank_lines(hsm_pin_init_unit)
    orchestrator_unit = squeeze_blank_lines(orchestrator_unit)

    # ---- Compose himmelblau-compliance-check.service (user unit) ----
    compliance_check_service = """\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl --user edit himmelblau-compliance-check.service

[Unit]
Description=Himmelblau Compliance Check
Documentation=man:aad-tool(1)

[Service]
Type=oneshot
ExecStart=/usr/bin/aad-tool compliance-check

[Install]
WantedBy=default.target
"""

    # ---- Compose himmelblau-compliance-check.timer (user unit) ----
    compliance_check_timer = """\
# You should not need to edit this file. Instead, use a drop-in file:
#   systemctl --user edit himmelblau-compliance-check.timer

[Unit]
Description=Himmelblau Compliance Check Timer
Documentation=man:aad-tool(1)

[Timer]
OnBootSec=10min
OnUnitActiveSec=8h
Persistent=true

[Install]
WantedBy=timers.target
"""

    socket_after = " ".join(
        s for s in base_after + ([hsm_pin_init_after] if hsm_pin_init_after else []) + ["sockets.target"] if s
    )
    socket_header = (
        "DefaultDependencies=no\n"
        "# Started by himmelblaud.service, not sockets.target. Early listening left\n"
        "# NSS clients connected to a socket nobody accepted and hung boot (#1345).\n"
        f"After={socket_after}\n"
        "Before=himmelblaud.service\n"
        "PartOf=himmelblaud.service\n"
    )

    # Debian and openSUSE socket units are the same. Write them once.
    socket_dir = Path(__file__).resolve().parent.parent / "platform" / "systemd"
    socket_dir.mkdir(parents=True, exist_ok=True)

    def write_socket(name: str, desc: str, listen: str, fdname: str, extra: str = "") -> None:
        (socket_dir / name).write_text(
            f"# You should not need to edit this file. Instead, use a drop-in file:\n"
            f"#   systemctl edit {name}\n\n"
            f"[Unit]\nDescription={desc}\n{socket_header}\n"
            f"[Socket]\nListenStream={listen}\nFileDescriptorName={fdname}\n"
            f"{extra}DirectoryMode=0755\nAccept=false\nService=himmelblaud.service\n"
        )
        print(f"[gen-systemd] Wrote: {socket_dir / name}")

    write_socket(
        "himmelblaud.socket",
        "Himmelblau Authentication Daemon Socket",
        "/run/himmelblaud/socket",
        "himmelblaud",
        extra="SocketMode=0666\n",
    )
    write_socket(
        "himmelblaud-tasks.socket",
        "Himmelblau Daemon Task Socket",
        "/run/himmelblaud/task_sock",
        "himmelblaud-task",
        extra="SocketMode=0600\nSocketUser=root\nSocketGroup=root\n",
    )
    write_socket(
        "himmelblaud-broker.socket",
        "Himmelblau Daemon Broker Socket",
        "/run/himmelblaud/broker_sock",
        "himmelblaud-broker",
        extra="SocketMode=0666\n",
    )

    (out_dir / "himmelblaud.service").write_text(daemon_unit)
    (out_dir / "himmelblaud-tasks.service").write_text(tasks_unit)
    (out_dir / "himmelblau-hsm-pin-init.service").write_text(hsm_pin_init_unit)
    (out_dir / "himmelblaud-orchestrator.service").write_text(orchestrator_unit)
    (out_dir / "himmelblau-compliance-check.service").write_text(compliance_check_service)
    (out_dir / "himmelblau-compliance-check.timer").write_text(compliance_check_timer)

    print(f"[gen-systemd] systemd version detected/assumed: {ver}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblaud.service'}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblaud-tasks.service'}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblau-hsm-pin-init.service'}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblaud-orchestrator.service'}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblau-compliance-check.service'}")
    print(f"[gen-systemd] Wrote: {out_dir/'himmelblau-compliance-check.timer'}")

if __name__ == "__main__":
    main()
