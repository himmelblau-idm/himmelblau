#!/usr/bin/env python3
"""Assertions inside the installed system (compatible with distro Python 3.6)."""

import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

SERVICES = ["himmelblaud.service", "himmelblaud-tasks.service"]
SOCKETS = ["himmelblaud.socket", "himmelblaud-tasks.socket", "himmelblaud-broker.socket"]
CONFIG = Path("/etc/himmelblau/himmelblau.conf")
DB = Path("/var/cache/himmelblaud/himmelblau.cache.db")
STATE = Path("/var/lib/himmelblaud")


def command(*args, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=kwargs.get("timeout", 15))
    if kwargs.get("check", True) and result.returncode:
        raise RuntimeError("{}: {} {}".format(args, result.stdout, result.stderr))
    return result


def ctl(*args, **kwargs):
    return command("systemctl", *args, **kwargs)


def wait_for(description, predicate, seconds=120):
    end = time.monotonic() + seconds
    last = ""
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            last = str(error)
        time.sleep(2)
    raise RuntimeError("Timed out waiting for {}: {}".format(description, last))


def working(result):
    return result.returncode == 0 and "working!" in result.stdout.splitlines()


def ready():
    if any(ctl("is-active", "--quiet", unit, check=False).returncode for unit in SERVICES):
        return False
    return working(command("aad-tool", "status", check=False))


def properties(unit):
    output = ctl("show", unit, "--property=MainPID,NRestarts,Result,InvocationID,ActiveState,SubState").stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def identities():
    if any(line.split(":", 1)[0] == "tux" for line in Path("/etc/passwd").read_text().splitlines()):
        raise RuntimeError("Local tux account would conceal NSS failure")
    records = []
    for name in ["tux", "tux@himmelblau-idm.org"]:
        lines = command("getent", "passwd", name).stdout.splitlines()
        if len(lines) != 1:
            raise RuntimeError("Expected exactly one NSS passwd record for " + name)
        fields = lines[0].split(":")
        if len(fields) != 7 or fields[0] != "tux" or not fields[2].isdigit() or not fields[3].isdigit():
            raise RuntimeError("Malformed/unexpected tux passwd record: " + repr(lines))
        if int(fields[2]) == 0 or int(fields[3]) == 0 or not fields[5].startswith("/") or not fields[6].startswith("/"):
            raise RuntimeError("Invalid identity fields: " + repr(fields))
        records.append(fields)
    if records[0] != records[1]:
        raise RuntimeError("Short name and UPN resolve inconsistently")
    record = records[0]
    if command("getent", "passwd", record[2]).stdout.strip().split(":") != record:
        raise RuntimeError("Numeric UID lookup differs")
    command("id", "tux")
    if command("id", "-u", "tux").stdout.strip() != record[2]:
        raise RuntimeError("id UID differs")
    if command("id", "-g", "tux").stdout.strip() != record[3]:
        raise RuntimeError("id GID differs")
    root = command("getent", "passwd", "root").stdout.strip().split(":")
    if len(root) != 7 or root[0] != "root" or root[2] != "0":
        raise RuntimeError("Local root lookup broken")
    print("NSS identity: " + ":".join(record), flush=True)
    return record


def loaded_sockets():
    return [unit for unit in SOCKETS
            if ctl("show", unit, "--property=LoadState", "--value", check=False).stdout.strip() == "loaded"]


def healthy():
    wait_for("daemon readiness", ready)
    before = {unit: properties(unit) for unit in SERVICES}
    for unit, props in before.items():
        if props["Result"] != "success" or int(props["MainPID"]) <= 0 or int(props["NRestarts"]) != 0:
            raise RuntimeError("Unhealthy service {}: {}".format(unit, props))
    for _ in range(6):
        time.sleep(5)
        if not ready():
            raise RuntimeError("Daemon became unresponsive during observation")
        for unit in SERVICES:
            if properties(unit) != before[unit]:
                raise RuntimeError("Service changed/restarted during observation: " + unit)
    for unit in loaded_sockets():
        if ctl("show", unit, "--property=SubState", "--value").stdout.strip() != "listening":
            raise RuntimeError("Socket is not listening: " + unit)
    # A missing oneshot is allowed only on historical baselines, but its failure is never ignored.
    init = ctl("show", "himmelblau-hsm-pin-init.service", "--property=LoadState,Result", check=False).stdout
    if "LoadState=loaded" in init and "Result=success" not in init:
        raise RuntimeError("HSM PIN initialization failed: " + init)


def state_snapshot():
    with sqlite3.connect("file:{}?mode=ro".format(DB), uri=True, timeout=10) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise RuntimeError("Database integrity check failed")
        rows = db.execute("SELECT key, value FROM hsm_int_t WHERE key IN ('mk', 'hmac') ORDER BY key").fetchall()
    if {key for key, _ in rows} != {"mk", "hmac"}:
        raise RuntimeError("Daemon did not initialize machine/HMAC keys")
    keys = {key: hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()
            for key, value in rows}
    sentinel = STATE / "package-smoke-sentinel"
    return {"config": CONFIG.read_text(), "keys": keys, "identity": identities(), "sentinel": sentinel.read_text()}


def lifecycle():
    if loaded_sockets() != SOCKETS:
        raise RuntimeError("Candidate package is missing daemon sockets")
    healthy()
    identity = identities()
    previous = properties(SERVICES[0])["InvocationID"]
    ctl("restart", *SERVICES, timeout=120)
    healthy()
    if properties(SERVICES[0])["InvocationID"] == previous:
        raise RuntimeError("Restart did not create a new invocation")
    if identities() != identity:
        raise RuntimeError("Identity changed across restart")
    ctl("stop", *SERVICES, timeout=120)
    for unit in SERVICES:
        if ctl("is-active", "--quiet", unit, check=False).returncode == 0:
            raise RuntimeError("Service did not stop: " + unit)
    ctl("start", *SERVICES, timeout=120)
    healthy()
    if identities() != identity:
        raise RuntimeError("Identity changed across stop/start")
    ctl("stop", *SERVICES, timeout=120)
    ctl("start", *SOCKETS, timeout=120)
    for unit in SOCKETS:
        if ctl("show", unit, "--property=SubState", "--value").stdout.strip() != "listening":
            raise RuntimeError("Socket unavailable for activation: " + unit)
    if ctl("is-active", "--quiet", SERVICES[0], check=False).returncode == 0:
        raise RuntimeError("Daemon already running before activation request")
    previous = properties(SERVICES[0])["InvocationID"]
    wait_for("socket-triggered client response", lambda: working(command("aad-tool", "status", check=False)))
    if properties(SERVICES[0])["InvocationID"] == previous:
        raise RuntimeError("Client did not activate a new daemon invocation")
    # Require automatic tasks startup when the packaged unit promises Upholds.
    upholds = ctl("show", SERVICES[0], "--property=Upholds", "--value").stdout.split()
    if SERVICES[1] not in upholds:
        ctl("start", SERVICES[1], timeout=120)
    healthy()
    if identities() != identity:
        raise RuntimeError("Identity changed after socket activation")


def main():
    phase = sys.argv[1]
    if phase == "boot":
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            raise RuntimeError("PID 1 must be real systemd")
        probe = Path("/sys/fs/cgroup/package-smoke-probe")
        probe.mkdir()
        probe.rmdir()
        wait_for("systemd boot", lambda: ctl("is-system-running", check=False).stdout.strip() in ("running", "degraded"))
        print(ctl("--failed", "--no-pager").stdout)
        Path("/var/tmp/smoke-boot-failures").write_text(ctl("--failed", "--no-pager").stdout)
    elif phase == "configure":
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text("[global]\ndomain = himmelblau-idm.org\nhsm_type = soft\ncn_name_mapping = true\n")
    elif phase in ("start", "start-baseline"):
        ctl("daemon-reload")
        sockets = SOCKETS if phase == "start" else loaded_sockets()
        if sockets:
            ctl("start", *sockets, timeout=120)
        ctl("start", *SERVICES, timeout=120)
        healthy()
        identities()
    elif phase == "lifecycle":
        lifecycle()
    elif phase == "snapshot":
        (STATE / "package-smoke-sentinel").write_text("preserve initialized state\n")
        Path("/var/tmp/package-smoke-before.json").write_text(json.dumps(state_snapshot()))
    elif phase == "preserved":
        healthy()  # Deliberately no daemon-reload/start/restart before this assertion.
        before = json.loads(Path("/var/tmp/package-smoke-before.json").read_text())
        if state_snapshot() != before:
            raise RuntimeError("Upgrade lost configuration, initialized state, or NSS identity")
        # Container-aware scripts may defer reload; verify recovery first, then test new units.
        ctl("daemon-reload")
    elif phase == "versions":
        family, records = sys.argv[2], json.loads(sys.argv[3])
        for record in records:
            if family == "deb":
                value = command("dpkg-query", "-W", "-f=${Status}|${Version}", record["name"]).stdout
                expected = "install ok installed|" + record["version"]
            else:
                value = command("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", record["name"]).stdout
                expected = record["version"]
            if value != expected:
                raise RuntimeError("Installed package identity differs: {} != {}".format(value, expected))
    elif phase == "rpm-older":
        result = command("rpm", "--eval", sys.argv[2]).stdout.strip()
        if result == "older":
            sys.exit(0)
        if result == "not-older":
            sys.exit(3)
        raise RuntimeError("Unexpected RPM version comparison result: " + repr(result))
    else:
        raise ValueError("Unknown phase: " + phase)


if __name__ == "__main__":
    main()
