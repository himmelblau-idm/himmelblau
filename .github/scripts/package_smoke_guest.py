#!/usr/bin/env python3
"""Probe the packaged services without enrollment, credentials, or login."""

from pathlib import Path
import subprocess
import sys
import time

SERVICES = ["himmelblaud.service", "himmelblaud-tasks.service"]


def command(*args, check=True, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def wait_for(predicate, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        time.sleep(2)
    raise RuntimeError("Timed out waiting for systemd/service readiness")


def working(result):
    return result.returncode == 0 and "working!" in result.stdout.splitlines()


def ready():
    return (all(command("systemctl", "is-active", "--quiet", unit, check=False).returncode == 0 for unit in SERVICES)
            and working(command("aad-tool", "status", check=False)))


def properties(unit):
    output = command("systemctl", "show", unit, "--property=MainPID,NRestarts,InvocationID,Result").stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def healthy():
    wait_for(ready)
    before = {unit: properties(unit) for unit in SERVICES}
    for props in before.values():
        if int(props["MainPID"]) <= 0 or int(props["NRestarts"]) != 0 or props["Result"] != "success":
            raise RuntimeError("Unhealthy packaged service: " + repr(props))
    for _ in range(6):
        time.sleep(5)
        if not ready() or any(properties(unit) != before[unit] for unit in SERVICES):
            raise RuntimeError("Service stopped, restarted, or became unresponsive")


def main():
    if sys.argv[1] == "boot":
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            raise RuntimeError("PID 1 is not systemd")
        wait_for(lambda: command("systemctl", "is-system-running", check=False).stdout.strip() in ("running", "degraded"))
    elif sys.argv[1] == "services":
        config = Path("/etc/himmelblau/himmelblau.conf")
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("[global]\ndomain = himmelblau-idm.org\nhsm_type = soft\n")
        command("systemctl", "daemon-reload")
        command("systemctl", "start", *SERVICES, timeout=120)
        healthy()
        invocation = properties(SERVICES[0])["InvocationID"]
        command("systemctl", "restart", *SERVICES, timeout=120)
        healthy()
        if properties(SERVICES[0])["InvocationID"] == invocation:
            raise RuntimeError("Restart did not create a new invocation")
        command("systemctl", "stop", *SERVICES, timeout=120)
        if any(command("systemctl", "is-active", "--quiet", unit, check=False).returncode == 0 for unit in SERVICES):
            raise RuntimeError("Service failed to stop")
        command("systemctl", "start", *SERVICES, timeout=120)
        healthy()
    else:
        raise ValueError("Unknown probe")


if __name__ == "__main__":
    main()
