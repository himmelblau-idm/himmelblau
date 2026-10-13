#!/usr/bin/env python3
"""Test home creation as root ONLY in a disposable Fedora/Aurora SELinux VM.

Requires Himmelblau and its SELinux package, Python 3, setools-console and
policycoreutils. Install the policy built from src/selinux/src/himmelblaud.te,
then run: sudo python3 scripts/test_selinux_home_labels.py

Uses private configuration/socket/skeleton mounts and a synthetic UID/GID 0
HomeDirectory request; no tenant login or identity/enrollment changes. Checks
every copied fixture entry before any relabeling, then dry-runs restorecon.
Global SELinux must be enforcing; reports the loaded task domain's mode without
changing it. Removes the temporary unit, home and alias on completion.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile


# Ordinary nested content and each special-name transition in the policy.
# The daemon copies this private fixture through its /etc/skel bind mount.
SKELETON_FILES = {
    ".bashrc": b"# Himmelblau home-label regression\n",
    "Documents/nested/example.txt": b"ordinary nested content\n",
    ".config/himmelblau/nested/settings.conf": b"fixture=true\n",
    ".local/share/notes.txt": b"shared data\n",
    ".local/share/flatpak/nested/metadata": b"flatpak fixture\n",
    ".ssh/config": b"# no keys or hosts in this fixture\n",
}


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def label_type(path):
    context = os.getxattr(path, "security.selinux", follow_symlinks=False)
    return context.decode().rstrip("\0").split(":")[2]


def expected_type(path):
    return output("matchpathcon", "-n", str(path)).split(":")[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--home-prefix", choices=["/home", "/var/home"],
        default="/var/home" if Path("/var/home").is_dir() else "/home",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Run as root in a disposable test VM")
    mode = output("getenforce")
    if mode != "Enforcing":
        raise RuntimeError("This regression requires global SELinux Enforcing")
    print(output("rpm", "-q", "himmelblau", "himmelblau-selinux",
                 "selinux-policy", "selinux-policy-targeted"), flush=True)
    permissive_types = output("seinfo", "--permissive=himmelblaud_tasks_t")
    permissive = bool(re.search(
        r"^\s*(?:type\s+)?himmelblaud_tasks_t(?:[,;\s]|$)",
        permissive_types, re.M,
    ))
    print("Global SELinux:", mode, flush=True)
    print("Loaded himmelblaud_tasks_t:",
          "permissive" if permissive else "enforcing", flush=True)
    prefix = Path(args.home_prefix)
    print(f"Parent {prefix}:", label_type(prefix), flush=True)
    if label_type(prefix) != "home_root_t":
        raise RuntimeError(f"Correct the parent label before testing: restorecon {prefix}")
    failures = []
    with tempfile.TemporaryDirectory(prefix="himmel-home-label-") as directory:
        root = Path(directory)
        home = prefix / root.name
        alias = prefix / (root.name + "-alias")
        if os.path.lexists(home) or os.path.lexists(alias):
            raise RuntimeError("Test paths already exist")
        skeleton = root / "skel"
        skeleton.mkdir()
        for relative, content in SKELETON_FILES.items():
            path = skeleton / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        entries = sorted(skeleton.rglob("*"))
        config, endpoint = root / "config", root / "tasks.sock"
        unit = root.name
        config.write_text(
            f"[global]\nhome_prefix = {prefix}/\n"
            f"task_socket_path = {endpoint}\nuse_etc_skel = true\nselinux = true\n"
        )
        subprocess.run(["chcon", "-t", "himmelblau_var_run_t", str(root)], check=True)
        subprocess.run(["chcon", "-t", "himmelblau_etc_t", str(config)], check=True)
        subprocess.run(["chcon", "-R", "-t", "etc_t", str(skeleton)], check=True)
        with socket.socket(socket.AF_UNIX) as server, (root / "log").open("w") as log:
            server.bind(str(endpoint))
            server.listen(1)
            server.settimeout(20)
            subprocess.run(["chcon", "-t", "himmelblau_var_run_t", str(endpoint)], check=True)
            task = subprocess.Popen([
                "systemd-run", "--quiet", "--wait", "--collect", "--unit=" + unit,
                "-p", f"BindReadOnlyPaths={config}:/etc/himmelblau/himmelblau.conf",
                "-p", f"BindReadOnlyPaths={skeleton}:/etc/skel",
                "/usr/sbin/himmelblaud_tasks",
            ], stdout=log, stderr=log)
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(20)
                    pid = output("systemctl", "show", unit, "--property=MainPID", "--value")
                    context = Path(f"/proc/{pid}/attr/current").read_text().rstrip("\0")
                    if ":himmelblaud_tasks_t:" not in context:
                        raise RuntimeError("Unexpected task daemon domain")
                    print("Task process:", context, flush=True)
                    connection.sendall(json.dumps({"HomeDirectory": {
                        "uid": 0, "gid": 0, "name": root.name, "aliases": [alias.name],
                    }}).encode())
                    data = b""
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            raise RuntimeError("Task daemon disconnected")
                        data += chunk
                        try:
                            response = json.loads(data)
                            break
                        except json.JSONDecodeError:
                            continue
                    if response != {"Success": 0}:
                        raise RuntimeError("HomeDirectory task failed")
                for name, path in [("HOME", home), ("ALIAS", alias)]:
                    actual, expected = label_type(path), expected_type(path)
                    print(f"{name}: actual={actual}, expected={expected}", flush=True)
                    if actual != expected:
                        failures.append(name + " label")
                if not alias.is_symlink() or os.readlink(alias) != home.name:
                    failures.append("alias target")
                mismatches = 0
                for source in entries:
                    relative = source.relative_to(skeleton)
                    target = home / relative
                    if not os.path.lexists(target):
                        failures.append(f"missing skeleton entry: {relative}")
                        continue
                    if source.is_file():
                        copied = (not target.is_symlink() and target.is_file()
                                  and source.read_bytes() == target.read_bytes())
                    else:
                        copied = not target.is_symlink() and target.is_dir()
                    actual, expected = label_type(target), expected_type(target)
                    print(f"SKEL {relative}: actual={actual}, expected={expected}, "
                          f"contents={'OK' if copied else 'FAIL'}", flush=True)
                    if not copied:
                        failures.append(f"skeleton contents differ: {relative}")
                    if actual != expected:
                        mismatches += 1
                print(f"SKELETON: {len(entries)} entries checked, "
                      f"{mismatches} label mismatches", flush=True)
                if mismatches:
                    failures.append("skeleton labels")
                changes = output("restorecon", "-nRv", str(home), str(alias))
                if changes:
                    failures.append("restorecon would change labels")
                print("restorecon dry-run:",
                      "corrections required" if changes else "no corrections", flush=True)
            finally:
                subprocess.run(["systemctl", "stop", unit], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    task.wait(timeout=20)
                finally:
                    if alias.is_symlink():
                        alias.unlink()
                    if home.is_dir():
                        shutil.rmtree(home)
    print("FAIL: " + ", ".join(failures) if failures
          else "PASS: home, alias and skeleton", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
