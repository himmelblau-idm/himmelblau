#!/usr/bin/env python3
"""Check generated units and optionally exercise their FD-store lifecycle.

Run the live tests with HIMMELBLAU_SYSTEMD_TESTS=1 python3
scripts/test_systemd_fdstore.py -v. They use disposable user units, a dummy
daemon and a synthetic token; no root, Entra account or installed daemon is used.
"""

import array
import configparser
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid


GENERATOR = Path(__file__).with_name("gen_servicefiles.py")


def generate(root, version):
    # The generator also writes platform/systemd relative to its own location.
    scripts = root / "scripts"
    scripts.mkdir(exist_ok=True)
    shutil.copyfile(GENERATOR, scripts / GENERATOR.name)
    out = root / "units"
    subprocess.run(
        [sys.executable, str(scripts / GENERATOR.name), "--out-dir", str(out),
         "--assume-version", str(version)],
        check=True, capture_output=True, text=True,
    )
    return out


def read_unit(path):
    unit = configparser.ConfigParser(strict=False, interpolation=None)
    unit.optionxform = str
    unit.read(path)
    return unit


class GeneratorTests(unittest.TestCase):
    def test_fd_store_version_gating(self):
        for version in (229, 234, 249, 252, 253, 254, 255, 256, 257, 260):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                unit = read_unit(generate(Path(tmp), version) / "himmelblaud.service")
                service = unit["Service"]
                self.assertEqual(service.get("FileDescriptorStoreMax"), "1" if version >= 234 else None)
                self.assertEqual(service.get("FileDescriptorStorePreserve"), "restart" if version >= 254 else None)


@unittest.skipUnless(os.getenv("HIMMELBLAU_SYSTEMD_TESTS") == "1", "opt-in user systemd integration tests")
class LifecycleTests(unittest.TestCase):
    def ctl(self, *args, check=True):
        result = subprocess.run(
            ["systemctl", "--user", *args], capture_output=True, text=True, timeout=30,
        )
        if check and result.returncode:
            self.fail(f"systemctl {' '.join(args)}: {result.stderr}")
        return result.stdout.strip()

    def prop(self, name):
        return self.ctl("show", self.service, f"--property={name}", "--value")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="himmelblau-fdstore-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        version = int(self.ctl("show", "--property=Version", "--value").split(".")[0])
        if version < 254:
            self.skipTest("reproducing pinned FD stores requires systemd >= 254")
        self.units = generate(self.root, version)
        self.name = "himmelblau-fdstore-test-" + uuid.uuid4().hex
        self.service = self.name + ".service"
        self.anchor = self.name + ".target"
        self.sockets = [self.name + suffix for suffix in (".socket", "-tasks.socket", "-broker.socket")]
        self.runtime = Path(os.environ["XDG_RUNTIME_DIR"]) / "systemd/user"
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self.cleanup_units)
        self.write_units()
        # Keep the fixture loaded after stopping, as the real enabled daemon is.
        # Otherwise garbage collection can hide the pinned-descriptor state.
        (self.runtime / self.anchor).write_text(
            f"[Unit]\nWants={self.service}\n"
        )
        self.ctl("daemon-reload")
        self.ctl("start", "--job-mode=ignore-dependencies", self.anchor)

    def write_units(self, preserve=None, sockets=True):
        daemon = read_unit(self.units / "himmelblaud.service")
        # Keep the generated lifecycle settings; omit host-only sandbox, TPM,
        # network and login targets so the fixture runs in the user manager.
        service = daemon["Service"]
        settings = [f"{key}={service[key]}" for key in
                    ("FileDescriptorStoreMax", "FileDescriptorStorePreserve") if key in service]
        if preserve:
            settings = [line for line in settings if not line.startswith("FileDescriptorStorePreserve=")]
            settings.append("FileDescriptorStorePreserve=" + preserve)
        dependencies = ""
        if sockets:
            dependencies = "Requires=" + daemon["Unit"]["Requires"].replace("himmelblaud", self.name)
            settings.append("Sockets=" + service["Sockets"].replace("himmelblaud", self.name))
        (self.runtime / self.service).write_text(
            f"[Unit]\n{dependencies}\n[Service]\nType=notify\n"
            f'ExecStart={sys.executable} "{Path(__file__).resolve()}" --daemon\n'
            "TimeoutStartSec=10\nTimeoutStopSec=10\n" + "\n".join(settings) + "\n"
        )
        if sockets:
            for name in self.sockets:
                source = name.replace(self.name, "himmelblaud")
                unit = read_unit(self.root / "platform/systemd" / source)
                # Preserve the socket/service ordering and lifetime relationships.
                relationships = "\n".join(
                    f"{key}={unit['Unit'][key].replace('himmelblaud', self.name)}"
                    for key in ("Before", "PartOf") if key in unit["Unit"]
                )
                (self.runtime / name).write_text(
                    f"[Unit]\n{relationships}\n[Socket]\n"
                    f"ListenStream={self.root / source}\n"
                    f"FileDescriptorName={unit['Socket']['FileDescriptorName']}\n"
                    f"Service={self.service}\n"
                )
        self.ctl("daemon-reload")

    def cleanup_units(self):
        self.ctl("stop", self.anchor, self.service, *self.sockets, check=False)
        self.ctl("clean", "--what=fdstore", self.service, check=False)
        self.ctl("reset-failed", self.service, *self.sockets, check=False)
        for name in (self.anchor, self.service, *self.sockets):
            (self.runtime / name).unlink(missing_ok=True)
        self.ctl("daemon-reload")

    def assert_running(self, restored):
        self.assertEqual(self.prop("ActiveState"), "active")
        self.assertEqual(self.prop("StatusText"), f"restored={restored} sockets=3")
        for name in self.sockets:
            self.assertEqual(self.ctl("is-active", name), "active")

    def test_repeated_restarts_preserve_tokens(self):
        self.ctl("start", self.service)
        self.assert_running(0)
        for _ in range(3):
            self.ctl("restart", self.service)
            self.assert_running(1)

    def test_full_stop_releases_tokens_and_sockets(self):
        self.ctl("start", self.service)
        self.ctl("stop", self.service)
        self.assertEqual(self.prop("SubState"), "dead")
        self.assertEqual(self.prop("NFileDescriptorStore"), "0")
        for name in self.sockets:
            self.assertEqual(self.ctl("is-active", name, check=False), "inactive")
        self.ctl("start", self.service)
        self.assert_running(0)

    def test_upgrade_from_running_daemon_without_socket_units(self):
        self.write_units(preserve="yes", sockets=False)
        self.ctl("start", self.service)
        self.write_units()
        self.ctl("restart", self.service)
        self.assert_running(1)

    def test_upgrade_recovers_already_pinned_daemon(self):
        self.write_units(preserve="yes")
        self.ctl("start", self.service)
        # The old setting strands a restart after its socket jobs fail.
        self.ctl("restart", self.service, check=False)
        self.assertEqual(self.prop("SubState"), "dead-resources-pinned")
        self.assertEqual(self.prop("NFileDescriptorStore"), "1")
        self.write_units()
        self.ctl("start", self.service)
        self.assert_running(0)


def dummy_daemon():
    """Store a synthetic token on SIGTERM, and validate it on the next start."""
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    restored = 0
    sockets = 0
    token = None
    for fd, name in enumerate(names, 3):
        if name == "test-token":
            assert os.pread(fd, 32, 0) == b"synthetic-token"
            token = fd
            restored += 1
        elif name.startswith("himmelblaud"):
            with socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
            sockets += 1
    if token is None:
        token = os.memfd_create("synthetic-token")
        os.write(token, b"synthetic-token")
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.connect(os.environ["NOTIFY_SOCKET"].replace("@", "\0", 1))

    def stop(signum, frame):
        notify.sendmsg([b"FDSTORE=1\nFDNAME=test-token"],
                       [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [token]))])
        # Wait until the manager processes the notification before exiting;
        # otherwise it can lose the sender's identity and discard the store.
        reader, writer = os.pipe()
        notify.sendmsg([b"BARRIER=1"],
                       [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [writer]))])
        os.close(writer)
        os.read(reader, 1)
        os.close(reader)
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    notify.send(f"READY=1\nSTATUS=restored={restored} sockets={sockets}".encode())
    while True:
        signal.pause()


if __name__ == "__main__":
    if sys.argv[1:] == ["--daemon"]:
        dummy_daemon()
    else:
        unittest.main()
