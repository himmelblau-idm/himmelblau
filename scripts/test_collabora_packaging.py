#!/usr/bin/env python3
"""Exercise Collabora maintainer scripts without touching real users/services.

Run with: python3 scripts/test_collabora_packaging.py -v
"""

import configparser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PLATFORM = Path(__file__).resolve().parents[1] / "src/collabora/platform"
UNIT = "himmelblau-collabora.service"
MOCK = r'''
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ["FIXTURE"])
config = json.loads((root / "config.json").read_text())
args = sys.argv[1:]
command = Path(sys.argv[0]).name
with (root / "calls").open("a") as output:
    output.write(json.dumps([command, os.environ.get("DPKG_ROOT", ""), *args]) + "\n")
if command == "deb-systemd-helper":
    sys.exit(int(os.environ.get("BOOKKEEPING_ERROR", "0")))
if command == "getent":
    kind = "UID" if len(args) > 1 else "ENUM"
    if os.environ.get(f"GETENT_{kind}_EMPTY") == "1":
        sys.exit(0)
    for user, values in config.items():
        if len(args) == 1 or args[1] == str(values["uid"]):
            print(f"{user}:x:{values['uid']}:1000::{root / user}:/bin/sh")
    sys.exit(int(os.environ.get(f"GETENT_{kind}_ERROR", "0")))
if command == "runuser":
    user = args[1]
    args = args[args.index("--") + 1:]
    assert args.pop(0) == "env"
    env = dict(os.environ, FIXTURE_USER=user)
    while args and "=" in args[0]:
        key, value = args.pop(0).split("=", 1)
        env[key] = value
    if args == ["/usr/bin/himmelblau-collabora", "cleanup"]:
        with (root / "events").open("a") as output:
            output.write(json.dumps([user, "cleanup"]) + "\n")
        with (root / "cleanup-environments").open("a") as output:
            output.write(json.dumps([user, {key: env.get(key) for key in
                ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME")}]) + "\n")
        sys.exit(config[user].get("cleanup_error", 0))
    assert args[0] == "systemctl", args
    sys.exit(subprocess.run(args, env=env).returncode)
assert command == "systemctl", command
user = os.environ.get("FIXTURE_USER", "system")
with (root / "events").open("a") as output:
    output.write(json.dumps([user, *args]) + "\n")
if args[0].startswith("--root="):
    sys.exit(int(os.environ.get("BOOKKEEPING_ERROR", "0")))
if args[0] == "--global":
    sys.exit(0)
if args[0] == "show":
    uid = int(args[1].split("@")[1].split(".")[0])
    values = next(v for v in config.values() if v["uid"] == uid)
    if not values.get("manager_error", False):
        print(values.get("manager_state", "active"))
    sys.exit(int(values.get("manager_error", False)))
assert args[0] == "--user", args
values = config[user]
if args[1] == "list-units":
    if values.get("list_error", False):
        sys.exit(1)
    if values.get("loaded", True):
        print("himmelblau-collabora.service loaded active running Collabora")
elif args[1] == "stop":
    sys.exit(int(values.get("stop_error", False)))
elif args[1] == "restart":
    # Model the in-memory editor capability lost by a restart.
    (root / user / "editor-session").unlink(missing_ok=True)
elif args[1] not in ("start", "daemon-reload"):
    raise AssertionError(args)
'''


class PackagingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="collabora-packaging-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "run/user"
        self.runtime.mkdir(parents=True)
        self.users = {}
        for name in ("systemctl", "runuser", "getent"):
            self.mock_command(name)
        # An isolated PATH ensures the tests never reach the host's systemctl.
        (self.bin / "cut").symlink_to("/usr/bin/cut")
        self.env = dict(os.environ, PATH=str(self.bin), FIXTURE=str(self.root), DPKG_ROOT="")

    def mock_command(self, name):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + MOCK)
        path.chmod(0o755)

    def user(self, name="alice", uid=1000, runtime=True, **values):
        self.users[name] = dict(uid=uid, **values)
        home = self.root / name
        (home / ".local/state/himmelblau-collabora").mkdir(parents=True)
        (home / "editor-session").write_text("unsaved editor capability")
        if runtime:
            (self.runtime / str(uid)).mkdir()

    def run_script(self, name, *arguments):
        (self.root / "config.json").write_text(json.dumps(self.users))
        # Rewrite only the runtime root in a temporary script, never production
        # files or the real /run/user tree.
        script = self.root / name
        script.write_text((PLATFORM / name).read_text().replace(
            "/run/user/", str(self.runtime) + "/"))
        return subprocess.run(["/bin/sh", str(script), *arguments], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def events(self):
        path = self.root / "events"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def calls(self):
        path = self.root / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_target_root_uses_helper_without_touching_host_users(self):
        self.user()
        self.mock_command("deb-systemd-helper")
        (self.bin / "systemctl").unlink()
        target = str(self.root / "target root")
        self.env["DPKG_ROOT"] = target
        for script, argument, action in (("postinst", "configure", "enable"),
                                         ("prerm", "remove", "disable")):
            with self.subTest(script=script):
                before = len(self.calls())
                result = self.run_script(script, argument)
                self.assertEqual(result.returncode, 0, result.stderr)
                actions = ("update-state", action) if action == "disable" else (action,)
                self.assertEqual(self.calls()[before:], [
                    ["deb-systemd-helper", target, "--user", step, UNIT] for step in actions])

    def test_target_root_systemctl_does_not_require_helper_state(self):
        self.user()
        self.mock_command("deb-systemd-helper")
        target = str(self.root / "target root")
        self.env["DPKG_ROOT"] = target
        for script, argument, action in (("postinst", "configure", "enable"),
                                         ("prerm", "remove", "disable")):
            with self.subTest(script=script):
                before = len(self.calls())
                result = self.run_script(script, argument)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls()[before:], [
                    ["systemctl", target, f"--root={target}", "--global", action, UNIT]])

    def test_target_root_bookkeeping_failure_cannot_fall_through_to_host(self):
        self.user()
        target = str(self.root / "target root")
        self.env.update(DPKG_ROOT=target, BOOKKEEPING_ERROR="1")
        for helper in (False, True):
            if helper:
                self.mock_command("deb-systemd-helper")
                (self.bin / "systemctl").unlink()
            for script, argument in (("postinst", "configure"), ("prerm", "remove")):
                with self.subTest(helper=helper, script=script):
                    before = len(self.calls())
                    result = self.run_script(script, argument)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = self.calls()[before:]
                    self.assertEqual(len(calls), 2 if helper and script == "prerm" else 1)
                    for call in calls:
                        self.assertEqual(call[0], "deb-systemd-helper" if helper else "systemctl")
                        self.assertEqual(call[1], target)

    def test_target_root_without_unit_tools_never_inspects_host_users(self):
        self.user()
        self.env["DPKG_ROOT"] = str(self.root / "target root")
        (self.bin / "systemctl").unlink()
        for script, argument in (("postinst", "configure"), ("prerm", "remove")):
            result = self.run_script(script, argument)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_uid_lookup_failure_or_empty_record_prevents_cleanup(self):
        self.user()
        for mode in ("ERROR", "EMPTY"):
            with self.subTest(mode=mode):
                key = f"GETENT_UID_{mode}"
                self.env[key] = "1"
                result = self.run_script("prerm", "remove")
                del self.env[key]
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Cannot look up user for runtime UID 1000", result.stderr)
                self.assertFalse(any(event[-1] == "cleanup" for event in self.events()))
                self.assertNotIn(["system", "--global", "disable", UNIT], self.events())

    def test_passwd_enumeration_failure_or_empty_result_prevents_cleanup(self):
        self.user(runtime=False)
        for mode in ("ERROR", "EMPTY"):
            with self.subTest(mode=mode):
                key = f"GETENT_ENUM_{mode}"
                self.env[key] = "1"
                result = self.run_script("prerm", "remove")
                del self.env[key]
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Cannot enumerate profile owners", result.stderr)
                self.assertFalse(any(event[-1] == "cleanup" for event in self.events()))
                self.assertNotIn(["system", "--global", "disable", UNIT], self.events())

    def test_postinst_starts_without_restarting_existing_documents(self):
        self.user()
        for argument in ("configure", "1", "2"):
            result = self.run_script("postinst", argument)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((self.root / "alice/editor-session").exists())
        self.assertEqual(self.events().count(["alice", "--user", "start", UNIT]), 3)

    def test_removal_stops_bridges_then_cleans_profiles_then_disables(self):
        self.user()
        self.user("bob", 1001)
        self.user("offline", 1002, runtime=False)
        for argument in ("remove", "0"):
            with self.subTest(argument=argument):
                before = len(self.events())
                result = self.run_script("prerm", argument)
                self.assertEqual(result.returncode, 0, result.stderr)
                events = self.events()[before:]
                for name in ("alice", "bob", "offline"):
                    self.assertIn([name, "cleanup"], events)
                    self.assertLess(events.index(["bob", "--user", "stop", UNIT]),
                                    events.index([name, "cleanup"]))
                self.assertEqual(events[-1], ["system", "--global", "disable", UNIT])
                self.assertEqual(events.count(["system", "--global", "disable", UNIT]), 1)

    def test_removal_cleans_profile_owners_with_low_or_root_uids(self):
        self.user("root", 0)
        self.user("enterprise", 500)
        result = self.run_script("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("root", "enterprise"):
            self.assertIn([name, "--user", "stop", UNIT], self.events())
            self.assertIn([name, "cleanup"], self.events())

    def test_stop_failure_aborts_before_any_profile_cleanup(self):
        self.user()
        self.user("bob", 1001, stop_error=True)
        result = self.run_script("prerm", "remove")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot stop Collabora bridge for bob", result.stderr)
        self.assertFalse(any(event[-1] == "cleanup" for event in self.events()))
        self.assertNotIn(["system", "--global", "disable", UNIT], self.events())

    def test_unloaded_service_can_be_cleaned_without_stopping(self):
        self.user(loaded=False)
        result = self.run_script("prerm", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["alice", "cleanup"], self.events())
        self.assertNotIn(["alice", "--user", "stop", UNIT], self.events())

    def test_confirmed_inactive_manager_can_be_cleaned(self):
        self.user(list_error=True, manager_state="inactive")
        result = self.run_script("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["alice", "cleanup"], self.events())

    def test_unreachable_user_bus_does_not_prove_service_is_stopped(self):
        self.user(list_error=True)
        for values in ({"manager_state": "active"}, {"manager_state": "failed"},
                       {"manager_state": ""}, {"manager_error": True}):
            with self.subTest(values=values):
                self.users["alice"].update(values)
                result = self.run_script("prerm", "remove")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Cannot determine Collabora bridge status", result.stderr)
                self.assertFalse(any(event[-1] == "cleanup" for event in self.events()))
                self.assertNotIn(["system", "--global", "disable", UNIT], self.events())

    def test_missing_systemctl_with_live_runtime_refuses_cleanup(self):
        self.user()
        (self.bin / "systemctl").unlink()
        result = self.run_script("prerm", "remove")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event[-1] == "cleanup" for event in self.events()))

    def test_offline_profiles_can_be_cleaned_without_systemctl(self):
        self.user(runtime=False)
        (self.bin / "systemctl").unlink()
        result = self.run_script("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["alice", "cleanup"], self.events())

    def test_cleanup_failure_is_reported(self):
        self.user(cleanup_error=1)
        result = self.run_script("prerm", "remove")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Collabora cleanup failed for alice", result.stderr)
        self.assertNotIn(["system", "--global", "disable", UNIT], self.events())

    def test_cleanup_pins_discovered_paths_despite_inherited_xdg_environment(self):
        self.user()
        self.user("offline", 1001, runtime=False)
        self.env.update(HOME=str(self.root / "package-manager-home"),
                        XDG_CONFIG_HOME=str(self.root / "unrelated config"),
                        XDG_STATE_HOME=str(self.root / "unrelated state"))
        result = self.run_script("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        environments = dict(json.loads(line) for line in
                            (self.root / "cleanup-environments").read_text().splitlines())
        for user in ("alice", "offline"):
            home = self.root / user
            self.assertEqual(environments[user], {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_STATE_HOME": str(home / ".local/state"),
            })

    def test_debian_and_rpm_upgrades_do_not_stop_or_clean(self):
        self.user()
        for argument in ("upgrade", "1"):
            result = self.run_script("prerm", argument)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [])

    def test_debian_non_removal_modes_do_not_stop_or_clean(self):
        self.user()
        for arguments in (("failed-upgrade", "2.0", "2.1"),
                          ("deconfigure", "in-favour", "other-package", "2.1")):
            with self.subTest(arguments=arguments):
                before = self.events()
                result = self.run_script("prerm", *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.events(), before)

    def test_unknown_empty_or_missing_arguments_do_not_stop_or_clean(self):
        self.user()
        for arguments in (("unknown",), ("",), (), ("2",)):
            with self.subTest(arguments=arguments):
                before = self.events()
                result = self.run_script("prerm", *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.events(), before)

    def test_unit_keeps_system_protection_without_readonly_user_storage(self):
        unit = configparser.ConfigParser()
        unit.read(PLATFORM / UNIT)
        service = unit["Service"]
        # full leaves home, Flatpak profiles and custom XDG data paths writable;
        # strict makes them read-only without an explicit write-path allowlist.
        self.assertEqual(service["ProtectSystem"], "full")
        self.assertEqual(service["NoNewPrivileges"], "yes")
        self.assertEqual(service["PrivateTmp"], "yes")
        self.assertNotIn("ProtectHome", service)


if __name__ == "__main__":
    unittest.main()
