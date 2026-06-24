#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import update_linux_entra_sso as updater


def release_payload(version: str, *, include_firefox: bool = True, include_thunderbird: bool = True) -> dict:
    assets = []
    if include_firefox:
        assets.append(
            {
                "name": f"linux_entra_sso-{version}.xpi",
                "browser_download_url": (
                    f"https://github.com/siemens/linux-entra-sso/releases/download/v{version}/"
                    f"linux_entra_sso-{version}.xpi"
                ),
            }
        )
    if include_thunderbird:
        assets.append(
            {
                "name": f"linux_entra_sso-{version}.thunderbird.xpi",
                "browser_download_url": (
                    f"https://github.com/siemens/linux-entra-sso/releases/download/v{version}/"
                    f"linux_entra_sso-{version}.thunderbird.xpi"
                ),
            }
        )
    return {"tag_name": f"v{version}", "assets": assets}


class GitRepoFixture:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        subprocess.run(["git", "init"], cwd=self.root, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.root, check=True)

    def close(self) -> None:
        self.tempdir.cleanup()

    def write_tracked(self, relative_path: str, text: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "add", relative_path], cwd=self.root, check=True)
        return path


class LinuxEntraSsoUpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = GitRepoFixture()

    def tearDown(self) -> None:
        self.repo.close()

    def test_numeric_version_comparison(self) -> None:
        self.assertGreater(updater.Version.parse("1.10.0"), updater.Version.parse("1.9.9"))

    def test_release_payload_requires_expected_assets(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "thunderbird"):
            updater.release_from_payload(release_payload("1.10.0", include_thunderbird=False))

    def test_noop_when_urls_already_match_latest(self) -> None:
        self.repo.write_tracked(
            "src/sso-policies/src/firefox/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.10.0/linux_entra_sso-1.10.0.xpi"',
        )
        release = updater.release_from_payload(release_payload("1.10.0"))

        changed = updater.update_tracked_urls(self.repo.root, release)

        self.assertEqual(changed, [])

    def test_rewrites_all_tracked_extension_urls(self) -> None:
        self.repo.write_tracked(
            "src/sso-policies/scripts/postinst",
            "\n".join(
                [
                    'FIREFOX_EXTENSION_URL="https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
                    'THUNDERBIRD_EXTENSION_URL="https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.thunderbird.xpi"',
                ]
            ),
        )
        self.repo.write_tracked(
            "src/sso-policies/src/firefox/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
        )
        self.repo.write_tracked(
            "src/sso-policies/src/thunderbird/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.thunderbird.xpi"',
        )
        self.repo.write_tracked(
            "nix/modules/himmelblau.nix",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
        )
        release = updater.release_from_payload(release_payload("1.10.0"))

        changed = updater.update_tracked_urls(self.repo.root, release)

        self.assertEqual(
            changed,
            [
                Path("nix/modules/himmelblau.nix"),
                Path("src/sso-policies/scripts/postinst"),
                Path("src/sso-policies/src/firefox/policies.json"),
                Path("src/sso-policies/src/thunderbird/policies.json"),
            ],
        )
        updater.validate_tracked_urls(self.repo.root, release)

    def test_normalizes_drift_without_newer_version(self) -> None:
        self.repo.write_tracked(
            "src/sso-policies/scripts/postinst",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
        )
        self.repo.write_tracked(
            "src/sso-policies/src/firefox/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.10.0/linux_entra_sso-1.10.0.xpi"',
        )
        release = updater.release_from_payload(release_payload("1.10.0"))

        changed = updater.update_tracked_urls(self.repo.root, release)

        self.assertEqual(changed, [Path("src/sso-policies/scripts/postinst")])
        updater.validate_tracked_urls(self.repo.root, release)

    def test_refuses_to_downgrade(self) -> None:
        self.repo.write_tracked(
            "src/sso-policies/src/firefox/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.10.0/linux_entra_sso-1.10.0.xpi"',
        )
        release = updater.release_from_payload(release_payload("1.9.9"))

        with self.assertRaisesRegex(RuntimeError, "Refusing to downgrade"):
            updater.update_tracked_urls(self.repo.root, release)

    def test_ignores_untracked_files(self) -> None:
        self.repo.write_tracked(
            "src/sso-policies/src/firefox/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
        )
        untracked = self.repo.root / "generated.spec"
        untracked.write_text(
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.8.0/linux_entra_sso-1.8.0.xpi"',
            encoding="utf-8",
        )
        release = updater.release_from_payload(release_payload("1.10.0"))

        updater.update_tracked_urls(self.repo.root, release)

        self.assertIn("v1.8.0", untracked.read_text(encoding="utf-8"))

    def test_ignores_tracked_test_fixture_urls(self) -> None:
        self.repo.write_tracked(
            "src/sso-policies/src/firefox/policies.json",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
        )
        test_fixture = self.repo.write_tracked(
            ".github/scripts/test_update_linux_entra_sso.py",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.10.0/linux_entra_sso-1.10.0.xpi"',
        )
        release = updater.release_from_payload(release_payload("1.9.9"))

        changed = updater.update_tracked_urls(self.repo.root, release)
        updater.validate_tracked_urls(self.repo.root, release)

        self.assertEqual(changed, [])
        self.assertIn("v1.10.0", test_fixture.read_text(encoding="utf-8"))

    def test_skips_tracked_directory_paths(self) -> None:
        self.repo.write_tracked(
            "current.txt",
            '"https://github.com/siemens/linux-entra-sso/releases/download/v1.9.9/linux_entra_sso-1.9.9.xpi"',
        )
        tracked_dir = self.repo.root / "docs-xml"
        tracked_dir.mkdir()
        release = updater.release_from_payload(release_payload("1.10.0"))

        with unittest.mock.patch.object(
            updater,
            "git_ls_files",
            return_value=[self.repo.root / "current.txt", tracked_dir],
        ):
            candidate_paths = ("current.txt", "docs-xml")
            changed = updater.update_tracked_urls(self.repo.root, release, candidate_paths)
            updater.validate_tracked_urls(self.repo.root, release, candidate_paths)

        self.assertEqual(changed, [Path("current.txt")])


if __name__ == "__main__":
    unittest.main()
