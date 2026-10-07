"""Tests for scheduled stable release reconciliation without network writes."""

import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error


MODULE = Path(__file__).with_name("stable_release_scan.py")
SPEC = importlib.util.spec_from_file_location("stable_release_scan", MODULE)
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


class SelectionTests(unittest.TestCase):
    def test_latest_tag_must_belong_to_branch(self):
        with patch.object(scan.packages, "resolve", side_effect=["a" * 40, "b" * 40]), \
             patch.object(scan.packages, "version", side_effect=["4.0.5", "4.0.5"]), \
             patch.object(scan.packages, "ancestor", return_value=True):
            self.assertEqual(scan.latest_tag("stable-4.x"), "4.0.5")

        with patch.object(scan.packages, "resolve", return_value="a" * 40), \
             patch.object(scan.packages, "version", return_value="3.1.14"):
            with self.assertRaisesRegex(ValueError, "another stable branch"):
                scan.latest_tag("stable-4.x")

    def test_missing_or_unreachable_tag_fails(self):
        with patch.object(scan.packages, "resolve", side_effect=["a" * 40, ValueError()]), \
             patch.object(scan.packages, "version", return_value="4.0.6"):
            with self.assertRaisesRegex(ValueError, "has no tag"):
                scan.latest_tag("stable-4.x")
        with patch.object(scan.packages, "resolve", side_effect=["a" * 40, "b" * 40]), \
             patch.object(scan.packages, "version", return_value="4.0.6"), \
             patch.object(scan.packages, "ancestor", return_value=False):
            with self.assertRaisesRegex(ValueError, "not reachable"):
                scan.latest_tag("stable-4.x")


class PackageStatusTests(unittest.TestCase):
    def test_checks_exact_package_identities_with_one_lookup_per_format(self):
        entries = [{"spec": json.dumps({"repository": "himmelblau/v_4", "format": "deb",
                                        "tag": "4.0.5", "distro": distro,
                                        "architecture": "amd64", "expected_packages": [{"name": distro}]})}
                   for distro in ("ubuntu22.04", "ubuntu24.04")]
        with patch.object(scan.packages, "matrix", return_value={"include": entries}), \
             patch.object(scan.packages, "api_packages", return_value=[]) as lookup, \
             patch.object(scan.packages, "upload_plan", side_effect=[(["missing"], False), ([], True)]):
            missing, pending = scan.package_status("4.0.5")
        self.assertEqual(missing, ["ubuntu22.04/amd64"])
        self.assertEqual(pending, ["ubuntu24.04/amd64"])
        lookup.assert_called_once_with("himmelblau/v_4", "deb", "4.0.5")


class ReconciliationTests(unittest.TestCase):
    def test_complete_tags_exit_without_dispatch(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": scan.REPOSITORY}), \
             patch.object(scan, "latest_tag", side_effect=["3.1.14", "4.0.5"]), \
             patch.object(scan, "active_tags", return_value=set()), \
             patch.object(scan, "release_published", return_value=True), \
             patch.object(scan, "package_status", return_value=([], [])), \
             patch.object(scan, "dispatch") as dispatch, \
             patch.object(scan.packages, "require_api_key"), \
             patch.object(scan.packages, "summary"):
            scan.scan()
        dispatch.assert_not_called()

    def test_missing_work_dispatches_each_workflow_once(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": scan.REPOSITORY}), \
             patch.object(scan, "latest_tag", side_effect=[None, "4.0.5"]), \
             patch.object(scan, "active_tags", return_value=set()), \
             patch.object(scan, "release_published", return_value=False), \
             patch.object(scan, "package_status", return_value=(["ubuntu24.04/amd64"], [])), \
             patch.object(scan, "dispatch") as dispatch, \
             patch.object(scan.packages, "require_api_key"), \
             patch.object(scan.packages, "summary"):
            scan.scan()
        self.assertEqual(dispatch.call_args_list, [
            unittest.mock.call("publish-release.yml", "4.0.5"),
            unittest.mock.call("stable-packages.yml", "4.0.5"),
        ])

    def test_in_flight_work_is_not_duplicated(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": scan.REPOSITORY}), \
             patch.object(scan, "latest_tag", side_effect=[None, "4.0.5"]), \
             patch.object(scan, "active_tags", return_value={"4.0.5"}), \
             patch.object(scan, "release_published", return_value=False), \
             patch.object(scan, "package_status") as package_status, \
             patch.object(scan, "dispatch") as dispatch, \
             patch.object(scan.packages, "require_api_key"), \
             patch.object(scan.packages, "summary"):
            scan.scan()
        package_status.assert_not_called()
        dispatch.assert_not_called()

    def test_pending_packages_wait_for_next_scan(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": scan.REPOSITORY}), \
             patch.object(scan, "latest_tag", side_effect=[None, "4.0.5"]), \
             patch.object(scan, "active_tags", return_value=set()), \
             patch.object(scan, "release_published", return_value=True), \
             patch.object(scan, "package_status", return_value=([], ["ubuntu24.04/amd64"])), \
             patch.object(scan, "dispatch") as dispatch, \
             patch.object(scan.packages, "require_api_key"), \
             patch.object(scan.packages, "summary"):
            scan.scan()
        dispatch.assert_not_called()

    def test_github_failure_does_not_dispatch(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": scan.REPOSITORY}), \
             patch.object(scan, "latest_tag", side_effect=[None, "4.0.5"]), \
             patch.object(scan, "active_tags", return_value=set()), \
             patch.object(scan, "release_published", side_effect=RuntimeError("GitHub unavailable")), \
             patch.object(scan, "dispatch") as dispatch, \
             patch.object(scan.packages, "require_api_key"):
            with self.assertRaisesRegex(RuntimeError, "GitHub unavailable"):
                scan.scan()
        dispatch.assert_not_called()


class GithubApiTests(unittest.TestCase):
    def test_only_matching_active_run_names_suppress_dispatch(self):
        def runs(path):
            if "status=in_progress" in path:
                return {"workflow_runs": [
                    {"display_title": "Stable packages 4.0.5"},
                    {"display_title": "Unrelated run"},
                ]}
            return {"workflow_runs": []}

        with patch.object(scan, "github_api", side_effect=runs):
            self.assertEqual(scan.active_tags("stable-packages.yml", "Stable packages"), {"4.0.5"})

    def test_drafts_and_prereleases_are_not_published_stable_releases(self):
        for release, expected in [
            (None, False),
            ({"draft": True, "prerelease": False, "published_at": None}, False),
            ({"draft": False, "prerelease": True, "published_at": "2026-10-07T00:00:00Z"}, False),
            ({"draft": False, "prerelease": False, "published_at": "2026-10-07T00:00:00Z"}, True),
        ]:
            with self.subTest(release=release), patch.object(scan, "github_api", return_value=release):
                self.assertEqual(scan.release_published("4.0.5"), expected)

    def test_only_release_lookup_treats_not_found_as_absent(self):
        error = urllib.error.HTTPError("url", 404, "Not Found", {}, None)
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test"}), \
             patch.object(scan.urllib.request, "urlopen", side_effect=error):
            self.assertIsNone(scan.github_api("releases/tags/4.0.5", not_found=True))
            with self.assertRaisesRegex(RuntimeError, "HTTP 404"):
                scan.github_api("actions/workflows/stable-packages.yml/runs")


if __name__ == "__main__":
    unittest.main()
