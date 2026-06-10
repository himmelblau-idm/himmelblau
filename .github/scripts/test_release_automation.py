#!/usr/bin/env python3

import gzip
import hashlib
import unittest
import unittest.mock

import release_automation as ra


class ReleaseAutomationTests(unittest.TestCase):
    def test_parse_index_links_ignores_parent(self):
        html = '<a href="../">../</a><a href="deb/">deb/</a><a href="sbom.json">sbom.json</a>'
        self.assertEqual(ra.parse_index_links(html), ["deb/", "sbom.json"])

    def test_parse_debian_packages(self):
        text = """Package: himmelblau
Version: 3.1.6-debian12
Architecture: amd64
Filename: ./himmelblau_3.1.6-debian12_amd64.deb
SHA256: 4b7a844c69180f8bc0dfc9243bf8acccae5c3317c6c441545e7a4cb631565be2

Package: pam-himmelblau
Version: 3.1.6-debian12
Architecture: amd64
Filename: ./pam-himmelblau_3.1.6-debian12_amd64.deb
SHA256: 1111111111111111111111111111111111111111111111111111111111111111
"""
        artifacts = ra.parse_debian_packages(
            text,
            "https://packages.example/stable/3.1.6/deb/debian12/",
            "3.1.6",
            "debian12",
            "himmelblau",
        )
        self.assertEqual(len(artifacts), 2)
        self.assertEqual(artifacts[0].name, "himmelblau")
        self.assertEqual(artifacts[0].digest, "sha256:4b7a844c69180f8bc0dfc9243bf8acccae5c3317c6c441545e7a4cb631565be2")
        self.assertEqual(
            artifacts[0].artifact_url,
            "https://packages.example/stable/3.1.6/deb/debian12/himmelblau_3.1.6-debian12_amd64.deb",
        )

    def test_parse_debian_packages_only_removes_dot_slash_prefix(self):
        text = """Package: himmelblau
Version: 3.1.6-debian12
Architecture: amd64
Filename: .hidden/himmelblau_3.1.6-debian12_amd64.deb
SHA256: 4b7a844c69180f8bc0dfc9243bf8acccae5c3317c6c441545e7a4cb631565be2
"""
        artifacts = ra.parse_debian_packages(
            text,
            "https://packages.example/stable/3.1.6/deb/debian12/",
            "3.1.6",
            "debian12",
            "himmelblau",
        )
        self.assertEqual(
            artifacts[0].artifact_url,
            "https://packages.example/stable/3.1.6/deb/debian12/.hidden/himmelblau_3.1.6-debian12_amd64.deb",
        )

    def test_parse_rpm_repodata_and_primary(self):
        repomd = """<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/abc-primary.xml.gz"/>
  </data>
</repomd>
"""
        self.assertEqual(ra.rpm_primary_href(repomd), "repodata/abc-primary.xml.gz")

        primary = """<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
<package type="rpm">
  <name>himmelblau</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="3.1.6" rel="1"/>
  <checksum type="sha256" pkgid="YES">6052a7a93501c48a24e14fc4d7bbcda5d963c9b7602bdd52df3df81d649c0d4d</checksum>
  <location href="himmelblau-3.1.6-1.x86_64-fedora42.rpm"/>
</package>
</metadata>
"""
        artifacts = ra.parse_rpm_primary(
            primary.encode(),
            "https://packages.example/stable/3.1.6/rpm/fedora42/",
            "3.1.6",
            "fedora42",
            "himmelblau",
        )
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].name, "himmelblau")
        self.assertEqual(artifacts[0].version, "3.1.6-1")
        self.assertEqual(artifacts[0].kind, "rpm:x86_64")

    def test_gzip_fixture_matches_primary_parser_input(self):
        body = b"<metadata />"
        self.assertEqual(gzip.decompress(gzip.compress(body)), body)

    def test_sbom_digest_format(self):
        digest = hashlib.sha256(b"{}").hexdigest()
        self.assertEqual(f"sha256:{digest}", "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")

    def test_build_release_prompt_appends_context(self):
        prompt_file = unittest.mock.Mock()
        prompt_file.read_text.return_value = "Compare: <PASTE_COMPARE_URL_HERE>"
        with unittest.mock.patch.object(ra, "local_compare_context", return_value="local"), unittest.mock.patch.object(
            ra, "github_compare_context", return_value="github"
        ):
            prompt = ra.build_release_prompt(prompt_file, "owner/repo", "1.0.0", "1.0.1")
        self.assertIn("Compare: https://github.com/owner/repo/compare/1.0.0...1.0.1", prompt)
        self.assertIn("# Additional Workflow-Fetched Compare Context", prompt)
        self.assertIn("local\n\ngithub", prompt)

    def test_call_azure_responses_reports_both_supported_key_names(self):
        with unittest.mock.patch.dict(ra.os.environ, {"AZURE_RESOURCE_NAME": "example"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "AZURE_API_KEY or AZURE_COGNITIVE_SERVICES_API_KEY"):
                ra.call_azure_responses("prompt", "model")

    def test_publish_artifacts_requires_owner_repo(self):
        with self.assertRaisesRegex(RuntimeError, "OWNER/REPO"):
            ra.publish_artifacts("3.1.6", "himmelblau", dry_run=True)


if __name__ == "__main__":
    unittest.main()
