#!/usr/bin/env python3
"""Coverage, context resolution, and failure regressions for staged cargo-vet reviews.

The live fixture is opt-in: CARGO_VET_LIVE_SMOKE=1 python3 -m unittest discover
-s scripts -p test_cargo_vet_staged.py -k live
"""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cargo_vet_review as review
from test_cargo_vet_review import stage_report


DELETED_HEADER = ("diff --git a/obsolete.rs b/obsolete.rs\n"
                  "deleted file mode 100644\nindex abcdef0..0000000\n"
                  "--- a/obsolete.rs\n+++ /dev/null\n")
DELETED_DIFF = DELETED_HEADER + "@@ -1,2 +0,0 @@\n-old implementation\n-old validation\n"
MODIFIED_DIFF = ("diff --git a/current.rs b/current.rs\n--- a/current.rs\n+++ b/current.rs\n"
                 "@@ -1 +1 @@\n-old validation\n+new validation\n")


class StagedReviewTests(unittest.TestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def run_review(self, source="+code\n", respond=None, **limits):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        calls = []
        prompts = []
        analyzer = review.AIAnalyzer("codex")

        def invoke(text, **kwargs):
            data = json.loads(text)
            calls.append(data)
            prompts.append(kwargs["_review_prompt"])
            return stage_report(data) if respond is None else respond(data)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(review, "PROJECT_ROOT", root))
            stack.enter_context(patch.object(analyzer, "analyze_diff", side_effect=invoke))
            for key, value in limits.items():
                stack.enter_context(patch.object(review.StagedReview, key, value))
            result = analyzer.review_diff(source, crate_name="fixture", old_version="1", new_version="2",
                                         publisher="fixture", old_source=root / "old", new_source=root / "new")
        return SimpleNamespace(result=result, root=root, calls=calls,
                               prompts=prompts,
                               workspaces=list(root.glob("*.review")))

    def test_whole_file_deletion_retains_metadata_and_explicit_omission(self):
        filtered, deletions = review.omit_deleted_file_contents(DELETED_DIFF + MODIFIED_DIFF)
        self.assertTrue(filtered.startswith(DELETED_HEADER))
        self.assertIn("[Deleted-file body intentionally omitted:", filtered)
        self.assertNotIn("-old implementation", filtered)
        self.assertNotIn("@@ -1,2 +0,0 @@", filtered)
        self.assertTrue(filtered.endswith(MODIFIED_DIFF))
        self.assertEqual(deletions, [dict(header=DELETED_HEADER,
                                         omitted_characters=len(DELETED_DIFF) - len(DELETED_HEADER),
                                         omitted_lines=3)])

    def test_binary_deletion_omits_payload_but_keeps_deletion_identity(self):
        header = 'diff --git "a/old asset" "b/old asset"\ndeleted file mode 100644\nindex abcdef0..0000000\n'
        for body in ('Binary files a/old asset and /dev/null differ\n',
                     'GIT binary patch\nliteral 0\nHcmV?d00001\n'):
            with self.subTest(body=body):
                filtered, deletions = review.omit_deleted_file_contents(header + body)
                self.assertTrue(filtered.startswith(header))
                self.assertNotIn(body, filtered)
                self.assertIn("intentionally omitted", filtered)
                self.assertEqual(deletions[0]["omitted_characters"], len(body))

    def test_empty_file_deletion_still_remains_visible(self):
        metadata = "diff --git a/empty b/empty\ndeleted file mode 100644\nindex e69de29..0000000"
        filtered, deletions = review.omit_deleted_file_contents(metadata)
        self.assertTrue(filtered.startswith(metadata + "\n"))
        self.assertIn("0 patch lines, 0 characters", filtered)
        self.assertEqual(len(deletions), 1)

    def test_additions_modifications_renames_and_deletion_like_code_are_unchanged(self):
        examples = [MODIFIED_DIFF,
                    'diff --git a/new b/new\nnew file mode 100644\n--- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+new code\n',
                    'diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n',
                    'diff --git a/code b/code\n--- a/code\n+++ b/code\n@@ -1 +1 @@\n'
                    '-deleted file mode 100644\n+deleted file mode 100755\n',
                    'diff --git a/code b/code\n--- a/code\n+++ b/code\n@@ -1,2 +1,2 @@\n'
                    ' deleted file mode 100644\n-old\n+new\n',
                    'deleted file mode 100644\nnot a Git diff section\n']
        for material in examples:
            with self.subTest(material=material):
                self.assertEqual(review.omit_deleted_file_contents(material), (material, []))

    def test_filtering_preserves_section_boundaries_and_final_retained_content(self):
        filtered, _ = review.omit_deleted_file_contents(MODIFIED_DIFF + DELETED_DIFF + MODIFIED_DIFF.rstrip("\n"))
        self.assertTrue(filtered.startswith(MODIFIED_DIFF))
        self.assertTrue(filtered.endswith(MODIFIED_DIFF.rstrip("\n")))
        self.assertEqual(filtered.count("diff --git "), 3)

    def test_deletion_scope_is_explained_to_both_source_and_integration_reviewers(self):
        run = self.run_review(DELETED_DIFF)
        self.assertEqual([c["task_id"] for c in run.calls], ["source-1", "integration-1"])
        self.assertTrue(run.result.complete)
        self.assertTrue(run.result.decision)
        self.assertIn("1 deleted-file bodies intentionally omitted", run.result.explanation)
        for prompt in run.prompts:
            self.assertIn("absent from the new implementation", prompt)
            self.assertIn("do not treat it as unread", prompt)
            self.assertIn("missing context", prompt)
            self.assertIn("withhold certification for this exclusion alone", prompt)
            self.assertIn("concrete removal-related concern", prompt)

    def test_deletion_only_review_requires_integration_decision(self):
        def respond(data):
            value = json.loads(stage_report(data))
            if "records" in data:
                value["review"].update(decision=False, explanation="Removing the build helper changes build behavior")
            return json.dumps(value)

        run = self.run_review(DELETED_DIFF, respond)
        self.assertFalse(run.result.decision)
        self.assertTrue(run.result.complete)
        self.assertIn("changes build behavior", run.result.explanation)
        self.assertEqual(len(run.calls), 2)

    def test_artifacts_and_coverage_distinguish_filtered_and_original_diffs(self):
        original = DELETED_DIFF + MODIFIED_DIFF
        def respond(data):
            value = json.loads(stage_report(data))
            if "records" in data:
                value["review"].update(decision=False, explanation="Retain artifacts for manual assessment")
            return json.dumps(value)

        run = self.run_review(original, respond)
        workspace = run.workspaces[0]
        filtered, _ = review.omit_deleted_file_contents(original)
        self.assertEqual((workspace / "original.diff").read_text(), original)
        self.assertEqual((workspace / "complete.diff").read_text(), filtered)
        self.assertEqual((workspace / "source-1.diff").read_text(), filtered)
        manifest = json.loads((workspace / "manifest.json").read_text())
        self.assertEqual(manifest["characters"], len(filtered))
        self.assertEqual(manifest["completed_ranges"], [[0, len(filtered)]])
        self.assertEqual(manifest["scope"]["original_characters"], len(original))
        self.assertEqual(manifest["scope"]["review_characters"], len(filtered))
        self.assertEqual(manifest["scope"]["initial_source_tasks"], 1)
        self.assertEqual(manifest["omitted_deletions"][0]["header"], DELETED_HEADER)
        self.assertEqual(run.calls[-1]["original_diff"], str(workspace / "original.diff"))
        self.assertEqual(run.calls[-1]["full_diff"], str(workspace / "complete.diff"))
        self.assertIn("Coverage applies to the retained diff and deletion metadata", run.result.explanation)

    def test_task_estimate_and_omission_count_are_printed_before_review_starts(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            run = self.run_review(DELETED_DIFF)
        text = output.getvalue()
        self.assertLess(text.index("1 deleted-file bodies intentionally omitted"), text.index("Reviewing source-1"))
        self.assertLess(text.index("1 initial source tasks"), text.index("Reviewing source-1"))
        self.assertLess(text.index("Source limits: 240000 characters / 6000 lines"), text.index("Reviewing source-1"))
        self.assertTrue(run.result.complete)

    def test_partition_covers_unicode_oversized_lines_and_file_boundaries(self):
        material = ("diff --git a/first b/first\n@@ -1 +1 @@\n" + "é🐍" * 260000 + "\n"
                    + "line\n" * 12500 + "diff --git a/second b/second\n+end\n")
        ranges = list(review.StagedReview.ranges(material))
        self.assertGreater(len(ranges), 3)
        self.assertEqual(ranges[0][0], 0)
        self.assertEqual(ranges[-1][1], len(material))
        self.assertEqual("".join(material[a:b] for a, b in ranges), material)
        self.assertTrue(all(left[1] == right[0] for left, right in zip(ranges, ranges[1:])))
        self.assertTrue(all(0 < b - a <= 240000 for a, b in ranges))
        self.assertTrue(all(len(material[a:b].splitlines()) <= 6000 for a, b in ranges))
        self.assertTrue(all(material[a:b].encode().decode() == material[a:b] for a, b in ranges))

    def test_incomplete_task_is_subdivided_and_parent_questions_are_retained(self):
        def respond(data):
            if data["task_id"] == "source-1":
                return stage_report(data, complete=False, questions=["Verify build.rs uses the new binding"])
            return stage_report(data)

        run = self.run_review("abcdefgh", respond)
        primary = [(call["start"], call["end"]) for call in run.calls if "primary" in call]
        self.assertEqual(primary, [(0, 8), (0, 4), (4, 8)])
        integration = run.calls[-1]
        questions = [issue["description"] for record in integration["records"] for issue in record["issues"]]
        self.assertEqual(questions, ["Verify build.rs uses the new binding"])
        self.assertTrue(run.result.decision)
        self.assertEqual(run.workspaces, [])

    def test_large_primary_uses_small_metadata_and_subdivides_without_losing_concerns(self):
        primary_sizes = []
        def respond(data):
            if "primary" in data:
                primary_sizes.append(len(Path(data["primary"]).read_text()))
                if data["task_id"] == "source-1":
                    return stage_report(data, complete=False, questions=["Verify the changed FFI contract"],
                                        findings=[dict(description="binding.rs:1 possible ABI mismatch",
                                                       severity="high", malicious=False)])
            return stage_report(data)

        run = self.run_review("x" * 240000, respond)
        self.assertEqual(primary_sizes, [240000, 120000, 120000])
        self.assertTrue(all(len(json.dumps(data, ensure_ascii=False)) <= 60000 for data in run.calls))
        integration_issues = [issue for record in run.calls[-1]["records"] for issue in record["issues"]]
        self.assertEqual({issue["description"] for issue in integration_issues},
                         {"Verify the changed FFI contract", "binding.rs:1 possible ABI mismatch"})
        self.assertTrue(run.result.complete)

    def test_source_line_limit_splits_after_six_thousand_lines(self):
        material = "+code\n" * 6001
        ranges = list(review.StagedReview.ranges(material))
        self.assertEqual([len(material[a:b].splitlines()) for a, b in ranges], [6000, 1])
        self.assertEqual("".join(material[a:b] for a, b in ranges), material)

    def test_larger_source_budget_does_not_allow_oversized_summaries(self):
        run = self.run_review(respond=lambda data: stage_report(data, summary="x" * 6001))
        self.assertFalse(run.result.complete)
        self.assertIn("oversized summary", run.result.explanation)

    def test_four_levels_of_subdivision_cannot_hide_unread_material(self):
        def respond(data):
            return stage_report(data, complete=False, summary="Only read a prefix")

        run = self.run_review("x" * 32, respond)
        manifest = json.loads((run.workspaces[0] / "manifest.json").read_text())
        self.assertFalse(run.result.complete)
        self.assertEqual(run.result.automatic_action(), "skip")
        self.assertEqual(max(task["depth"] for task in manifest["tasks"]), 4)
        self.assertEqual(len(manifest["tasks"]), 31)
        self.assertTrue(all("primary" in call for call in run.calls))
        self.assertIn("unread assignment [0, 2)", run.result.explanation)

    def test_malformed_missing_duplicate_and_wrong_identity_reports_never_certify(self):
        responses = [None, "not JSON", "[]", '{"task_id":"source-1","task_id":"source-1"}',
                     stage_report({"task_id": "wrong"}),
                     stage_report({"task_id": "source-1"}, questions="missing list"),
                     stage_report({"task_id": "source-1"}, complete="true")]
        for response in responses:
            with self.subTest(response=response):
                run = self.run_review(respond=lambda data: response)
                self.assertFalse(run.result.decision)
                self.assertFalse(run.result.complete)
                self.assertEqual(len(run.calls), 1)
                self.assertTrue((run.workspaces[0] / "failure.json").is_file())

    def test_missing_source_report_blocks_integration_but_other_tasks_are_reviewed(self):
        def respond(data):
            return None if data["task_id"] == "source-2" else stage_report(data)

        run = self.run_review("a\nb\nc\n", respond, SOURCE_MAX_LINES=1)
        self.assertFalse(run.result.complete)
        self.assertEqual([call["task_id"] for call in run.calls], ["source-1", "source-2", "source-3"])
        manifest = json.loads((run.workspaces[0] / "manifest.json").read_text())
        self.assertEqual(manifest["completed_ranges"], [[0, 2], [4, 6]])

    def test_cross_file_question_can_be_resolved_using_source_context(self):
        inspected = []
        def respond(data):
            if "primary" in data:
                old, new = Path(data["old_source"]), Path(data["new_source"])
                old.mkdir(); new.mkdir()
                (old / "build.rs").write_text('fn main() {}\n')
                (new / "build.rs").write_text('fn main() { println!("cargo:rustc-link-lib=sqlite3"); }\n')
                return stage_report(data, questions=["Does build.rs link sqlite3?"])
            inspected.append((Path(data["new_source"]) / "build.rs").read_text())
            value = json.loads(stage_report(data))
            value["dispositions"][0]["evidence"] = "build.rs:1 links sqlite3; checked old and new implementation"
            return json.dumps(value)

        run = self.run_review(respond=respond)
        self.assertIn("rustc-link-lib=sqlite3", inspected[0])
        self.assertTrue(run.result.decision)

    def test_unresolved_questions_get_three_targeted_resolution_rounds(self):
        def respond(data):
            if "primary" in data:
                return stage_report(data, assumptions=["FFI layout must match the replacement binding"])
            value = json.loads(stage_report(data))
            for disposition in value["dispositions"]:
                disposition.update(status="unresolved", evidence="replacement layout remains unverified")
            value["review"].update(decision=False, complete=False)
            return json.dumps(value)

        run = self.run_review(respond=respond)
        self.assertFalse(run.result.complete)
        self.assertEqual([c["resolution_round"] for c in run.calls if "records" in c], [0, 1, 2, 3])
        self.assertIn("FFI layout", run.result.explanation)

    def test_question_discovered_during_integration_is_not_lost(self):
        def respond(data):
            if data["task_id"] == "integration-1":
                return stage_report(data, questions=["Validate manifest versus build.rs"])
            return stage_report(data)

        run = self.run_review(respond=respond)
        self.assertEqual(len(run.calls), 3)
        self.assertEqual(run.calls[-1]["records"][0]["issues"][0]["description"], "Validate manifest versus build.rs")
        self.assertTrue(run.result.decision)

    def test_missing_or_duplicate_issue_dispositions_cannot_silently_drop_findings(self):
        for duplicate in (False, True):
            def respond(data):
                if "primary" in data:
                    return stage_report(data, findings=[dict(description="src/lib.rs:2 unchecked pointer",
                                                           severity="high", malicious=False)])
                value = json.loads(stage_report(data))
                value["dispositions"] = value["dispositions"] * 2 if duplicate else []
                return json.dumps(value)

            with self.subTest(duplicate=duplicate):
                run = self.run_review(respond=respond)
                self.assertFalse(run.result.complete)
                self.assertEqual(run.result.automatic_action(), "block")
                self.assertIn("unchecked pointer", run.result.explanation)

    def test_confirmed_late_task_finding_overrides_optimistic_final_recommendation(self):
        def respond(data):
            if "primary" in data and data["following_context"] == "":
                return stage_report(data, findings=[dict(description="last.rs:9 deliberate exfiltration",
                                                       severity="critical", malicious=True)])
            value = json.loads(stage_report(data))
            for disposition in value.get("dispositions", []):
                disposition.update(status="confirmed", evidence="last.rs:9 transmits credentials")
            return json.dumps(value)

        run = self.run_review("a\nb\nc\n", respond, SOURCE_MAX_LINES=1)
        self.assertTrue(run.result.complete)
        self.assertFalse(run.result.decision)
        self.assertEqual(run.result.severity, review.RiskLevel.CRITICAL)
        self.assertTrue(run.result.malicious)
        self.assertEqual(run.result.automatic_action(), "block")
        self.assertIn("last.rs:9", run.result.explanation)
        self.assertTrue((run.workspaces[0] / "result.json").is_file())

    def test_incomplete_parent_malicious_finding_survives_child_execution_failure(self):
        def respond(data):
            if data["task_id"] == "source-1":
                return stage_report(data, complete=False, findings=[dict(
                    description="build.rs:7 exfiltration", severity="high", malicious=True)])
            return None

        run = self.run_review("abcd", respond)
        self.assertFalse(run.result.complete)
        self.assertTrue(run.result.malicious)
        self.assertEqual(run.result.automatic_action(), "block")

    def test_report_grouping_preserves_issue_until_evidence_resolves_it(self):
        def respond(data):
            if "primary" in data:
                return stage_report(data, summary="Changed interface. " * 260,
                                    questions=["Verify " + data["task_id"] + " ABI"])
            value = json.loads(stage_report(data))
            if not data["final"]:
                for disposition in value["dispositions"]:
                    disposition.update(status="unresolved", evidence="Defer source inspection to integration")
            return json.dumps(value)

        run = self.run_review("a\n" * 15, respond, SOURCE_MAX_LINES=1)
        integration = [call for call in run.calls if "records" in call]
        self.assertGreater(len(integration), 1)
        self.assertTrue(all(len(json.dumps(call, ensure_ascii=False)) <= 60000 for call in integration))
        self.assertTrue(any(not call["final"] for call in integration))
        final_issues = [i for r in integration[-1]["records"] for i in r["issues"]]
        self.assertEqual(len(final_issues), 15)
        self.assertEqual(len({i["id"] for i in final_issues}), 15)
        self.assertTrue(run.result.decision)

    def test_file_header_context_does_not_inherit_previous_files_hunk(self):
        headers = []
        def respond(data):
            if "primary" in data:
                headers.append(data["section_headers"])
            return stage_report(data)

        run = self.run_review("diff --git a/first b/first\n@@ -1 +1 @@\n+x\n"
                              "diff --git a/second b/second\n+y\n", respond, SOURCE_MAX_LINES=1)
        self.assertEqual(headers[-2], ["diff --git a/second b/second"])
        self.assertEqual(headers[-1], ["diff --git a/second b/second"])
        self.assertTrue(run.result.complete)

    def test_incomplete_integration_cannot_hide_inside_successful_summary(self):
        def respond(data):
            if data["task_id"] == "integration-1":
                return stage_report(data, complete=False, summary="Cross-file review unfinished")
            return stage_report(data)

        run = self.run_review(respond=respond)
        pending = run.calls[-1]["records"][0]["issues"]
        self.assertEqual(pending[0]["id"], "integration-1:incomplete")
        self.assertTrue(run.result.complete)

    def test_cross_file_finding_discovered_in_integration_requires_a_disposition(self):
        def respond(data):
            if data["task_id"] == "integration-1":
                return stage_report(data, findings=[dict(description="build.rs and lib.rs disagree on FFI layout",
                                                       severity="high", malicious=False)])
            value = json.loads(stage_report(data))
            for disposition in value.get("dispositions", []):
                disposition.update(status="confirmed", evidence="build.rs:9 and lib.rs:4 have incompatible layouts")
            return json.dumps(value)

        run = self.run_review(respond=respond)
        self.assertFalse(run.result.decision)
        self.assertTrue(run.result.complete)
        self.assertEqual(run.result.severity, review.RiskLevel.HIGH)
        self.assertIn("incompatible layouts", run.result.explanation)

    def test_final_assessment_concerns_survive_another_resolution_round(self):
        def respond(data):
            if "primary" in data:
                return stage_report(data, questions=["Check external inputs"])
            value = json.loads(stage_report(data))
            for disposition in value["dispositions"]:
                disposition.update(status="unresolved", evidence="Still verifying the input boundary")
            value["review"].update(decision=False, complete=False, severity="high", malicious=True,
                                   explanation="network.rs:7 possible credential exfiltration")
            return json.dumps(value)

        run = self.run_review(respond=respond)
        self.assertFalse(run.result.complete)
        self.assertEqual(run.result.automatic_action(), "block")
        self.assertIn("network.rs:7", run.result.explanation)
        carried = run.calls[2]["records"][0]["issues"]
        self.assertTrue(any(i["malicious"] for i in carried))

    def test_oversized_report_is_retained_without_truncation_but_never_certifies(self):
        response = "x" * 12001
        run = self.run_review(respond=lambda data: response)
        self.assertFalse(run.result.complete)
        raw = json.loads((run.workspaces[0] / "source-1.response.json").read_text())
        self.assertEqual(raw, response)
        self.assertIn("bounded report capacity", run.result.explanation)

    def test_workspace_creation_failure_returns_an_incomplete_review(self):
        with patch.object(review.tempfile, "mkdtemp", side_effect=OSError("disk unavailable")):
            result = review.AIAnalyzer("codex").review_diff(
                "+code", crate_name="fixture", old_version="1", new_version="2", publisher="fixture")
        self.assertFalse(result.complete)
        self.assertIn("disk unavailable", result.explanation)

    @unittest.skipUnless(os.environ.get("CARGO_VET_LIVE_SMOKE") == "1", "opt-in live Codex review")
    def test_live_multifile_fixture_completes_without_certifying_a_real_crate(self):
        analyzer = review.AIAnalyzer("codex", timeout=120)
        self.assertTrue(analyzer.is_available(), "Codex CLI is required for the live smoke test")
        with tempfile.TemporaryDirectory(prefix=".cargo-vet-review-", suffix=".review", dir=review.PROJECT_ROOT) as directory:
            root = Path(directory)
            old, new = root / "old", root / "new"
            old.mkdir(); new.mkdir()
            (old / "lib.rs").write_text('mod helper;\npub fn answer() -> u32 { helper::value() }\n')
            (new / "lib.rs").write_text((old / "lib.rs").read_text())
            (old / "helper.rs").write_text('pub fn value() -> u32 { 1 }\n')
            (new / "helper.rs").write_text('pub fn value() -> u32 { 2 }\n')
            material = ('diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1,2 +1,2 @@\n'
                        ' mod helper;\n pub fn answer() -> u32 { helper::value() }\n'
                        'diff --git a/helper.rs b/helper.rs\n--- a/helper.rs\n+++ b/helper.rs\n@@ -1 +1 @@\n'
                        '-pub fn value() -> u32 { 1 }\n+pub fn value() -> u32 { 2 }\n')
            with patch.object(review.StagedReview, "SOURCE_MAX_LINES", 6), \
                 patch.object(review, "PROJECT_ROOT", root):
                result = analyzer.review_diff(material, crate_name="synthetic-smoke-fixture", old_version="1", new_version="2",
                                              publisher="local fixture", old_source=old, new_source=new)
            self.assertTrue(result.complete, result.explanation)


if __name__ == "__main__":
    unittest.main()
