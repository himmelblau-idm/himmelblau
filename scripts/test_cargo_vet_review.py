#!/usr/bin/env python3
"""Offline regressions: no AI providers, crate downloads, or cargo writes are run."""
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cargo_vet_review as review


@contextlib.contextmanager
def working_directory(path):
    previous = Path.cwd()
    try:
        review.os.chdir(path)
        yield
    finally:
        review.os.chdir(previous)


def stage_report(data, **overrides):
    value = dict(task_id=data["task_id"], complete=True, summary="Reviewed assigned behavior",
                 findings=[], questions=[], assumptions=[])
    if "records" in data:
        value["dispositions"] = [
            dict(id=issue["id"], status="resolved", evidence="src/lib.rs:1 verified implementation")
            for record in data["records"] for issue in record["issues"]
        ]
        if data["final"]:
            value["review"] = dict(decision=True, complete=True, severity="low", malicious=False,
                                   explanation="Reviewed source and cross-file behavior")
    value.update(overrides)
    return json.dumps(value)


class ReviewTests(unittest.TestCase):
    kwargs = dict(crate_name="example", old_version="1.0", new_version="1.1",
                  publisher="publisher", verbose=False)

    def setUp(self):
        self.stdout = io.StringIO()
        self.output = contextlib.redirect_stdout(self.stdout)
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.errors = contextlib.redirect_stderr(io.StringIO())
        self.errors.__enter__()
        self.addCleanup(self.errors.__exit__, None, None, None)

    def report(self, **overrides):
        value = dict(complete=True, decision=True, severity="low", malicious=False,
                     explanation="Reviewed all content; LOW risk")
        value.update(overrides)
        return json.dumps(value)

    def test_single_complete_approval_is_certifiable(self):
        analyzer = review.AIAnalyzer("codex")
        with tempfile.TemporaryDirectory() as root, \
             patch.object(review, "PROJECT_ROOT", Path(root)), \
             patch.object(analyzer, "analyze_diff", side_effect=lambda text, **kw: stage_report(json.loads(text))):
            result = analyzer.review_diff("source", **self.kwargs)
            self.assertEqual(list(Path(root).iterdir()), [])
        self.assertTrue(result.decision)
        self.assertTrue(result.complete)

    def test_empty_review_does_not_invoke_ai(self):
        analyzer = review.AIAnalyzer("codex")
        with patch.object(analyzer, "analyze_diff") as invoke:
            result = analyzer.review_diff("", **self.kwargs)
        invoke.assert_not_called()
        self.assertFalse(result.decision)
        self.assertFalse(result.complete)
        self.assertIn("No review material", result.explanation)

    def test_invalid_or_incomplete_responses_never_approve(self):
        for bad in ("{}{}", "prefix " + self.report(), "[]", "{broken}", None,
                    self.report(complete=False), self.report(complete="true"),
                    self.report(decision="yes"), self.report(explanation=""),
                    '{"decision": false, "decision": true, "complete": true, "explanation": "safe"}'):
            with self.subTest(bad=bad):
                result = review.AIReview.parse(bad)
                self.assertFalse(result.decision)
                self.assertFalse(result.complete)
                self.assertIn("Manual review required", result.explanation)

    def test_failed_review_preserves_response_for_diagnosis(self):
        for failed in ("not JSON", None, self.report(decision=False, complete=False,
                                                    explanation="Unread range")):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as root:
                analyzer = review.AIAnalyzer("codex")
                with patch.object(review, "PROJECT_ROOT", Path(root)), \
                     patch.object(analyzer, "analyze_diff", return_value=failed):
                    result = analyzer.review_diff("source", **self.kwargs)
                self.assertFalse(result.decision)
                self.assertFalse(result.complete)
                workspace = next(Path(root).iterdir())
                self.assertEqual(json.loads((workspace / "source-1.response.json").read_text()), failed)
                self.assertIn(str(workspace), result.explanation)

    def test_fenced_json_is_accepted(self):
        for fence in ("```json\n", "```\n"):
            with self.subTest(fence=fence):
                result = review.AIReview.parse(fence + self.report() + "\n```")
                self.assertTrue(result.decision)

    def test_review_classification_requires_valid_explicit_fields(self):
        cases = [dict(severity="severe"), dict(severity=True), dict(severity=[]),
                 dict(malicious="false"), dict(malicious=0), dict(malicious=None)]
        values = [json.loads(self.report(**case)) for case in cases]
        for missing in ("severity", "malicious"):
            value = json.loads(self.report())
            del value[missing]
            values.append(value)
        for value in values:
            with self.subTest(value=value):
                result = review.AIReview.parse(json.dumps(value))
                self.assertFalse(result.decision)
                self.assertFalse(result.complete)
                self.assertEqual(result.automatic_action(), "skip")

    def test_relative_provider_paths_survive_workspace_cwd(self):
        for provider, attempts in (("claude", 3), ("gemini", 2), ("codex", 1)):
            for use_path in (False, True):
                with self.subTest(provider=provider, use_path=use_path), \
                     tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    caller = root / "caller"
                    caller.mkdir()
                    executable = caller / provider
                    executable.write_text("#!/bin/sh\nexit 99\n")
                    executable.chmod(0o700)
                    with working_directory(caller), \
                         patch.dict(review.os.environ, {"PATH": "."}):
                        analyzer = review.AIAnalyzer(
                            provider, path=None if use_path else "./" + provider,
                        )
                        self.assertTrue(analyzer.is_available())
                        self.assertEqual(analyzer.cli_path, str(executable))
                        def run(command, **kwargs):
                            self.assertEqual(command[0], str(executable))
                            self.assertEqual(kwargs["cwd"], root)
                            # No executable is run, including the fixture above.
                            return subprocess.CompletedProcess(command, 1, "", "mock failure")
                        with patch.object(review, "PROJECT_ROOT", root), \
                             patch.object(review.subprocess, "run", side_effect=run) as mocked:
                            self.assertIsNone(analyzer.analyze_diff("source", **self.kwargs))
                        self.assertEqual(mocked.call_count, attempts)

    def test_missing_provider_does_not_launch(self):
        analyzer = review.AIAnalyzer("codex", path="./missing-provider")
        with tempfile.TemporaryDirectory() as directory, working_directory(directory), \
             patch.object(review.subprocess, "run") as mocked:
            self.assertFalse(analyzer.is_available())
            self.assertIsNone(analyzer.analyze_diff("source", **self.kwargs))
            mocked.assert_not_called()

    def test_provider_workspace_and_cleanup_on_all_invocations(self):
        for provider, attempts in (("claude", 3), ("gemini", 2), ("codex", 1)):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                paths = []
                def run(command, **kwargs):
                    self.assertEqual(kwargs["cwd"], root)
                    self.assertEqual(kwargs["timeout"], 73)
                    prompt = kwargs.get("input")
                    if prompt is None:
                        flag = "-p" if "-p" in command else "--print"
                        prompt = command[command.index(flag) + 1]
                    path = Path(re.search(r"available at: (.+)\n", prompt).group(1))
                    paths.append(path)
                    self.assertEqual(path.parent, root)
                    self.assertTrue(path.name.startswith(".cargo-vet-review-"))
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.read_text(), "untrusted source")
                    if provider == "codex":
                        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)
                        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
                        self.assertEqual(command[command.index("--cd") + 1], str(root))
                        Path(command[command.index("--output-last-message") + 1]).write_text("Reviewed source fully")
                        return subprocess.CompletedProcess(command, 0, "", "")
                    # Exercise every fallback, not just the first invocation.
                    return subprocess.CompletedProcess(command, 1, "", "mock failure")
                analyzer = review.AIAnalyzer(provider, timeout=73)
                with patch.object(review, "PROJECT_ROOT", root), \
                     patch.object(analyzer, "is_available", return_value=True), \
                     patch.object(review.subprocess, "run", side_effect=run) as mocked:
                    result = analyzer.analyze_diff("untrusted source", **self.kwargs)
                self.assertEqual(mocked.call_count, attempts)
                self.assertTrue(paths)
                self.assertTrue(all(not path.exists() for path in paths))
                if provider == "codex":
                    self.assertEqual(result, "Reviewed source fully")

    def test_orphaned_review_input_cannot_be_accidentally_staged(self):
        # Simulate a leftover after an uncatchable termination: finally cannot
        # remove it, but normal git add must not publish its crate contents.
        ignore_rules = (review.PROJECT_ROOT / ".gitignore").read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            (root / ".gitignore").write_text(ignore_rules)
            orphan = root / ".cargo-vet-review-orphan.diff"
            orphan.write_text("private untrusted crate source")
            workspace = root / ".cargo-vet-review-orphan.review"
            workspace.mkdir()
            (workspace / "source-1.report.json").write_text('{"summary": "private review"}')
            (root / "legitimate.diff").write_text("a patch intended for review")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            staged = subprocess.run(
                ["git", "ls-files"], cwd=root, check=True,
                capture_output=True, text=True,
            ).stdout.splitlines()
            self.assertNotIn(orphan.name, staged)
            self.assertFalse(any(path.startswith(workspace.name + "/") for path in staged))
            self.assertIn("legitimate.diff", staged)
            self.assertEqual(orphan.read_text(), "private untrusted crate source")

    def test_temporary_files_are_removed_on_provider_errors(self):
        create_temp = tempfile.NamedTemporaryFile
        for provider in ("claude", "gemini", "codex"):
            for error in (OSError("mock failure"), subprocess.TimeoutExpired("mock", 600)):
                with self.subTest(provider=provider, error=type(error).__name__), \
                     tempfile.TemporaryDirectory() as root:
                    paths = []
                    def temporary_file(*args, **kwargs):
                        result = create_temp(*args, **kwargs)
                        paths.append(Path(result.name))
                        return result
                    analyzer = review.AIAnalyzer(provider)
                    with patch.object(review, "PROJECT_ROOT", Path(root)), \
                         patch.object(analyzer, "is_available", return_value=True), \
                         patch.object(review.tempfile, "NamedTemporaryFile", side_effect=temporary_file), \
                         patch.object(review.subprocess, "run", side_effect=error):
                        self.assertIsNone(analyzer.analyze_diff("source", **self.kwargs))
                    self.assertGreaterEqual(len(paths), 2)
                    self.assertTrue(all(not path.exists() for path in paths))

    def test_structured_prompts_have_only_json_contract(self):
        for full in (False, True):
            with self.subTest(full=full), tempfile.TemporaryDirectory() as root:
                def run(command, **kwargs):
                    prompt = command[command.index("-p") + 1]
                    self.assertIn("Review Criteria", prompt)
                    self.assertIn("Return ONLY a JSON object", prompt)
                    self.assertIn('"severity": "low", "malicious": false', prompt)
                    self.assertIn("highest finding severity", prompt)
                    self.assertIn("backdoors or deliberate exfiltration", prompt)
                    self.assertNotIn("## Your Analysis", prompt)
                    self.assertNotIn("Provide a concise security analysis", prompt)
                    return subprocess.CompletedProcess(command, 0, self.report(), "")
                analyzer = review.AIAnalyzer("claude")
                with patch.object(review, "PROJECT_ROOT", Path(root)), \
                     patch.object(analyzer, "is_available", return_value=True), \
                     patch.object(review.subprocess, "run", side_effect=run):
                    self.assertIsNotNone(analyzer.analyze_diff(
                        "source", _structured=True, is_full_crate=full, **self.kwargs))

    def exemption_flow(self, inputs, ai=True):
        item = SimpleNamespace(crate_name="example", old_version="1.0", new_version="1.1",
                               publisher="publisher", audit_size="1 line", used_by="app",
                               trust_note=None, manual_reason=None)
        fetched = review.FetchedDiff("+safe code", None, Path("/unused"), False)
        with patch.object(review.sys, "argv", ["review"] + ([] if ai else ["--no-ai"])), \
             patch.object(review, "run_cargo_vet", return_value=self.vet_report()), \
             patch.object(review, "check_cargo_vet", return_value=(self.success_report(), set())), \
             patch.object(review.CargoVetParser, "parse_vet_output", return_value=[item]), \
             patch.object(review.DiffFetcher, "fetch", return_value=fetched), \
             patch.object(review.AIAnalyzer, "is_available", return_value=True), \
             patch.object(review.AIAnalyzer, "review_diff", return_value=review.AIReview.parse(
                 self.report(decision=False, explanation="Existing review"))), \
             patch.object(review.AIAnalyzer, "analyze_diff", return_value="Generated exemption"), \
             patch("builtins.input", side_effect=inputs), \
             patch.object(review, "exempt_crate", return_value=True) as exempt:
            review.main()
            return exempt

    def test_exemption_command_targets_project_from_other_directory(self):
        with tempfile.TemporaryDirectory() as directory, working_directory(directory), \
             patch.object(review.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(review.exempt_crate("example", "1.1", "reviewed note"))
            run.assert_called_once_with(
                ["cargo", "vet", "add-exemption", "example", "1.1",
                 "--criteria", "safe-to-deploy", "--notes", "reviewed note"],
                timeout=30, cwd=review.PROJECT_ROOT,
            )

    def test_exemption_generated_note_requires_acceptance(self):
        self.exemption_flow(["e", ""]).assert_called_once_with("example", "1.1", "Generated exemption")

    def test_exemption_generated_note_can_be_edited(self):
        self.exemption_flow(["e", "replacement"]).assert_called_once_with("example", "1.1", "replacement")

    def test_exemption_can_be_cancelled_before_writing(self):
        for cancel in (KeyboardInterrupt(), EOFError()):
            with self.subTest(cancel=type(cancel).__name__):
                self.exemption_flow(["e", cancel, "s"]).assert_not_called()

    def test_manual_exemption_note(self):
        self.exemption_flow(["e", "manual"], ai=False).assert_called_once_with("example", "1.1", "manual")

    def vet_report(self, targets=(("example", "1.0.0", "1.1.0"),)):
        return json.dumps({
            "conclusion": "fail (vetting)",
            "failures": [{"name": name, "version": new, "missing_criteria": ["safe-to-deploy"]}
                         for name, old, new in targets],
            "suggest": {"suggestions": [{"name": name, "notable_parents": "app",
                                        "suggested_diff": {"from": old, "to": new}}
                                       for name, old, new in targets]},
        })

    def success_report(self):
        return json.dumps({"conclusion": "success", "vetted_fully": [],
                           "vetted_partially": [], "vetted_with_exemptions": []})

    def test_json_discovery_covers_new_crates_and_multiple_versions(self):
        targets = (("example", "1.0.0", "1.1.0"), ("example", None, "2.0.0"),
                   ("other", None, "3.0.0"))
        items = review.CargoVetParser().parse_vet_output(self.vet_report(targets))
        self.assertEqual([(item.crate_name, item.old_version, item.new_version) for item in items], list(targets))

    def test_discovery_rejects_missing_ambiguous_and_invalid_requirements(self):
        report = json.loads(self.vet_report())
        duplicate = json.loads(self.vet_report())
        duplicate["suggest"]["suggestions"] *= 2
        unrelated = json.loads(self.vet_report())
        unrelated["suggest"]["suggestions"][0]["name"] = "unrelated"
        for value in ({}, [], {"conclusion": "fail (violation)"}, duplicate, unrelated,
                      report | {"failures": []}, {"conclusion": "success"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.CargoVetParser().parse_vet_output(json.dumps(value))

    def test_intermediate_coverage_suggestion_is_accepted(self):
        # Failure is 1.2.0, but cargo-vet suggests auditing 1.0.0 -> 1.1.0 because
        # 1.1.0 -> 1.2.0 coverage already exists.
        report = {
            "conclusion": "fail (vetting)",
            "failures": [{"name": "example", "version": "1.2.0",
                          "missing_criteria": ["safe-to-deploy"]}],
            "suggest": {"suggestions": [{
                "name": "example",
                "notable_parents": "app",
                "suggested_diff": {"from": "1.0.0", "to": "1.1.0"},
            }]},
        }
        items = review.CargoVetParser().parse_vet_output(json.dumps(report))
        by_version = {item.new_version: item for item in items}
        self.assertEqual(set(by_version), {"1.1.0", "1.2.0"})
        self.assertEqual(
            (by_version["1.1.0"].old_version, by_version["1.1.0"].manual_reason),
            ("1.0.0", None),
        )
        self.assertIsNotNone(by_version["1.2.0"].manual_reason)
        self.assertEqual(by_version["1.2.0"].missing_criteria, ["safe-to-deploy"])

    def test_unmatched_sibling_version_remains_manual(self):
        # Two failing versions of the same crate; only one has a suggestion.
        report = {
            "conclusion": "fail (vetting)",
            "failures": [
                {"name": "example", "version": "1.1.0",
                 "missing_criteria": ["safe-to-deploy"]},
                {"name": "example", "version": "2.0.0",
                 "missing_criteria": ["safe-to-run"]},
            ],
            "suggest": {"suggestions": [{
                "name": "example",
                "notable_parents": "app",
                "suggested_diff": {"from": "1.0.0", "to": "1.1.0"},
            }]},
        }
        items = review.CargoVetParser().parse_vet_output(json.dumps(report))
        by_version = {item.new_version: item for item in items}
        self.assertEqual(set(by_version), {"1.1.0", "2.0.0"})
        self.assertIsNone(by_version["1.1.0"].manual_reason)
        self.assertIsNotNone(by_version["2.0.0"].manual_reason)
        self.assertEqual(by_version["2.0.0"].missing_criteria, ["safe-to-run"])

    def test_missing_published_suggestion_routes_to_manual_without_blocking(self):
        report = json.loads(self.vet_report())
        report["suggest"]["suggestions"] = []
        items = review.CargoVetParser().parse_vet_output(json.dumps(report))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].new_version, "1.1.0")
        self.assertIsNotNone(items[0].manual_reason)

    def test_human_hints_preserve_publisher_actions_without_adding_targets(self):
        report = json.loads(self.vet_report())
        report["review_hints"] = (
            "cargo vet diff example 1.0.0 1.1.0 publisher app 1 file changed, 5 insertions(+)\n"
            "    NOTE: this project trusts Example Author (trusted-login)\n"
            "cargo vet inspect extra 9.0.0 other app 20 lines\n"
        )
        items = review.CargoVetParser().parse_vet_output(json.dumps(report))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].publisher, "publisher")
        self.assertEqual(items[0].trust_note, "trusted-login")
        self.assertEqual(items[0].used_by, "app")

    def test_git_target_does_not_prevent_discovery_of_other_targets(self):
        targets = (("example", "1.0.0", "1.1.0@git:" + "a" * 40), ("other", None, "2.0.0"))
        items = review.CargoVetParser().parse_vet_output(self.vet_report(targets))
        self.assertEqual(len(items), 2)
        manual = next(item for item in items if item.crate_name == "example")
        self.assertEqual(manual.new_version, targets[0][2])
        self.assertIsNotNone(manual.manual_reason)

    def git_report(self):
        report = json.loads(self.vet_report((("rsa", "0.10.0", "0.10.0@git:" + "a" * 40),)))
        report["suggest"]["suggestions"][0]["suggested_diff"] = {
            "from": "0.10.0-rc.19", "to": "0.10.0",
        }
        return report

    def test_git_prerequisite_is_manual_without_requiring_target_equality(self):
        report = self.git_report()
        items = review.CargoVetParser().parse_vet_output(json.dumps(report))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].new_version, "0.10.0@git:" + "a" * 40)
        self.assertEqual(items[0].manual_commands, ["cargo vet diff rsa 0.10.0-rc.19 0.10.0"])
        self.assertEqual(items[0].missing_criteria, ["safe-to-deploy"])

    def test_published_failure_for_same_git_crate_is_also_manual(self):
        report = self.git_report()
        report["failures"].append({"name": "rsa", "version": "0.10.0",
                                   "missing_criteria": ["safe-to-run"]})
        report["suggest"]["suggestions"].append({
            "name": "rsa", "suggested_diff": {
                "from": "0.10.0@git:" + "b" * 40,
                "to": "0.10.0@git:" + "a" * 40,
            },
        })
        with self.main_flow([], vet_output=json.dumps(report)) as flow, \
             patch.object(review, "exempt_crate") as exempt:
            self.assertEqual(review.main(), 1)
        self.assertIn("cargo vet diff rsa 0.10.0@git:" + "b" * 40, self.stdout.getvalue())
        self.assertIn("--criteria safe-to-run", self.stdout.getvalue())
        for mocked in (flow.fetch, flow.ai, flow.automatic, flow.manual, flow.prompt, exempt):
            mocked.assert_not_called()

    def test_git_requirements_without_suggestions_remain_unresolved(self):
        for suggestions in (None, {}, {"suggestions": []}):
            with self.subTest(suggestions=suggestions):
                report = self.git_report() | {"suggest": suggestions}
                with self.main_flow([], vet_output=json.dumps(report)) as flow:
                    self.assertEqual(review.main(), 1)
                flow.fetch.assert_not_called()
                flow.ai.assert_not_called()
                flow.automatic.assert_not_called()
                flow.manual.assert_not_called()
                flow.prompt.assert_not_called()
                flow.final_check.assert_not_called()
        self.assertIn("cargo vet add-exemption rsa", self.stdout.getvalue())
        self.assertIn("cargo vet check", self.stdout.getvalue())
        self.assertNotIn("All dependencies are already vetted", self.stdout.getvalue())

    def test_manual_git_json_does_not_fetch_review_or_write(self):
        with self.main_flow([], flags=["--json"], vet_output=json.dumps(self.git_report())) as flow, \
             patch.object(review, "exempt_crate") as exempt, \
             patch.object(review, "AIAnalyzer") as analyzer, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(review.main(), 1)
        entry, = json.loads(output.getvalue())
        self.assertTrue(entry["manual_reason"])
        self.assertIn("0.10.0-rc.19 0.10.0", entry["recommendation"])
        for flag in ("ai_decision", "ai_complete", "auto_certified", "resolved"):
            self.assertFalse(entry[flag])
        for mocked in (flow.fetch, flow.ai, flow.automatic, flow.manual, flow.prompt, exempt, analyzer):
            mocked.assert_not_called()

    def test_mixed_git_and_published_requirements_review_only_published(self):
        report = self.git_report()
        published = json.loads(self.vet_report())
        report["failures"].extend(published["failures"])
        report["suggest"]["suggestions"].extend(published["suggest"]["suggestions"])
        gaps = review.CargoVetParser.gaps(report)
        with self.main_flow([self.report()], vet_output=json.dumps(report)) as flow:
            flow.final_check.return_value = (json.dumps(report), gaps - {("example", "1.1.0")})
            self.assertEqual(review.main(), 1)
        flow.fetch.assert_called_once_with("example", "1.0.0", "1.1.0", verbose=False)
        flow.ai.assert_called_once()
        flow.automatic.assert_called_once()
        self.assertEqual(flow.automatic.call_args.args[0].crate_name, "example")
        flow.prompt.assert_not_called()

    def test_git_handling_keeps_published_targets_reviewable(self):
        # Missing published suggestion: route that gap to manual without rejecting
        # the git requirement.
        missing = self.git_report()
        missing["failures"].extend(json.loads(self.vet_report())["failures"])
        items = review.CargoVetParser().parse_vet_output(json.dumps(missing))
        manual = {item.crate_name: item for item in items}
        self.assertEqual(set(manual), {"rsa", "example"})
        self.assertIsNotNone(manual["rsa"].manual_reason)
        self.assertIsNotNone(manual["example"].manual_reason)

        # Unrelated published suggestion still fails closed.
        unrelated = self.git_report()
        published = json.loads(self.vet_report())["suggest"]["suggestions"][0]
        published["name"] = "unrelated"
        unrelated["suggest"]["suggestions"].append(published)
        with self.assertRaisesRegex(ValueError, "failing published target"):
            review.CargoVetParser().parse_vet_output(json.dumps(unrelated))

    def test_command_errors_preserve_policy_diagnostics_and_never_report_success(self):
        diagnostic = "Some non-crates.io-fetched packages match published crates.io versions\nrsa:0.9.10"
        for stdout in ("", "not JSON", '{"conclusion": "fail (policy)"}'):
            for flags in ([], ["--json"]):
                with self.subTest(stdout=stdout, flags=flags), \
                     patch.object(review.sys, "argv", ["review", *flags]), \
                     patch.object(review.subprocess, "run", return_value=subprocess.CompletedProcess(
                         [], 1, stdout, diagnostic,
                     )) as run, \
                     patch.object(review.DiffFetcher, "fetch") as fetch, \
                     patch.object(review.AIAnalyzer, "analyze_diff") as ai, \
                     contextlib.redirect_stderr(io.StringIO()) as stderr, \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(review.main(), 1)
                messages = output.getvalue() + stderr.getvalue()
                self.assertIn(diagnostic, messages)
                self.assertIn("status 1", messages)
                self.assertIn("cargo vet --locked --frozen --output-format=json", messages)
                self.assertNotIn("already vetted", messages)
                if flags:
                    self.assertEqual(output.getvalue(), "")
                fetch.assert_not_called()
                ai.assert_not_called()
                run.assert_called_once()

    def test_contradictory_success_reports_are_errors(self):
        success_with_failures = json.loads(self.success_report())
        success_with_failures["failures"] = json.loads(self.vet_report())["failures"]
        for code, report in ((255, self.success_report()), (0, self.vet_report()),
                             (0, json.dumps(success_with_failures))):
            with self.subTest(code=code, report=report), \
                 patch.object(review.subprocess, "run", return_value=subprocess.CompletedProcess([], code, report, "")), \
                 self.assertRaises(ValueError):
                review.run_cargo_vet()

    def test_unresolved_runs_and_cancellation_return_failure(self):
        for flags, inputs in ((["--dry-run"], []), (["--json"], []), ([], ["s"]),
                              ([], ["q"]), ([], [EOFError]), ([], [KeyboardInterrupt]),
                              (["--skip-large", "1"], []), (["--crate", "missing"], [])):
            with self.subTest(flags=flags, inputs=inputs), \
                 self.main_flow([self.report(decision=False)], inputs=inputs, flags=flags,
                                source="+one\n+two\n") as flow:
                self.assertEqual(review.main(), 1)
            flow.final_check.assert_not_called()

    def test_successful_action_requires_final_vetting_success(self):
        for final_gaps, expected in ((set(), 0), ({("example", "1.1.0")}, 1)):
            with self.subTest(final_gaps=final_gaps), self.main_flow([self.report()]) as flow:
                flow.final_check.return_value = (
                    self.vet_report() if final_gaps else self.success_report(), final_gaps,
                )
                self.assertEqual(review.main(), expected)
            flow.final_check.assert_called_once_with(
                ["cargo", "vet", "--locked", "--frozen", "--output-format=json"]
            )

    def test_final_vetting_command_error_is_not_success(self):
        with self.main_flow([self.report()]) as flow:
            flow.final_check.side_effect = ValueError("policy configuration error")
            self.assertEqual(review.main(), 1)
        self.assertIn("Could not verify final vetting status", self.stdout.getvalue())

    def test_genuinely_vetted_dependencies_return_success(self):
        with self.main_flow([], vet_output=self.success_report()) as flow:
            self.assertEqual(review.main(), 0)
        flow.fetch.assert_not_called()
        self.assertIn("All dependencies are already vetted", self.stdout.getvalue())

    def test_successful_check_has_no_reviews_and_no_hint_command(self):
        report = json.dumps({"conclusion": "success", "vetted_fully": [],
                             "vetted_partially": [], "vetted_with_exemptions": []})
        with patch.object(review.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, report, "")) as run:
            self.assertEqual(review.CargoVetParser().parse_vet_output(review.run_cargo_vet()), [])
        run.assert_called_once()

    def test_locked_discovery_checks_status_and_gap_consistency(self):
        report = self.vet_report()
        with patch.object(review.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 255, report, ""),
            subprocess.CompletedProcess([], 255, report, ""),
            subprocess.CompletedProcess([], 1, "", "optional hints unavailable"),
        ]):
            self.assertEqual(review.run_cargo_vet(), report)
        for result in (subprocess.CompletedProcess([], 1, report, "failed"),
                       subprocess.CompletedProcess([], 0, report, ""),
                       subprocess.CompletedProcess([], 255, "not JSON", "")):
            with self.subTest(result=result), patch.object(review.subprocess, "run", return_value=result), \
                 self.assertRaises(ValueError):
                review.run_cargo_vet()
        with patch.object(review.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 255, report, ""),
            subprocess.CompletedProcess([], 255, self.vet_report((("other", None, "1.0.0"),)), ""),
        ]), self.assertRaisesRegex(ValueError, "disagree"):
            review.run_cargo_vet()

    def test_invalid_discovery_exits_with_error(self):
        with patch.object(review.sys, "argv", ["review"]), \
             patch.object(review, "run_cargo_vet", return_value="not JSON"), \
             patch.object(review.DiffFetcher, "fetch") as fetch:
            self.assertEqual(review.main(), 1)
        fetch.assert_not_called()

    @contextlib.contextmanager
    def main_flow(self, responses, inputs=(), flags=(), targets=(("example", "1.0.0", "1.1.0"),),
                  available=True, certify=True, source="+safe code", vet_output=None):
        fetched = review.FetchedDiff(source, None, Path("/unused"), False)
        with patch.object(review.sys, "argv", ["review", *flags]), \
             patch.object(review, "run_cargo_vet", return_value=vet_output or self.vet_report(targets)), \
             patch.object(review, "check_cargo_vet", return_value=(self.success_report(), set())) as final_check, \
             patch.object(review.DiffFetcher, "fetch", return_value=fetched) as fetch, \
             patch.object(review.AIAnalyzer, "is_available", return_value=available), \
             patch.object(review.AIAnalyzer, "review_diff",
                          side_effect=[review.AIReview.parse(value) for value in responses]) as ai, \
             patch("builtins.input", side_effect=inputs) as prompt, \
             patch.object(review, "auto_certify_crate", return_value=certify) as automatic, \
             patch.object(review, "certify_crate", return_value=True) as manual:
            yield SimpleNamespace(ai=ai, prompt=prompt, automatic=automatic, manual=manual,
                                  fetch=fetch, final_check=final_check)

    def test_positive_reviews_auto_certify_each_target_without_prompting(self):
        targets = (("example", "1.0.0", "1.1.0"), ("fresh", None, "2.0.0"))
        with self.main_flow([self.report(), self.report()], targets=targets) as flow:
            review.main()
        self.assertEqual(flow.automatic.call_count, 2)
        self.assertIsNone(flow.automatic.call_args.args[0].old_version)
        flow.prompt.assert_not_called()
        flow.manual.assert_not_called()

    def test_ordinary_mode_rejects_unsafe_classifications_before_certify(self):
        cases = [
            dict(severity="high"),
            dict(severity="critical"),
            dict(malicious=True),
            dict(severity=None),
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides), \
                 self.main_flow([self.report(**overrides)], inputs=["s"]) as flow:
                self.assertEqual(review.main(), 1)
            flow.automatic.assert_not_called()
            flow.manual.assert_not_called()
            flow.prompt.assert_called_once()

    def test_auto_exempt_policy_matrix_never_prompts(self):
        cases = [
            (True, True, "low", False, "certify"),
            (True, True, "medium", False, "certify"),
            (False, True, "low", False, "exempt"),
            (False, True, "medium", False, "exempt"),
            (False, True, "high", False, "block"),
            (False, True, "critical", False, "block"),
            (True, True, "high", False, "block"),
            (True, True, "critical", False, "block"),
            (True, True, "low", True, "block"),
            (False, True, "medium", True, "block"),
            (False, True, None, False, "skip"),
            (True, True, None, False, "skip"),
            (False, False, "low", False, "skip"),
        ]
        for decision, complete, severity, malicious, action in cases:
            with self.subTest(decision=decision, complete=complete, severity=severity,
                              malicious=malicious), \
                 self.main_flow([self.report(decision=decision, complete=complete,
                                            severity=severity, malicious=malicious)],
                                flags=["--auto-exempt"]) as flow, \
                 patch.object(review, "exempt_crate", return_value=True) as exempt, \
                 patch.object(review.subprocess, "run") as run:
                self.assertEqual(review.main(), 0 if action in ("certify", "exempt") else 1)
            self.assertEqual(flow.automatic.call_count, int(action == "certify"))
            self.assertEqual(exempt.call_count, int(action == "exempt"))
            self.assertEqual(flow.final_check.call_count, int(action in ("certify", "exempt")))
            flow.prompt.assert_not_called()
            flow.manual.assert_not_called()
            run.assert_not_called()

    def test_auto_exemption_keeps_detailed_review_and_ignores_pattern_risk(self):
        explanation = "src/lib.rs:7 moderate issue; requires a local attacker.\nFix: validate the path."
        finding = review.SecurityFinding("pattern", "Possible danger", review.RiskLevel.CRITICAL)
        with self.main_flow([self.report(decision=False, severity="medium", explanation=explanation)],
                            flags=["--auto-exempt"]) as flow, \
             patch.object(review.SecurityAnalyzer, "analyze_diff", return_value=[finding]), \
             patch.object(review, "exempt_crate", return_value=True) as exempt:
            self.assertEqual(review.main(), 0)
        crate, version, note = exempt.call_args.args
        self.assertEqual((crate, version), ("example", "1.1.0"))
        self.assertIn(explanation, note)
        self.assertIn("not certification", note)
        self.assertIn("codex", note)
        self.assertIn("MEDIUM", note)
        self.assertIn("remain unresolved", note)
        flow.ai.assert_called_once()
        flow.automatic.assert_not_called()
        flow.prompt.assert_not_called()

    def test_auto_exempt_skips_unavailable_or_failed_reviews(self):
        for response, available, source in ((None, True, "+code"), ("not JSON", True, "+code"),
                                             (None, False, "+code"), (None, True, "")):
            with self.subTest(response=response, available=available, source=source), \
                 self.main_flow([response], available=available, source=source,
                                flags=["--auto-exempt"]) as flow, \
                 patch.object(review, "exempt_crate") as exempt:
                self.assertEqual(review.main(), 1)
            flow.automatic.assert_not_called()
            exempt.assert_not_called()
            flow.prompt.assert_not_called()

    def test_auto_exempt_mixed_run_continues_after_block_skip_and_write_failure(self):
        targets = tuple((name, "1.0.0", "1.1.0") for name in
                        ("blocked", "unknown", "write-failed", "exempted", "approved"))
        responses = [self.report(severity="high"), None,
                     self.report(decision=False), self.report(decision=False), self.report()]
        with self.main_flow(responses, targets=targets, flags=["--auto-exempt"]) as flow, \
             patch.object(review, "exempt_crate", side_effect=[False, True]) as exempt:
            # Even a successful final graph check must not conceal blocked/skipped crates.
            self.assertEqual(review.main(), 1)
        self.assertEqual(flow.ai.call_count, 5)
        self.assertEqual([call.args[0] for call in exempt.call_args_list], ["write-failed", "exempted"])
        flow.automatic.assert_called_once()
        self.assertEqual(flow.automatic.call_args.args[0].crate_name, "approved")
        flow.final_check.assert_called_once()
        flow.prompt.assert_not_called()

    def test_auto_certification_failure_never_becomes_exemption(self):
        with self.main_flow([self.report()], certify=False, flags=["--auto-exempt"]) as flow, \
             patch.object(review, "exempt_crate") as exempt:
            self.assertEqual(review.main(), 1)
        flow.automatic.assert_called_once()
        exempt.assert_not_called()
        flow.prompt.assert_not_called()

    def test_auto_exempt_preserves_final_vetting_requirements(self):
        for failure in ("remaining", "error"):
            with self.subTest(failure=failure), \
                 self.main_flow([self.report(decision=False)], flags=["--auto-exempt"]) as flow, \
                 patch.object(review, "exempt_crate", return_value=True):
                if failure == "error":
                    flow.final_check.side_effect = ValueError("verification failed")
                else:
                    flow.final_check.return_value = (self.vet_report(), {("example", "1.1.0")})
                self.assertEqual(review.main(), 1)
            flow.prompt.assert_not_called()

    def test_auto_exempt_preview_reports_actions_without_writes(self):
        for flag in ("--dry-run", "--json"):
            with self.subTest(flag=flag), \
                 self.main_flow([self.report(decision=False, severity="medium")],
                                flags=["--auto-exempt", flag]) as flow, \
                 patch.object(review, "exempt_crate") as exempt, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(review.main(), 1)
            flow.automatic.assert_not_called()
            exempt.assert_not_called()
            flow.prompt.assert_not_called()
            if flag == "--json":
                entry, = json.loads(output.getvalue())
                self.assertEqual(entry["automatic_action"], "exempt")
                self.assertEqual(entry["ai_severity"], "medium")
                self.assertFalse(entry["ai_malicious"])
                self.assertFalse(entry["auto_exempted"])
                self.assertFalse(entry["resolved"])
                self.assertTrue(entry["automatic_reason"])

    def test_auto_exempt_skips_manual_git_requirements(self):
        with self.main_flow([], flags=["--auto-exempt"],
                            vet_output=json.dumps(self.git_report())) as flow, \
             patch.object(review, "exempt_crate") as exempt:
            self.assertEqual(review.main(), 1)
        for mocked in (flow.ai, flow.fetch, flow.automatic, flow.manual, flow.prompt, exempt):
            mocked.assert_not_called()

    def test_auto_exempt_clears_manual_placeholder_after_intermediate_audit(self):
        # Failure 1.2.0 with intermediate suggestion 1.0.0 -> 1.1.0. Certifying
        # the suggestion closes coverage; the manual 1.2.0 placeholder must not
        # keep --auto-exempt failing when the final locked check is clean.
        report = {
            "conclusion": "fail (vetting)",
            "failures": [{"name": "example", "version": "1.2.0",
                          "missing_criteria": ["safe-to-deploy"]}],
            "suggest": {"suggestions": [{
                "name": "example",
                "notable_parents": "app",
                "suggested_diff": {"from": "1.0.0", "to": "1.1.0"},
            }]},
        }
        with self.main_flow([self.report()], flags=["--auto-exempt"],
                            vet_output=json.dumps(report)) as flow:
            flow.final_check.return_value = (self.success_report(), set())
            self.assertEqual(review.main(), 0)
        flow.automatic.assert_called_once()
        self.assertEqual(flow.automatic.call_args.args[0].new_version, "1.1.0")
        flow.prompt.assert_not_called()

    def test_auto_exempt_keeps_manual_placeholder_when_final_gap_remains(self):
        # Same intermediate suggestion shape, but the locked re-check still
        # reports 1.2.0 uncovered. The placeholder must keep failing policy.
        report = {
            "conclusion": "fail (vetting)",
            "failures": [{"name": "example", "version": "1.2.0",
                          "missing_criteria": ["safe-to-deploy"]}],
            "suggest": {"suggestions": [{
                "name": "example",
                "notable_parents": "app",
                "suggested_diff": {"from": "1.0.0", "to": "1.1.0"},
            }]},
        }
        with self.main_flow([self.report()], flags=["--auto-exempt"],
                            vet_output=json.dumps(report)) as flow:
            flow.final_check.return_value = (
                json.dumps(report), {("example", "1.2.0")},
            )
            self.assertEqual(review.main(), 1)
        flow.automatic.assert_called_once()
        self.assertEqual(flow.automatic.call_args.args[0].new_version, "1.1.0")

    def test_auto_exempt_explicit_size_skip_continues_without_prompting(self):
        targets = (("skipped", "1.0.0", "1.1.0"), ("approved", None, "2.0.0"))
        with self.main_flow([self.report()], targets=targets,
                            flags=["--auto-exempt", "--skip-large", "2"]) as flow, \
             patch.object(review.DiffFetcher, "fetch", side_effect=[
                 review.FetchedDiff("+code\n" * 3, None, Path("/unused"), False),
                 review.FetchedDiff("+code\n", None, Path("/unused"), False),
             ]), patch.object(review, "exempt_crate") as exempt:
            self.assertEqual(review.main(), 1)
        flow.automatic.assert_called_once()
        self.assertEqual(flow.automatic.call_args.args[0].crate_name, "approved")
        flow.prompt.assert_not_called()
        exempt.assert_not_called()

    def test_auto_exempt_rejects_no_ai_before_discovery(self):
        with patch.object(review.sys, "argv", ["review", "--auto-exempt", "--no-ai"]), \
             patch.object(review, "run_cargo_vet") as discover, \
             self.assertRaises(SystemExit) as error:
            review.main()
        self.assertEqual(error.exception.code, 2)
        discover.assert_not_called()

    def test_large_complete_review_auto_certifies_without_prompting(self):
        source = "+safe code\n" * 7000
        with self.main_flow([self.report()], source=source) as flow:
            self.assertEqual(review.main(), 0)
        flow.ai.assert_called_once()
        self.assertEqual(flow.ai.call_args.kwargs["diff_content"], source)
        flow.automatic.assert_called_once()
        flow.prompt.assert_not_called()
        flow.manual.assert_not_called()

    def test_large_rejected_review_requires_manual_action(self):
        with self.main_flow([self.report(decision=False,
                            explanation="Unresolved cross-file dependency")],
                            source="+code\n" * 15000, inputs=["s"]) as flow:
            self.assertEqual(review.main(), 1)
        flow.ai.assert_called_once()
        flow.automatic.assert_not_called()
        flow.prompt.assert_called_once()
        flow.manual.assert_not_called()
        self.assertIn("Unresolved cross-file dependency", self.stdout.getvalue())

    def test_negative_review_prints_reason_and_offers_former_actions(self):
        with self.main_flow([self.report(decision=False, explanation="src/lib.rs:7 memory corruption")],
                            inputs=["d", "p", "r", "c"]) as flow:
            review.main()
        flow.automatic.assert_not_called()
        flow.manual.assert_called_once_with("example", "1.0.0", "1.1.0")
        self.assertIn("src/lib.rs:7 memory corruption", self.stdout.getvalue())
        self.assertIn("ACTIONS", self.stdout.getvalue())

    def test_ai_errors_and_unavailability_require_manual_actions(self):
        for response, available in ((None, True), ("Looks safe", True),
                                    (self.report(complete=False), True), (None, False)):
            with self.subTest(response=response, available=available), \
                 self.main_flow([response], inputs=["s"], available=available) as flow:
                review.main()
            flow.automatic.assert_not_called()
            flow.prompt.assert_called_once()

    def test_source_failure_requires_manual_handling_and_reviews_next_target(self):
        targets = (("example", None, "1.1.0"), ("other", None, "2.0.0"))
        with self.main_flow([self.report()], targets=targets, inputs=["s"]) as flow:
            with patch.object(review.DiffFetcher, "fetch", side_effect=[
                None, review.FetchedDiff("+safe code", None, Path("/unused"), False),
            ]):
                review.main()
        flow.prompt.assert_called_once()
        flow.automatic.assert_called_once()
        self.assertEqual(flow.automatic.call_args.args[0].crate_name, "other")
        self.assertIn("Source retrieval failed", self.stdout.getvalue())

    def test_manual_certification_failure_keeps_the_menu_open(self):
        with self.main_flow([self.report(decision=False)], inputs=["c", "s"]) as flow:
            flow.manual.return_value = False
            review.main()
        self.assertEqual(flow.prompt.call_count, 2)
        self.assertIn("Certification failed", self.stdout.getvalue())

    def test_auto_certification_failure_returns_to_menu_and_continues(self):
        targets = (("example", None, "1.1.0"), ("other", None, "2.0.0"))
        with self.main_flow([self.report(), self.report()], targets=targets,
                            inputs=["s", "s"], certify=False) as flow:
            review.main()
        self.assertEqual(flow.automatic.call_count, 2)
        self.assertEqual(flow.prompt.call_count, 2)

    def test_rerun_can_automatically_certify(self):
        with self.main_flow([self.report(decision=False), self.report()], inputs=["a"]) as flow:
            review.main()
        flow.automatic.assert_called_once()
        flow.prompt.assert_called_once()
        flow.manual.assert_not_called()

    def test_rerun_rejects_unsafe_classifications_before_certify(self):
        cases = [
            dict(severity="high"),
            dict(severity="critical"),
            dict(malicious=True),
            dict(severity=None),
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides), \
                 self.main_flow([self.report(decision=False), self.report(**overrides)],
                                inputs=["a", "s"]) as flow:
                self.assertEqual(review.main(), 1)
            flow.automatic.assert_not_called()
            flow.manual.assert_not_called()
            self.assertEqual(flow.prompt.call_count, 2)

    def test_dry_run_and_json_never_write_or_prompt(self):
        for flag in ("--dry-run", "--json"):
            with self.subTest(flag=flag), self.main_flow([self.report()], flags=[flag],
                                                       source="+unsafe { action(); }") as flow:
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    review.main()
                if flag == "--json":
                    result = json.loads(output.getvalue())
                    self.assertTrue(result[0]["ai_decision"])
                    self.assertTrue(result[0]["ai_complete"])
                    self.assertFalse(result[0]["auto_certified"])
                    self.assertTrue(result[0]["findings"])
            flow.automatic.assert_not_called()
            flow.manual.assert_not_called()
            flow.prompt.assert_not_called()

    def test_no_ai_keeps_manual_certification(self):
        with self.main_flow([], flags=["--no-ai"], inputs=["c"]) as flow:
            review.main()
        flow.ai.assert_not_called()
        flow.automatic.assert_not_called()
        flow.manual.assert_called_once()

    def test_large_reviews_are_not_skipped_by_default(self):
        with self.main_flow([self.report()], source="+code\n" * 100001) as flow:
            # Batch coverage has separate tests; here verify the main loop reaches AI review.
            approved = review.AIReview(
                True, True, "safe", review.RiskLevel.LOW, False,
            )
            with patch.object(review.AIAnalyzer, "review_diff", return_value=approved) as ai:
                review.main()
        ai.assert_called_once()
        flow.automatic.assert_called_once()
        with self.main_flow([], flags=["--skip-large", "1"], source="+one\n+two\n") as flow:
            review.main()
        flow.ai.assert_not_called()
        flow.automatic.assert_not_called()
        flow.prompt.assert_not_called()

    def test_audits_use_ai_identity_and_preserve_existing_entries(self):
        for old, provider in ((None, "claude"), ("1.0.0", "codex"), (None, "gemini")):
            with self.subTest(old=old, provider=provider), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = root / "supply-chain"
                store.mkdir()
                audits = store / "audits.toml"
                original = '# existing user edit\n[[audits.existing]]\nwho = "Human"\ncriteria = "safe-to-deploy"\nversion = "1.0.0"\n'
                audits.write_text(original)
                (store / "imports.lock").write_text("original imports")
                item = SimpleNamespace(crate_name="example", old_version=old, new_version="1.1.0")
                def formatter(command, **kwargs):
                    staged = Path(command[command.index("--store-path") + 1])
                    self.assertNotEqual(staged, store)
                    (staged / "imports.lock").write_text("formatter side effect")
                    return subprocess.CompletedProcess(command, 0, "", "")
                with patch.object(review, "PROJECT_ROOT", root), \
                     patch.object(review.subprocess, "run", side_effect=formatter):
                    self.assertTrue(review.auto_certify_crate(item, provider))
                parsed = review.tomllib.loads(audits.read_text())["audits"]
                self.assertEqual(parsed["existing"][0]["who"], "Human")
                entry = parsed["example"][0]
                self.assertEqual(entry["criteria"], "safe-to-deploy")
                self.assertEqual(entry["who"], f"{provider.capitalize()} (automated via {provider} CLI)")
                self.assertEqual(entry.get("delta"), "1.0.0 -> 1.1.0" if old else None)
                self.assertEqual(entry.get("version"), None if old else "1.1.0")
                self.assertEqual((store / "imports.lock").read_text(), "original imports")
                self.assertTrue(audits.read_text().startswith(original))

    def test_concurrent_audit_edits_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "supply-chain").mkdir()
            audits = root / "supply-chain" / "audits.toml"
            audits.write_text("# original\n")
            item = SimpleNamespace(crate_name="example", old_version=None, new_version="1.1.0")
            def formatter(command, **kwargs):
                audits.write_text("# concurrent edit\n")
                return subprocess.CompletedProcess(command, 0, "", "")
            with patch.object(review, "PROJECT_ROOT", root), \
                 patch.object(review.subprocess, "run", side_effect=formatter):
                self.assertFalse(review.auto_certify_crate(item, "codex"))
            self.assertEqual(audits.read_text(), "# concurrent edit\n")

    def test_audit_failures_leave_original_file_untouched(self):
        for failure in ("exit", "timeout", "changed", "malformed", "replace"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = root / "supply-chain"
                store.mkdir()
                audits = store / "audits.toml"
                original = b"# user edits\n"
                audits.write_bytes(original)
                item = SimpleNamespace(crate_name="example", old_version=None, new_version="1.1.0")
                def formatter(command, **kwargs):
                    staged = Path(command[command.index("--store-path") + 1]) / "audits.toml"
                    if failure == "timeout":
                        raise subprocess.TimeoutExpired(command, 120)
                    if failure == "changed":
                        staged.write_text(staged.read_text().replace("safe-to-deploy", "safe-to-run"))
                    if failure == "malformed":
                        staged.write_text("[invalid")
                    return subprocess.CompletedProcess(command, 1 if failure == "exit" else 0, "", "mock failure")
                with patch.object(review, "PROJECT_ROOT", root), \
                     patch.object(review.subprocess, "run", side_effect=formatter), \
                     patch.object(review.os, "replace", side_effect=OSError("write failed")):
                    self.assertFalse(review.auto_certify_crate(item, "codex"))
                self.assertEqual(audits.read_bytes(), original)
                self.assertEqual(list(store.iterdir()), [audits])

    def test_large_diff_uses_shared_file_and_bounded_assignments(self):
        source = "diff --git a/x b/x\n" + "x" * 500000 + "\n" + "short\n" * 12500
        with tempfile.TemporaryDirectory() as root:
            paths, primary = [], []
            def run(command, **kwargs):
                self.assertEqual(kwargs["timeout"], 1800)
                prompt = kwargs["input"]
                path = Path(re.search(r"available at: (.+)\n", prompt).group(1))
                paths.append(path)
                data = json.loads(path.read_text())
                self.assertEqual(Path(data["full_diff"]).read_text(), source)
                if "primary" in data:
                    text = Path(data["primary"]).read_text()
                    self.assertLessEqual(len(text), review.StagedReview.SOURCE_MAX_CHARS)
                    self.assertLessEqual(len(text.splitlines()), review.StagedReview.SOURCE_MAX_LINES)
                    primary.append((data["start"], data["end"], text))
                Path(command[command.index("--output-last-message") + 1]).write_text(stage_report(data))
                return subprocess.CompletedProcess(command, 0, "", "")
            analyzer = review.AIAnalyzer("codex")
            with patch.object(review, "PROJECT_ROOT", Path(root)), \
                 patch.object(analyzer, "is_available", return_value=True), \
                 patch.object(review.subprocess, "run", side_effect=run):
                result = analyzer.review_diff(source, **self.kwargs)
            self.assertTrue(result.decision)
            self.assertTrue(result.complete)
            self.assertEqual("".join(text for _, _, text in sorted(primary)), source)
            self.assertGreater(len(primary), 3)
            self.assertTrue(all(not path.exists() for path in paths))
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_staged_prompts_reach_each_provider_with_the_configured_timeout(self):
        for provider in ("codex", "claude", "gemini"):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as root:
                stages = []

                def run(command, **kwargs):
                    prompt = kwargs.get("input") or command[command.index("-p") + 1]
                    data = json.loads(Path(re.search(r"available at: (.+)\n", prompt).group(1)).read_text())
                    stages.append(data["task_id"])
                    self.assertIn("Review Criteria", prompt)
                    self.assertNotIn("## Your Analysis", prompt)
                    self.assertEqual(kwargs["timeout"], 73)
                    response = stage_report(data)
                    if provider == "codex":
                        Path(command[command.index("--output-last-message") + 1]).write_text(response)
                        response = ""
                    return subprocess.CompletedProcess(command, 0, response, "")

                analyzer = review.AIAnalyzer(provider, timeout=73)
                with patch.object(review, "PROJECT_ROOT", Path(root)), \
                     patch.object(analyzer, "is_available", return_value=True), \
                     patch.object(review.subprocess, "run", side_effect=run):
                    result = analyzer.review_diff("+safe code", **self.kwargs)
                self.assertTrue(result.decision)
                self.assertEqual(stages, ["source-1", "integration-1"])
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_ai_timeout_cli_default_and_override_reach_provider(self):
        review_diff = review.AIAnalyzer.review_diff
        for flags, expected in (([], 1800), (["--ai-timeout", "3600"], 3600)):
            def run(command, **kwargs):
                data = json.loads(Path(re.search(r"available at: (.+)\n", kwargs["input"]).group(1)).read_text())
                Path(command[command.index("--output-last-message") + 1]).write_text(stage_report(data))
                return subprocess.CompletedProcess(command, 0, "", "")
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as root, \
                 self.main_flow([], flags=flags) as flow, \
                 patch.object(review, "PROJECT_ROOT", Path(root)), \
                 patch.object(review.AIAnalyzer, "review_diff", review_diff), \
                 patch.object(review.subprocess, "run", side_effect=run) as invoke:
                self.assertEqual(review.main(), 0)
            self.assertEqual(invoke.call_count, 2)
            self.assertTrue(all(call.kwargs["timeout"] == expected for call in invoke.call_args_list))
            flow.automatic.assert_called_once()
            flow.prompt.assert_not_called()

    def test_ai_timeout_cli_rejects_invalid_values_before_review(self):
        for value in ("0", "-1", "invalid", "1.5"):
            with self.subTest(value=value), \
                 patch.object(review.sys, "argv", ["review", "--ai-timeout", value]), \
                 patch.object(review, "run_cargo_vet") as discover, \
                 self.assertRaises(SystemExit) as error:
                review.main()
            self.assertEqual(error.exception.code, 2)
            discover.assert_not_called()

    def test_configured_provider_timeout_prompts_only_in_interactive_mode(self):
        review_diff = review.AIAnalyzer.review_diff
        for extra, inputs, prompts in (([], ["s"], 1), (["--auto-exempt"], [], 0)):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as root, \
                 self.main_flow([], flags=["--ai-timeout", "42", *extra], inputs=inputs) as flow, \
                 patch.object(review, "PROJECT_ROOT", Path(root)), \
                 patch.object(review.AIAnalyzer, "review_diff", review_diff), \
                 patch.object(review, "exempt_crate") as exempt, \
                 patch.object(review.subprocess, "run",
                              side_effect=subprocess.TimeoutExpired("codex", 42)) as invoke:
                self.assertEqual(review.main(), 1)
                workspace = next(Path(root).iterdir())
                self.assertTrue((workspace / "failure.json").exists())
            self.assertEqual(invoke.call_args.kwargs["timeout"], 42)
            flow.automatic.assert_not_called()
            exempt.assert_not_called()
            self.assertEqual(flow.prompt.call_count, prompts)
            self.assertIn("timed out (42s)", self.stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
