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


class ReviewTests(unittest.TestCase):
    kwargs = dict(crate_name="example", old_version="1.0", new_version="1.1",
                  publisher="publisher", verbose=False)

    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def report(self, **overrides):
        value = dict(complete=True, risk="LOW", summary="Reviewed all content",
                     findings=[], follow_up="None", decision="accept", reasons=[])
        value.update(overrides)
        return json.dumps(value)

    def batches(self, responses, **kwargs):
        analyzer = review.AIAnalyzer("codex")
        with patch.object(analyzer, "analyze_diff", side_effect=responses):
            return analyzer._analyze_batches(["one", "two"], **(self.kwargs | kwargs))

    def test_rejected_decisions_and_highest_risk_survive_safe_synthesis(self):
        for decision in ("reject", "needs_review"):
            for verbose in (False, True):
                with self.subTest(decision=decision, verbose=verbose):
                    result = self.batches([
                        self.report(risk="CRITICAL", decision=decision,
                                    reasons=["src/lib.rs:7 unsound pointer"]),
                        self.report(), "Looks safe; certify."], verbose=verbose)
                    self.assertIn("Highest reported risk: CRITICAL", result)
                    self.assertIn(f"Batch 1 ({decision}): src/lib.rs:7 unsound pointer", result)
                    self.assertIn("Vetting withheld", result)
                    self.assertIn("cross-file safety", result)

    def test_coverage_gap_survives_synthesis(self):
        result = self.batches(["not JSON", self.report(), "Looks safe; certify."])
        self.assertIn("1/2 batches complete", result)
        self.assertIn("Do not certify", result)

    def test_incomplete_accept_is_invalid(self):
        result = self.batches([self.report(complete=False), self.report(), None])
        self.assertIn("incomplete review cannot accept vetting", result)
        self.assertIn("Do not certify", result)

    def test_failed_synthesis_retains_rejection(self):
        result = self.batches([
            self.report(decision="reject", reasons=["blocker"], risk="HIGH"),
            self.report(), None])
        self.assertIn("Final synthesis failed", result)
        self.assertIn("Batch 1 (reject): blocker", result)
        self.assertIn("Highest reported risk: HIGH", result)

    def test_fenced_json_is_accepted(self):
        for fence in ("```json\n", "```\n"):
            with self.subTest(fence=fence):
                result = self.batches([fence + self.report() + "\n```",
                                       self.report(), "Synthesis complete"])
                self.assertIn("2/2 batches complete", result)

    def test_ambiguous_or_malformed_json_is_not_certifiable(self):
        for bad in ("{}{}", "prefix " + self.report(), "[]", "{broken}",
                    self.report(decision="reject", reasons=[]),
                    self.report(complete="true")):
            with self.subTest(bad=bad):
                result = self.batches([bad, self.report(), "Looks safe; certify."])
                self.assertIn("Do not certify", result)
                self.assertIn("1/2 batches complete", result)

    def test_provider_workspace_and_cleanup_on_all_invocations(self):
        for provider, attempts in (("claude", 3), ("gemini", 2), ("codex", 1)):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                paths = []
                def run(command, **kwargs):
                    self.assertEqual(kwargs["cwd"], root)
                    prompt = kwargs.get("input")
                    if prompt is None:
                        flag = "-p" if "-p" in command else "--print"
                        prompt = command[command.index(flag) + 1]
                    path = Path(re.search(r"available at: (.+)\n", prompt).group(1))
                    paths.append(path)
                    self.assertEqual(path.parent, root)
                    self.assertEqual(path.read_text(), "untrusted source")
                    if provider == "codex":
                        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)
                        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
                        self.assertEqual(command[command.index("--cd") + 1], str(root))
                        Path(command[command.index("--output-last-message") + 1]).write_text("Reviewed source fully")
                        return subprocess.CompletedProcess(command, 0, "", "")
                    # Exercise every fallback, not just the first invocation.
                    return subprocess.CompletedProcess(command, 1, "", "mock failure")
                analyzer = review.AIAnalyzer(provider)
                with patch.object(review, "PROJECT_ROOT", root), \
                     patch.object(analyzer, "is_available", return_value=True), \
                     patch.object(review.subprocess, "run", side_effect=run) as mocked:
                    result = analyzer.analyze_diff("untrusted source", **self.kwargs)
                self.assertEqual(mocked.call_count, attempts)
                self.assertTrue(paths)
                self.assertTrue(all(not path.exists() for path in paths))
                if provider == "codex":
                    self.assertEqual(result, "Reviewed source fully")

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
                               trust_note=None)
        fetched = review.FetchedDiff("+safe code", None, Path("/unused"), False)
        with patch.object(review.sys, "argv", ["review"] + ([] if ai else ["--no-ai"])), \
             patch.object(review, "run_cargo_vet", return_value="Vetting Failed"), \
             patch.object(review.CargoVetParser, "parse_vet_output", return_value=[item]), \
             patch.object(review.DiffFetcher, "fetch", return_value=fetched), \
             patch.object(review.AIAnalyzer, "is_available", return_value=True), \
             patch.object(review.AIAnalyzer, "analyze_diff", side_effect=["Existing review", "Generated exemption"]), \
             patch("builtins.input", side_effect=inputs), \
             patch.object(review, "exempt_crate", return_value=True) as exempt:
            review.main()
            return exempt

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

    def test_batches_preserve_entire_input_and_budgets(self):
        analyzer = review.AIAnalyzer("codex")
        source = "diff --git a/x b/x\n" + "x" * 125000 + "\n" + "short\n" * 3100
        batches = analyzer._review_batches(source)
        self.assertEqual("".join(batches), source)
        self.assertTrue(all(len(batch) <= analyzer.REVIEW_MAX_CHARS for batch in batches))
        self.assertTrue(all(len(batch.splitlines()) <= analyzer.REVIEW_MAX_LINES for batch in batches))


if __name__ == "__main__":
    unittest.main()
