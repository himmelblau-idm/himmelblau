#!/usr/bin/env python3
"""Offline regressions for target-scoped backport cache decisions."""
import tempfile
import unittest
from pathlib import Path
from backport import AnalysisCache, select_backport_candidates
from types import SimpleNamespace
from unittest.mock import Mock

class AnalysisCacheTests(unittest.TestCase):
    def test_legacy_decisions_never_apply_to_a_target_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = AnalysisCache(Path(directory))
            for verdict in ('BACKPORT', 'SKIP', 'MAYBE'):
                cache.set('commit', {'verdict': verdict})
                for scope in ('stable-3.x', 'stable-2.x', 'stable-2.x,stable-3.x'):
                    self.assertIsNone(cache.get('commit', scope))
                self.assertEqual(cache.get('commit'), {'verdict': verdict})

    def test_scoped_decisions_are_reused_only_for_matching_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = AnalysisCache(Path(directory))
            decision = {'verdict': 'BACKPORT'}
            cache.set('commit', decision, 'stable-3.x')
            self.assertEqual(cache.get('commit', 'stable-3.x'), decision)
            self.assertIsNone(cache.get('commit', 'stable-2.x'))

class BackportCandidateTests(unittest.TestCase):
    def test_exclusions_are_not_reported_as_already_backported(self):
        def commit(sha, **flags):
            return SimpleNamespace(sha=sha, subject=sha, **dict(is_merge=False, is_dependabot=False, is_ci_only=False) | flags)
        commits = [commit('merge', is_merge=True), commit('deps', is_dependabot=True),
                   commit('ci', is_ci_only=True), commit('both'), commit('one'), commit('neither')]
        versions = [SimpleNamespace(branch='stable-3.x'), SimpleNamespace(branch='stable-2.x')]
        git = Mock()
        git.is_commit_in_branch.side_effect = lambda sha, branch, subject: sha == 'both' or (sha == 'one' and branch == 'origin/stable-3.x')
        candidates, present, count = select_backport_candidates(commits, versions, git)
        self.assertEqual(count, 1)
        self.assertEqual([c.sha for c in candidates], ['one', 'neither'])
        self.assertEqual(present['one'], {'stable-3.x'})
        self.assertEqual(git.is_commit_in_branch.call_count, 6)

if __name__ == '__main__':
    unittest.main()
