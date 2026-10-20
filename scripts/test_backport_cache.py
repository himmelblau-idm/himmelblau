import tempfile
import unittest
from pathlib import Path
from backport import AnalysisCache


class AnalysisCacheTests(unittest.TestCase):
    def test_scoped_requests_never_reuse_unscoped_verdicts(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = AnalysisCache(Path(directory))
            for verdict in ("BACKPORT", "SKIP", "MAYBE"):
                with self.subTest(verdict=verdict):
                    cache.set("commit", {"verdict": verdict})
                    self.assertIsNone(cache.get("commit", "stable-3.x"))
                    self.assertEqual(cache.get("commit"), {"verdict": verdict})
            cache.set("commit", {"verdict": "BACKPORT"}, "stable-3.x")
            self.assertEqual(cache.get("commit", "stable-3.x"), {"verdict": "BACKPORT"})
            self.assertIsNone(cache.get("commit", "stable-2.x"))


if __name__ == "__main__":
    unittest.main()
