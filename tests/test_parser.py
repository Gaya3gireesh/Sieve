import unittest

from app.parser import DiffAnalyzer


class DiffAnalyzerTests(unittest.TestCase):
    def test_low_effort_detected_for_comment_only_changes(self) -> None:
        diff_text = """\
diff --git a/app.py b/app.py
@@ -1,2 +1,4 @@
+# new comment
+# another comment
+   
"""
        result = DiffAnalyzer(snr_threshold=0.10).analyze(diff_text)
        self.assertTrue(result.is_low_effort)
        self.assertEqual(result.logic_lines, 0)
        self.assertGreaterEqual(result.noise_lines, 2)

    def test_docs_only_flag(self) -> None:
        diff_text = """\
diff --git a/README.md b/README.md
@@ -1,1 +1,2 @@
+Add setup section.
"""
        result = DiffAnalyzer(snr_threshold=0.10).analyze(diff_text)
        self.assertTrue(result.is_docs_only)


if __name__ == "__main__":
    unittest.main()
