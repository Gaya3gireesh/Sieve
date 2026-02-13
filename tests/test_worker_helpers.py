import unittest
import os

os.environ.setdefault(
    "SUPABASE_URL",
    "postgresql+asyncpg://postgres.test:pass@pooler.supabase.com:6543/postgres",
)
os.environ.setdefault("SUPABASE_KEY", "test-key")
os.environ.setdefault("GROQ_API_KEY", "test-key")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret")
os.environ.setdefault("GITHUB_TOKEN", "test-token")

from app.worker import _is_vague_description, _parse_quality_report


class WorkerHelperTests(unittest.TestCase):
    def test_vague_description_detected(self) -> None:
        body = "This PR has minor improvements and general improvements to enhance performance."
        self.assertTrue(_is_vague_description(body))

    def test_specific_description_not_vague(self) -> None:
        body = (
            "Fixes #42\n\n"
            "Expected: API returned 500 for empty payload.\n"
            "Actual: now returns 400 with validation detail.\n"
            "Added tests for /webhook."
        )
        self.assertFalse(_is_vague_description(body))

    def test_parse_quality_report_defaults(self) -> None:
        score, issues = _parse_quality_report({"quality_score": "bad", "issues": "n/a"})
        self.assertEqual(score, 1.0)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
