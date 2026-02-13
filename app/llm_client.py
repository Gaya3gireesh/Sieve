"""
Sentinel — Groq LLM client.

Single AI provider (Llama-3-70b via Groq) for spam classification,
issue-alignment checking, and code-quality analysis.
"""

from __future__ import annotations

import json
import logging
import textwrap
from typing import Any

from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _chunk_text(text: str, max_chars: int = 18_000) -> list[str]:
    """Split *text* into chunks that fit in the Groq context window.

    ``max_chars`` ≈ 6 000 tokens (rough 3-chars-per-token estimate)
    leaving headroom for the system prompt and response.
    """
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    while text:
        chunks.append(text[:max_chars])
        text = text[max_chars:]
    return chunks


class GroqClient:
    """Thin wrapper around the Groq SDK for Sentinel's AI tasks."""

    def __init__(self) -> None:
        self._client = Groq(api_key=settings.groq_api_key)
        self._model = settings.groq_model

    # ── helpers ─────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    def _chat(self, system: str, user: str) -> str:
        """Send a chat completion and return the assistant's text."""
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.1,
            max_tokens=1024,
        )
        return resp.choices[0].message.content or ""

    def _parse_json(self, raw: str) -> dict[str, Any]:
        """Best-effort JSON extraction from LLM output."""
        # Strip markdown fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM JSON, returning raw text")
            return {"raw": raw}

    # ── public API ──────────────────────────────────────────────────────

    def classify_spam(self, pr_meta: dict[str, Any]) -> dict[str, Any]:
        """Classify whether a PR is spam / AI-generated slop.

        Parameters
        ----------
        pr_meta : dict
            Keys: ``author``, ``account_age_days``, ``title``,
            ``body``, ``repo``, ``files_changed``.

        Returns
        -------
        dict  ``{is_spam: bool, confidence: float, reason: str}``
        """
        system = textwrap.dedent("""\
            You are Sentinel, a GitHub PR spam detector.
            Analyse the metadata below and decide if the PR is spam,
            AI-generated slop, or a legitimate contribution.

            Signals of spam / slop:
            - Account younger than 7 days
            - Generic AI-written description (e.g. "This PR improves code quality")
            - Repo-hopping: many PRs across unrelated repos in short time
            - Trivial changes marketed as "improvements"

            Respond ONLY with JSON:
            {"is_spam": <bool>, "confidence": <0.0-1.0>, "reason": "<short explanation>"}
        """)
        user = json.dumps(pr_meta, indent=2, default=str)
        return self._parse_json(self._chat(system, user))

    def check_issue_alignment(
        self,
        pr_body: str,
        issue_body: str,
        issue_title: str,
    ) -> dict[str, Any]:
        """Check whether a PR genuinely addresses the linked issue.

        Returns
        -------
        dict  ``{aligned: bool, score: float, explanation: str}``
        """
        system = textwrap.dedent("""\
            You are Sentinel, a GitHub PR reviewer.
            Determine whether the Pull Request description and changes
            genuinely address the linked Issue.

            Respond ONLY with JSON:
            {"aligned": <bool>, "score": <0.0-1.0>, "explanation": "<short>"}
        """)
        user = (
            f"## Issue\n**Title:** {issue_title}\n\n{issue_body}\n\n"
            f"## Pull Request Body\n{pr_body}"
        )
        return self._parse_json(self._chat(system, user))

    def analyze_code_quality(self, diff_text: str) -> dict[str, Any]:
        """Deep code-quality analysis on a diff.

        Large diffs are chunked; results are merged.

        Returns
        -------
        dict  ``{quality_score: float, issues: [...], summary: str}``
        """
        system = textwrap.dedent("""\
            You are Sentinel, a code-review AI.
            Analyse the unified diff below.  Look for:
            - Bugs or logic errors introduced
            - Security issues
            - Style / best-practice violations
            - Dead code / unnecessary changes

            Respond ONLY with JSON:
            {
                "quality_score": <0.0-1.0>,
                "issues": [{"severity": "low|medium|high", "description": "..."}],
                "summary": "<one paragraph>"
            }
        """)
        chunks = _chunk_text(diff_text)
        if len(chunks) == 1:
            return self._parse_json(self._chat(system, chunks[0]))

        # Merge multi-chunk results
        all_issues: list[dict] = []
        scores: list[float] = []
        for i, chunk in enumerate(chunks, 1):
            header = f"[Chunk {i}/{len(chunks)}]\n"
            result = self._parse_json(self._chat(system, header + chunk))
            scores.append(float(result.get("quality_score", 0.5)))
            all_issues.extend(result.get("issues", []))

        avg_score = sum(scores) / len(scores) if scores else 0.5
        return {
            "quality_score": round(avg_score, 3),
            "issues": all_issues,
            "summary": f"Analysed {len(chunks)} diff chunks. "
                       f"Average quality score: {avg_score:.2f}.",
        }
