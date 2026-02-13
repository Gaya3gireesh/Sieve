"""
Sentinel — Celery worker.

Orchestrates the full PR analysis pipeline:
  1. Fetch PR details (PyGitHub)
  2. Spam filter (Groq)
  3. Policy engine (.sentinel.yaml)
  4. Effort analysis (regex parser)
  5. Issue alignment (Groq)
  6. Verdict → label / close / pushback
  7. Persist PRScan record
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

import yaml
from celery import Celery
from github import Auth, Github

from app.config import get_settings
from app.models import Verdict

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Celery app ──────────────────────────────────────────────────────────────
# broker_connection_retry_on_startup prevents crash if Redis is down at import

celery_app = Celery("sentinel")
celery_app.conf.update(
    broker_url=settings.redis_url,
    result_backend=settings.redis_url,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)

# ── Lazy clients (created on first task execution, not at import) ───────────

_groq = None
_analyzer = None


def _get_groq():
    global _groq
    if _groq is None:
        from app.llm_client import GroqClient
        _groq = GroqClient()
    return _groq


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        from app.parser import DiffAnalyzer
        _analyzer = DiffAnalyzer(snr_threshold=settings.effort_snr_threshold)
    return _analyzer


# ── Helper: GitHub client ───────────────────────────────────────────────────


def _github() -> Github:
    return Github(auth=Auth.Token(settings.github_token))


# ── Helper: fetch .sentinel.yaml ────────────────────────────────────────────


def _fetch_sentinel_config(repo) -> dict[str, Any]:  # type: ignore[type-arg]
    """Fetch and parse .sentinel.yaml from the repo root. Returns {} on miss."""
    try:
        content = repo.get_contents(".sentinel.yaml")
        return yaml.safe_load(content.decoded_content.decode()) or {}
    except Exception:
        logger.info("No .sentinel.yaml found, skipping policy engine")
        return {}


# ── Helper: policy engine ───────────────────────────────────────────────────


def _check_policies(
    config: dict[str, Any],
    changed_files: list[str],
    pr,
) -> list[dict[str, str]]:
    """Evaluate .sentinel.yaml rules against the PR.

    Supported rule types:
    - ``protected_paths``: list of path prefixes that require extra reviewers.
    - ``min_description_length``: minimum PR body length.
    - ``blocked_file_patterns``: glob patterns that should never be modified.
    """
    violations: list[dict[str, str]] = []

    # ── protected paths ─────────────────────────────────────────────────
    protected = config.get("protected_paths", [])
    for rule in protected:
        prefix = rule.get("path", "")
        min_reviewers = rule.get("min_reviewers", 1)
        touching = [f for f in changed_files if f.startswith(prefix)]
        if touching:
            review_count = pr.get_reviews().totalCount
            if review_count < min_reviewers:
                violations.append({
                    "rule": "protected_path",
                    "detail": (
                        f"Files under '{prefix}' require {min_reviewers} "
                        f"reviewer(s) but only {review_count} found."
                    ),
                })

    # ── minimum description length ──────────────────────────────────────
    min_desc = config.get("min_description_length", 0)
    if min_desc and len(pr.body or "") < min_desc:
        violations.append({
            "rule": "min_description_length",
            "detail": (
                f"PR description is {len(pr.body or '')} chars; "
                f"minimum is {min_desc}."
            ),
        })

    # ── blocked file patterns ───────────────────────────────────────────
    blocked = config.get("blocked_file_patterns", [])
    for pattern in blocked:
        rx = re.compile(pattern)
        matched = [f for f in changed_files if rx.search(f)]
        if matched:
            violations.append({
                "rule": "blocked_file_pattern",
                "detail": (
                    f"Files matching '{pattern}' are blocked: "
                    f"{', '.join(matched[:5])}"
                ),
            })

    return violations


# ── Helper: extract linked issue ────────────────────────────────────────────

_ISSUE_RE = re.compile(
    r"(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(\d+)",
    re.IGNORECASE,
)


def _extract_issue_number(body: str | None) -> int | None:
    """Return the first linked issue number from a PR body, or None."""
    if not body:
        return None
    m = _ISSUE_RE.search(body)
    return int(m.group(1)) if m else None


# ── Helper: apply verdict ───────────────────────────────────────────────────


def _apply_verdict(
    pr,
    repo,
    verdict: Verdict,
    reason: str,
) -> None:
    """Label, comment, or close the PR based on the verdict."""
    if verdict == Verdict.PASSED:
        pr.add_to_labels("sentinel-verified")
        pr.create_issue_comment(
            f"✅ **Sentinel — Verified**\n\n{reason}\n\n"
            f"This PR has passed automated review."
        )

    elif verdict == Verdict.FAILED:
        pr.create_issue_comment(
            f"❌ **Sentinel — Rejected**\n\n{reason}\n\n"
            f"This PR has been automatically closed. "
            f"Please address the issues above and resubmit."
        )
        pr.edit(state="closed")

    elif verdict == Verdict.SOFT_FAIL:
        pr.create_issue_comment(
            f"🤔 **Sentinel — Needs Clarification**\n\n{reason}\n\n"
            f"Could you please provide more context so a maintainer "
            f"can review this effectively?"
        )


# ── The main pipeline task ──────────────────────────────────────────────────


@celery_app.task(name="sentinel.process_pr", bind=True, max_retries=2)
def process_pr(self, payload: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
    """Full Sentinel analysis pipeline for a single PR event."""
    groq = _get_groq()
    analyzer = _get_analyzer()

    pr_data = payload.get("pull_request", {})
    repo_full_name = payload.get("repository", {}).get("full_name", "")
    pr_number = pr_data.get("number", 0)

    logger.info("Processing %s#%s", repo_full_name, pr_number)

    # ── 1. Fetch PR & author info via PyGitHub ──────────────────────────
    g = _github()
    repo = g.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)
    author = pr.user

    account_age_days = (
        datetime.now(timezone.utc) - author.created_at.replace(tzinfo=timezone.utc)
    ).days

    # Get changed file list
    changed_files = [f.filename for f in pr.get_files()]

    # ── 2. Spam filter (Groq) ───────────────────────────────────────────
    pr_meta = {
        "author": author.login,
        "account_age_days": account_age_days,
        "title": pr.title,
        "body": pr.body or "",
        "repo": repo_full_name,
        "files_changed": len(changed_files),
    }
    spam_result = groq.classify_spam(pr_meta)
    spam_score = float(spam_result.get("confidence", 0))
    is_spam = spam_result.get("is_spam", False)

    if is_spam and spam_score >= settings.spam_threshold:
        _apply_verdict(
            pr, repo, Verdict.FAILED,
            f"🚫 **Spam detected** (confidence {spam_score:.0%}).\n\n"
            f"Reason: {spam_result.get('reason', 'N/A')}",
        )
        return _build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            verdict=Verdict.FAILED,
            reason=f"Spam: {spam_result.get('reason', '')}",
        )

    # ── 3. Policy engine (.sentinel.yaml) ───────────────────────────────
    sentinel_config = _fetch_sentinel_config(repo)
    policy_violations = _check_policies(sentinel_config, changed_files, pr)

    if policy_violations:
        detail = "\n".join(
            f"- **{v['rule']}**: {v['detail']}" for v in policy_violations
        )
        _apply_verdict(
            pr, repo, Verdict.SOFT_FAIL,
            f"⚠️ **Policy violations detected:**\n\n{detail}",
        )
        return _build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            verdict=Verdict.SOFT_FAIL,
            reason="Policy violations",
            policy_violations=policy_violations,
        )

    # ── 4. Effort analysis (regex parser) ───────────────────────────────
    diff_text = _get_pr_diff(pr)
    analysis = analyzer.analyze(diff_text)

    if analysis.is_low_effort and not analysis.is_docs_only:
        _apply_verdict(
            pr, repo, Verdict.FAILED,
            f"📉 **Low-effort PR detected.**\n\n"
            f"Signal-to-Noise ratio: {analysis.signal_to_noise_ratio:.1%} "
            f"(minimum {settings.effort_snr_threshold:.0%}).\n\n"
            f"Logic lines: {analysis.logic_lines} | "
            f"Noise lines: {analysis.noise_lines} | "
            f"Total added: {analysis.total_added}",
        )
        return _build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            effort_score=analysis.signal_to_noise_ratio,
            snr=analysis.signal_to_noise_ratio,
            verdict=Verdict.FAILED,
            reason="Low effort (SNR below threshold)",
        )

    # ── 5. Issue alignment (Groq) ───────────────────────────────────────
    issue_number = _extract_issue_number(pr.body)
    if issue_number:
        try:
            issue = repo.get_issue(issue_number)
            alignment = groq.check_issue_alignment(
                pr.body or "", issue.body or "", issue.title,
            )
            if not alignment.get("aligned", True):
                _apply_verdict(
                    pr, repo, Verdict.SOFT_FAIL,
                    f"🔗 **Issue alignment concern** (score "
                    f"{alignment.get('score', 0):.0%}).\n\n"
                    f"{alignment.get('explanation', '')}",
                )
                return _build_result(
                    repo_full_name, pr_number, pr, author,
                    account_age_days, spam_score,
                    effort_score=analysis.signal_to_noise_ratio,
                    snr=analysis.signal_to_noise_ratio,
                    verdict=Verdict.SOFT_FAIL,
                    reason=f"Issue #{issue_number} alignment concern",
                )
        except Exception:
            logger.warning("Could not fetch issue #%s", issue_number)

    # ── 6. Verdict: PASS ────────────────────────────────────────────────
    _apply_verdict(
        pr, repo, Verdict.PASSED,
        f"All checks passed.\n\n"
        f"- Spam score: {spam_score:.0%}\n"
        f"- Signal-to-Noise: {analysis.signal_to_noise_ratio:.1%}\n"
        f"- Logic lines: {analysis.logic_lines}\n"
        f"- Policy violations: 0",
    )
    return _build_result(
        repo_full_name, pr_number, pr, author,
        account_age_days, spam_score,
        effort_score=analysis.signal_to_noise_ratio,
        snr=analysis.signal_to_noise_ratio,
        verdict=Verdict.PASSED,
        reason="All checks passed",
    )


# ── Utility helpers ──────────────────────────────────────────────────────────


def _get_pr_diff(pr) -> str:
    """Fetch the raw unified diff for a PR via PyGitHub."""
    parts: list[str] = []
    for f in pr.get_files():
        header = f"diff --git a/{f.filename} b/{f.filename}\n"
        patch = f.patch or ""
        parts.append(header + patch)
    return "\n".join(parts)


def _build_result(
    repo_full_name: str,
    pr_number: int,
    pr,
    author,
    account_age_days: int,
    spam_score: float,
    *,
    effort_score: float = 0.0,
    snr: float = 0.0,
    verdict: Verdict = Verdict.PENDING,
    reason: str = "",
    policy_violations: list[dict] | None = None,
) -> dict[str, Any]:
    """Build a result dict (also used as the Celery task return value)."""
    return {
        "repo_full_name": repo_full_name,
        "pr_number": pr_number,
        "pr_author": author.login,
        "pr_title": pr.title,
        "pr_url": pr.html_url,
        "author_account_age_days": account_age_days,
        "spam_score": spam_score,
        "effort_score": effort_score,
        "signal_to_noise_ratio": snr,
        "verdict": verdict.value,
        "verdict_reason": reason,
        "policy_violations": policy_violations or [],
    }
