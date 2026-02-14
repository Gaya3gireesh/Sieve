"""
Sentinel — Celery worker.

Orchestrates the full PR analysis pipeline:
  1. Fetch PR details (PyGitHub)
  2. Spam filter (Groq)
  3. Policy engine (.sentinel.yaml)
  4. Effort analysis (regex parser)
  5. Intent verification (description vs diff)
  6. Deep code-quality analysis (Groq)
  7. Issue alignment (Groq)
  8. Verdict → label / close / pushback
  9. Persist PRScan record
"""

from __future__ import annotations

import asyncio
import logging
import re
from tempfile import TemporaryDirectory
from datetime import datetime, timezone
from typing import Any

import httpx
import yaml
from celery import Celery
from git import Repo
from github import Auth, Github
from github.GithubException import BadCredentialsException, GithubException
from sqlalchemy import select

from app.config import get_settings
from app.database import _get_session_factory
from app.models import PRScan, Repository, User, Verdict

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
_worker_loop: asyncio.AbstractEventLoop | None = None


def _run_async(coro):
    """Run async code on a stable worker event loop.

    Celery tasks are sync functions; using ``asyncio.run`` per task creates
    a new event loop each time, which breaks asyncpg connections bound to a
    previous loop. Reusing one loop avoids cross-loop DB errors.
    """
    global _worker_loop
    if _worker_loop is None or _worker_loop.is_closed():
        _worker_loop = asyncio.new_event_loop()
    return _worker_loop.run_until_complete(coro)


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


def _github(token: str | None = None) -> Github:
    return Github(auth=Auth.Token(token or settings.github_token))


def _lookup_repo_access_token(repo_full_name: str) -> str | None:
    """Return stored OAuth token for the repository owner, if available."""
    if not settings.supabase_uses_postgres:
        return None
    try:
        return _run_async(_lookup_repo_access_token_async(repo_full_name))
    except Exception:
        logger.exception("Could not resolve repo access token for %s", repo_full_name)
        return None


async def _lookup_repo_access_token_async(repo_full_name: str) -> str | None:
    factory = _get_session_factory()
    async with factory() as session:
        repo_stmt = (
            select(Repository.owner_user_id)
            .where(
                Repository.full_name == repo_full_name,
                Repository.is_active.is_(True),
            )
            .limit(1)
        )
        owner_user_id = await session.scalar(repo_stmt)
        if owner_user_id is None:
            return None

        user_stmt = (
            select(User.access_token_encrypted)
            .where(
                User.id == owner_user_id,
                User.is_active.is_(True),
            )
            .limit(1)
        )
        token = await session.scalar(user_stmt)
        if not token:
            return None
        return str(token)


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
_VAGUE_PHRASES = (
    "improve code quality",
    "minor improvements",
    "small fixes",
    "enhance performance",
    "update codebase",
    "refactor code",
    "general improvements",
)


def _extract_issue_number(body: str | None) -> int | None:
    """Return the first linked issue number from a PR body, or None."""
    if not body:
        return None
    m = _ISSUE_RE.search(body)
    return int(m.group(1)) if m else None


def _is_vague_description(body: str | None) -> bool:
    """Heuristic pushback for low-context PR descriptions."""
    if not body:
        return True

    text = body.strip()
    if len(text) < settings.vague_description_min_chars:
        return True

    lowered = text.lower()
    phrase_hits = sum(1 for phrase in _VAGUE_PHRASES if phrase in lowered)
    has_specific_signal = bool(
        re.search(
            r"(fix(?:es|ed)?\s+#\d+|https?://|`[^`]+`|```|reproduc|expected|actual|steps?)",
            lowered,
        )
    )
    return phrase_hits >= 2 and not has_specific_signal


def _parse_quality_report(quality: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
    """Normalize model quality output to typed values."""
    try:
        quality_score = float(quality.get("quality_score", 1.0))
    except (TypeError, ValueError):
        quality_score = 1.0

    quality_issues_raw = quality.get("issues", [])
    quality_issues = (
        quality_issues_raw if isinstance(quality_issues_raw, list) else []
    )
    return quality_score, quality_issues


def _persist_scan_result(result: dict[str, Any]) -> None:
    """Best-effort persistence of each scan result into Supabase."""
    try:
        _run_async(_persist_scan_result_async(result))
    except Exception:
        logger.exception(
            "Could not persist scan result for %s#%s",
            result.get("repo_full_name"),
            result.get("pr_number"),
        )


async def _persist_scan_result_async(result: dict[str, Any]) -> None:
    if settings.supabase_uses_postgres:
        await _persist_scan_result_postgres(result)
    else:
        await _persist_scan_result_rest(result)


async def _persist_scan_result_postgres(result: dict[str, Any]) -> None:
    factory = _get_session_factory()
    async with factory() as session:
        scan = PRScan(
            repo_full_name=result["repo_full_name"],
            pr_number=result["pr_number"],
            pr_author=result["pr_author"],
            pr_title=result["pr_title"],
            pr_url=result["pr_url"],
            author_account_age_days=result.get("author_account_age_days"),
            spam_score=result.get("spam_score"),
            is_spam=result.get("is_spam"),
            spam_reason=result.get("spam_reason"),
            effort_score=result.get("effort_score"),
            signal_to_noise_ratio=result.get("signal_to_noise_ratio"),
            issue_number=result.get("issue_number"),
            issue_aligned=result.get("issue_aligned"),
            issue_alignment_score=result.get("issue_alignment_score"),
            issue_alignment_reason=result.get("issue_alignment_reason"),
            description_match=result.get("description_match"),
            description_match_score=result.get("description_match_score"),
            description_match_reason=result.get("description_match_reason"),
            quality_score=result.get("quality_score"),
            quality_issues=result.get("quality_issues"),
            verdict=Verdict(result["verdict"]),
            verdict_reason=result.get("verdict_reason"),
            policy_violations=result.get("policy_violations"),
        )
        session.add(scan)
        await session.commit()


async def _persist_scan_result_rest(result: dict[str, Any]) -> None:
    if settings.supabase_key_is_publishable:
        logger.warning(
            "Skipping Supabase REST persistence for %s#%s: "
            "SUPABASE_KEY is publishable (read/limited scope).",
            result.get("repo_full_name"),
            result.get("pr_number"),
        )
        return

    endpoint = f"{settings.supabase_rest_base_url}/rest/v1/pr_scans"
    headers = {
        "apikey": settings.supabase_key,
        "Authorization": f"Bearer {settings.supabase_key}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }
    payload = {
        "repo_full_name": result["repo_full_name"],
        "pr_number": result["pr_number"],
        "pr_author": result["pr_author"],
        "pr_title": result["pr_title"],
        "pr_url": result["pr_url"],
        "author_account_age_days": result.get("author_account_age_days"),
        "spam_score": result.get("spam_score"),
        "is_spam": result.get("is_spam"),
        "spam_reason": result.get("spam_reason"),
        "effort_score": result.get("effort_score"),
        "signal_to_noise_ratio": result.get("signal_to_noise_ratio"),
        "issue_number": result.get("issue_number"),
        "issue_aligned": result.get("issue_aligned"),
        "issue_alignment_score": result.get("issue_alignment_score"),
        "issue_alignment_reason": result.get("issue_alignment_reason"),
        "description_match": result.get("description_match"),
        "description_match_score": result.get("description_match_score"),
        "description_match_reason": result.get("description_match_reason"),
        "quality_score": result.get("quality_score"),
        "quality_issues": result.get("quality_issues") or [],
        "verdict": result["verdict"],
        "verdict_reason": result.get("verdict_reason"),
        "policy_violations": result.get("policy_violations") or [],
    }

    async with httpx.AsyncClient(timeout=settings.supabase_http_timeout_sec) as client:
        resp = await client.post(endpoint, headers=headers, json=payload)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"Supabase REST insert failed ({resp.status_code}): {resp.text[:220]}"
        )


def _finalize(result: dict[str, Any]) -> dict[str, Any]:
    _persist_scan_result(result)
    return result


def _build_early_result(
    payload: dict[str, Any],
    repo_full_name: str,
    pr_number: int,
    *,
    verdict: Verdict,
    reason: str,
) -> dict[str, Any]:
    """Result payload used when GitHub objects are unavailable."""
    pr_data = payload.get("pull_request", {})
    pr_user = pr_data.get("user", {}) if isinstance(pr_data, dict) else {}
    return {
        "repo_full_name": repo_full_name,
        "pr_number": pr_number,
        "pr_author": pr_user.get("login", "unknown"),
        "pr_title": pr_data.get("title", ""),
        "pr_url": pr_data.get("html_url", ""),
        "author_account_age_days": None,
        "spam_score": 0.0,
        "is_spam": None,
        "spam_reason": None,
        "effort_score": 0.0,
        "signal_to_noise_ratio": 0.0,
        "issue_number": None,
        "issue_aligned": None,
        "issue_alignment_score": None,
        "issue_alignment_reason": None,
        "description_match": None,
        "description_match_score": None,
        "description_match_reason": None,
        "quality_score": None,
        "quality_issues": [],
        "verdict": verdict.value,
        "verdict_reason": reason,
        "policy_violations": [],
    }


# ── Helper: apply verdict ───────────────────────────────────────────────────


def _apply_verdict(
    pr,
    repo,
    verdict: Verdict,
    reason: str,
) -> None:
    """Label, comment, or close the PR based on the verdict."""
    if verdict == Verdict.PASSED:
        owner_login = getattr(getattr(repo, "owner", None), "login", None)
        owner_note = (
            f"@{owner_login} this PR is ready for human review."
            if owner_login
            else "Maintainers: this PR is ready for human review."
        )
        pr.add_to_labels("sentinel-verified")
        pr.create_issue_comment(
            f"✅ **Sentinel — Verified**\n\n{reason}\n\n"
            f"This PR has passed automated review.\n\n"
            f"{owner_note}"
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

    repo_access_token = _lookup_repo_access_token(repo_full_name)
    if settings.github_token_is_placeholder and not repo_access_token:
        return _finalize(_build_early_result(
            payload,
            repo_full_name,
            pr_number,
            verdict=Verdict.SOFT_FAIL,
            reason=(
                "GitHub token appears to be a placeholder and no repository "
                "OAuth token was found. Set a real GITHUB_TOKEN or connect "
                "the repository via the UI."
            ),
        ))

    # ── 1. Fetch PR & author info via PyGitHub ──────────────────────────
    github_client = _github(repo_access_token) if repo_access_token else _github()
    try:
        repo = github_client.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        author = pr.user
    except BadCredentialsException:
        if repo_access_token and repo_access_token != settings.github_token:
            logger.warning(
                "Repo token invalid for %s; falling back to GITHUB_TOKEN.",
                repo_full_name,
            )
            try:
                github_client = _github()
                repo = github_client.get_repo(repo_full_name)
                pr = repo.get_pull(pr_number)
                author = pr.user
            except BadCredentialsException:
                logger.error("GitHub authentication failed for %s#%s", repo_full_name, pr_number)
                return _finalize(_build_early_result(
                    payload,
                    repo_full_name,
                    pr_number,
                    verdict=Verdict.SOFT_FAIL,
                    reason=(
                        "GitHub authentication failed (401 Bad credentials). "
                        "Update GITHUB_TOKEN."
                    ),
                ))
            except GithubException as exc:
                logger.error(
                    "GitHub API error while loading %s#%s after fallback: %s",
                    repo_full_name,
                    pr_number,
                    exc,
                )
                return _finalize(_build_early_result(
                    payload,
                    repo_full_name,
                    pr_number,
                    verdict=Verdict.SOFT_FAIL,
                    reason=f"GitHub API error before analysis: {exc}",
                ))
        else:
            logger.error("GitHub authentication failed for %s#%s", repo_full_name, pr_number)
            return _finalize(_build_early_result(
                payload,
                repo_full_name,
                pr_number,
                verdict=Verdict.SOFT_FAIL,
                reason=(
                    "GitHub authentication failed (401 Bad credentials). "
                    "Update GITHUB_TOKEN."
                ),
            ))
    except GithubException as exc:
        logger.error(
            "GitHub API error while loading %s#%s: %s",
            repo_full_name,
            pr_number,
            exc,
        )
        return _finalize(_build_early_result(
            payload,
            repo_full_name,
            pr_number,
            verdict=Verdict.SOFT_FAIL,
            reason=f"GitHub API error before analysis: {exc}",
        ))

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
    is_spam = bool(spam_result.get("is_spam", False))
    spam_reason = str(spam_result.get("reason", "")).strip() or None

    issue_number: int | None = _extract_issue_number(pr.body)
    issue_aligned: bool | None = None
    issue_alignment_score: float | None = None
    issue_alignment_reason: str | None = None
    description_match: bool | None = None
    description_match_score: float | None = None
    description_match_reason: str | None = None

    if is_spam and spam_score >= settings.spam_threshold:
        _apply_verdict(
            pr, repo, Verdict.FAILED,
            f"🚫 **Spam detected** (confidence {spam_score:.0%}).\n\n"
            f"Reason: {spam_reason or 'N/A'}",
        )
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            issue_number=issue_number,
            verdict=Verdict.FAILED,
            reason=f"Spam: {spam_reason or ''}",
        ))

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
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            issue_number=issue_number,
            verdict=Verdict.SOFT_FAIL,
            reason="Policy violations",
            policy_violations=policy_violations,
        ))

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
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            effort_score=analysis.signal_to_noise_ratio,
            snr=analysis.signal_to_noise_ratio,
            issue_number=issue_number,
            verdict=Verdict.FAILED,
            reason="Low effort (SNR below threshold)",
        ))

    # ── 5. Vague description challenge (PushbackBot) ───────────────────
    if _is_vague_description(pr.body):
        _apply_verdict(
            pr, repo, Verdict.SOFT_FAIL,
            "📝 **PR description is too vague.**\n\n"
            "Please explain what changed, why it changed, and how it was validated.",
        )
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            effort_score=analysis.signal_to_noise_ratio,
            snr=analysis.signal_to_noise_ratio,
            issue_number=issue_number,
            verdict=Verdict.SOFT_FAIL,
            reason="Vague PR description",
        ))

    # ── 6. Intent verification (description vs diff) ────────────────────
    try:
        intent = groq.check_intent_match(pr.title, pr.body or "", diff_text)
        if isinstance(intent.get("matches"), bool):
            description_match = bool(intent.get("matches"))
        if intent.get("score") is not None:
            description_match_score = float(intent.get("score"))
        description_match_reason = str(intent.get("explanation", "")).strip() or None
    except Exception:
        logger.exception("Intent verification failed; continuing with other checks")

    if description_match is False:
        _apply_verdict(
            pr, repo, Verdict.SOFT_FAIL,
            f"🧭 **Intent mismatch detected** (score "
            f"{(description_match_score or 0):.0%}).\n\n"
            f"{description_match_reason or 'PR description does not match code changes.'}",
        )
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            effort_score=analysis.signal_to_noise_ratio,
            snr=analysis.signal_to_noise_ratio,
            issue_number=issue_number,
            description_match=description_match,
            description_match_score=description_match_score,
            description_match_reason=description_match_reason,
            verdict=Verdict.SOFT_FAIL,
            reason="Description does not match code diff",
        ))

    # ── 7. Deep code-quality analysis (Groq) ────────────────────────────
    quality_score = 1.0
    quality_issues: list[dict[str, Any]] = []
    quality_summary = ""
    try:
        quality_report = groq.analyze_code_quality(diff_text)
        quality_score, quality_issues = _parse_quality_report(quality_report)
        quality_summary = str(quality_report.get("summary", "")).strip()
    except Exception:
        logger.exception("Deep quality analysis failed; continuing with other checks")

    high_severity_issues = [
        issue for issue in quality_issues
        if str(issue.get("severity", "")).lower() == "high"
    ]
    if high_severity_issues or quality_score < settings.quality_fail_threshold:
        _apply_verdict(
            pr, repo, Verdict.FAILED,
            f"🛑 **Code-quality gate failed**.\n\n"
            f"Quality score: {quality_score:.2f} "
            f"(minimum {settings.quality_fail_threshold:.2f}).\n"
            f"High severity issues: {len(high_severity_issues)}.\n\n"
            f"{quality_summary}",
        )
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            effort_score=analysis.signal_to_noise_ratio,
            snr=analysis.signal_to_noise_ratio,
            issue_number=issue_number,
            description_match=description_match,
            description_match_score=description_match_score,
            description_match_reason=description_match_reason,
            quality_score=quality_score,
            quality_issues=quality_issues,
            verdict=Verdict.FAILED,
            reason="Deep quality gate failed",
        ))

    if quality_score < settings.quality_soft_fail_threshold:
        _apply_verdict(
            pr, repo, Verdict.SOFT_FAIL,
            f"⚠️ **Code-quality concerns detected**.\n\n"
            f"Quality score: {quality_score:.2f} "
            f"(minimum for auto-pass {settings.quality_soft_fail_threshold:.2f}).\n\n"
            f"{quality_summary}",
        )
        return _finalize(_build_result(
            repo_full_name, pr_number, pr, author,
            account_age_days, spam_score,
            is_spam=is_spam,
            spam_reason=spam_reason,
            effort_score=analysis.signal_to_noise_ratio,
            snr=analysis.signal_to_noise_ratio,
            issue_number=issue_number,
            description_match=description_match,
            description_match_score=description_match_score,
            description_match_reason=description_match_reason,
            quality_score=quality_score,
            quality_issues=quality_issues,
            verdict=Verdict.SOFT_FAIL,
            reason="Deep quality soft-fail",
        ))

    # ── 8. Issue alignment (Groq) ───────────────────────────────────────
    if issue_number:
        try:
            issue = repo.get_issue(issue_number)
            alignment = groq.check_issue_alignment(
                pr.body or "",
                issue.body or "",
                issue.title,
                diff_text,
            )
            if isinstance(alignment.get("aligned"), bool):
                issue_aligned = bool(alignment.get("aligned"))
            if alignment.get("score") is not None:
                issue_alignment_score = float(alignment.get("score"))
            issue_alignment_reason = (
                str(alignment.get("explanation", "")).strip() or None
            )

            if issue_aligned is False:
                _apply_verdict(
                    pr, repo, Verdict.SOFT_FAIL,
                    f"🔗 **Issue alignment concern** (score "
                    f"{(issue_alignment_score or 0):.0%}).\n\n"
                    f"{issue_alignment_reason or ''}",
                )
                return _finalize(_build_result(
                    repo_full_name, pr_number, pr, author,
                    account_age_days, spam_score,
                    is_spam=is_spam,
                    spam_reason=spam_reason,
                    effort_score=analysis.signal_to_noise_ratio,
                    snr=analysis.signal_to_noise_ratio,
                    issue_number=issue_number,
                    issue_aligned=issue_aligned,
                    issue_alignment_score=issue_alignment_score,
                    issue_alignment_reason=issue_alignment_reason,
                    description_match=description_match,
                    description_match_score=description_match_score,
                    description_match_reason=description_match_reason,
                    quality_score=quality_score,
                    quality_issues=quality_issues,
                    verdict=Verdict.SOFT_FAIL,
                    reason=f"Issue #{issue_number} alignment concern",
                ))
        except Exception:
            logger.warning("Could not fetch issue #%s", issue_number)

    # ── 9. Verdict: PASS ────────────────────────────────────────────────
    _apply_verdict(
        pr, repo, Verdict.PASSED,
        f"All checks passed.\n\n"
        f"- Spam score: {spam_score:.0%}\n"
        f"- Signal-to-Noise: {analysis.signal_to_noise_ratio:.1%}\n"
        f"- Quality score: {quality_score:.2f}\n"
        f"- Logic lines: {analysis.logic_lines}\n"
        f"- Policy violations: 0",
    )
    return _finalize(_build_result(
        repo_full_name, pr_number, pr, author,
        account_age_days, spam_score,
        is_spam=is_spam,
        spam_reason=spam_reason,
        effort_score=analysis.signal_to_noise_ratio,
        snr=analysis.signal_to_noise_ratio,
        issue_number=issue_number,
        issue_aligned=issue_aligned,
        issue_alignment_score=issue_alignment_score,
        issue_alignment_reason=issue_alignment_reason,
        description_match=description_match,
        description_match_score=description_match_score,
        description_match_reason=description_match_reason,
        quality_score=quality_score,
        quality_issues=quality_issues,
        verdict=Verdict.PASSED,
        reason="All checks passed",
    ))


# ── Utility helpers ──────────────────────────────────────────────────────────


def _get_pr_diff(pr) -> str:
    """Fetch raw unified diff via GitPython, with API fallback."""
    try:
        base_repo = pr.base.repo
        head_repo = pr.head.repo
        base_sha = pr.base.sha
        head_sha = pr.head.sha

        with TemporaryDirectory(prefix="sentinel-pr-") as tmpdir:
            repo = Repo.clone_from(
                _auth_clone_url(base_repo.clone_url),
                tmpdir,
                no_checkout=True,
                depth=1,
                multi_options=["--filter=blob:none"],
            )
            repo.git.fetch("origin", base_sha, "--depth=1")

            head_remote = "origin"
            if head_repo and head_repo.full_name != base_repo.full_name:
                repo.create_remote(
                    "headremote",
                    _auth_clone_url(head_repo.clone_url),
                )
                head_remote = "headremote"
            repo.git.fetch(head_remote, head_sha, "--depth=1")

            return repo.git.diff(base_sha, head_sha, unified=3)
    except Exception as exc:
        logger.warning("GitPython raw diff failed, using patch fallback: %s", exc)

    parts: list[str] = []
    for f in pr.get_files():
        header = f"diff --git a/{f.filename} b/{f.filename}\n"
        patch = f.patch or ""
        parts.append(header + patch)
    return "\n".join(parts)


def _auth_clone_url(url: str) -> str:
    """Inject GitHub token into HTTPS clone URLs for authenticated fetches."""
    if not url.startswith("https://"):
        return url
    return url.replace(
        "https://",
        f"https://x-access-token:{settings.github_token}@",
        1,
    )


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
    is_spam: bool | None = None,
    spam_reason: str | None = None,
    issue_number: int | None = None,
    issue_aligned: bool | None = None,
    issue_alignment_score: float | None = None,
    issue_alignment_reason: str | None = None,
    description_match: bool | None = None,
    description_match_score: float | None = None,
    description_match_reason: str | None = None,
    quality_score: float | None = None,
    quality_issues: list[dict[str, Any]] | None = None,
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
        "is_spam": is_spam,
        "spam_reason": spam_reason,
        "effort_score": effort_score,
        "signal_to_noise_ratio": snr,
        "issue_number": issue_number,
        "issue_aligned": issue_aligned,
        "issue_alignment_score": issue_alignment_score,
        "issue_alignment_reason": issue_alignment_reason,
        "description_match": description_match,
        "description_match_score": description_match_score,
        "description_match_reason": description_match_reason,
        "quality_score": quality_score,
        "quality_issues": quality_issues or [],
        "verdict": verdict.value,
        "verdict_reason": reason,
        "policy_violations": policy_violations or [],
    }
