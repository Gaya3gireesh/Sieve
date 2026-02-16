"""
Sentinel — FastAPI entry point.

Handles GitHub webhooks and exposes a health-check endpoint.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import multiprocessing
import secrets
from contextlib import asynccontextmanager
from html import escape
from typing import Any
from urllib.parse import urlencode, urlparse, urljoin

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.database import _get_session_factory
from app.models import PRScan, Repository, User, Verdict

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
settings = get_settings()

# ── Lifespan ────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    if settings.github_token_is_placeholder:
        logger.warning(
            "GITHUB_TOKEN looks like a placeholder. "
            "Worker will rely on per-repository OAuth tokens from UI connections."
        )
    logger.info(
        "Supabase mode: %s",
        "postgres" if settings.supabase_uses_postgres else "rest",
    )
    logger.info(
        "Processing mode: %s",
        "celery-worker" if settings.use_celery_worker else "inline",
    )
    logger.info("Sentinel is online 🛡️")
    yield
    logger.info("Sentinel shutting down")


# ── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Sentinel",
    description="The Open Source Gatekeeper — intelligent PR filtering.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.ui_session_secret,
    same_site="lax",
    https_only=settings.public_base_url.startswith("https://"),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list({
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        settings.frontend_url.rstrip("/"),
        settings.public_base_url.rstrip("/"),
    }),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Lazy worker import ──────────────────────────────────────────────────────


def _process_pr_inline(payload: dict[str, Any], task_id: str) -> None:
    """Run PR pipeline in-process (no separate Celery worker required)."""
    from app.worker import process_pr

    try:
        process_pr.run(payload)
        logger.info(
            "Inline processed PR %s#%s → task %s",
            payload.get("repository", {}).get("full_name", "?"),
            payload.get("pull_request", {}).get("number", "?"),
            task_id,
        )
    except Exception:
        logger.exception("Inline PR processing failed for task %s", task_id)


def _spawn_inline_pr_process(payload: dict[str, Any], task_id: str) -> None:
    """Run one PR scan in a separate process to isolate async DB loops."""
    proc = multiprocessing.Process(
        target=_process_pr_inline,
        args=(payload, task_id),
        daemon=True,
    )
    proc.start()


def _enqueue_pr(payload: dict[str, Any]) -> str:
    """Enqueue PR processing using Celery or inline background mode."""
    if settings.use_celery_worker:
        from app.worker import process_pr

        task = process_pr.delay(payload)
        return task.id

    task_id = secrets.token_urlsafe(12)
    _spawn_inline_pr_process(payload, task_id)
    return task_id


# ── Signature verification ──────────────────────────────────────────────────


async def _repository_webhook_secret_from_payload(payload: dict[str, Any]) -> str | None:
    """Resolve per-repository webhook secret from DB using payload metadata."""
    repo_raw = payload.get("repository")
    if not isinstance(repo_raw, dict):
        return None

    repo_id = _coerce_int(repo_raw.get("id"))
    full_name = str(repo_raw.get("full_name") or "").strip()
    if repo_id is None and not full_name:
        return None
    if not settings.supabase_uses_postgres:
        return None

    factory = _get_session_factory()
    async with factory() as session:
        row = None
        if repo_id is not None:
            row = (
                await session.execute(
                    select(Repository).where(Repository.github_repo_id == repo_id)
                )
            ).scalar_one_or_none()
        if row is None and full_name:
            row = (
                await session.execute(
                    select(Repository).where(Repository.full_name == full_name)
                )
            ).scalar_one_or_none()
        if row is None:
            return None

        secret = str(row.webhook_secret_encrypted or "").strip()
        return secret or None


async def _verify_signature(
    payload_body: bytes,
    signature: str | None,
    payload: dict[str, Any],
) -> None:
    """Verify webhook signature using repository secret first, then global fallback."""
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-Hub-Signature-256 header.",
        )

    candidates: list[str] = []
    repo_secret = await _repository_webhook_secret_from_payload(payload)
    if repo_secret:
        candidates.append(repo_secret)
    if settings.github_webhook_secret_configured:
        candidates.append(settings.github_webhook_secret.strip())

    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "No webhook secret configured for this repository. "
                "Authorize the repository from UI first."
            ),
        )

    for candidate in candidates:
        expected = "sha256=" + hmac.new(
            candidate.encode(),
            payload_body,
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected, signature):
            return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid webhook signature.",
    )


def _coerce_int(value: Any) -> int | None:
    """Safely parse integer-like values from webhook payloads."""
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_repository_rows(raw: Any) -> list[tuple[int, str]]:
    """Return deduplicated (repo_id, full_name) pairs from payload lists."""
    if not isinstance(raw, list):
        return []

    repos: dict[int, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        repo_id = _coerce_int(item.get("id"))
        full_name = str(item.get("full_name") or "").strip()
        if repo_id is None or not full_name:
            continue
        repos[repo_id] = full_name
    return list(repos.items())


def _extract_repository_ids(raw: Any) -> list[int]:
    """Return deduplicated repository IDs from payload lists."""
    if not isinstance(raw, list):
        return []

    repo_ids: set[int] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        repo_id = _coerce_int(item.get("id"))
        if repo_id is None:
            continue
        repo_ids.add(repo_id)
    return list(repo_ids)


async def _upsert_repositories(
    db: AsyncSession,
    *,
    installation_id: int,
    repositories: list[tuple[int, str]],
) -> tuple[int, int]:
    """Create missing repository rows and reactivate/update existing ones."""
    if not repositories:
        return 0, 0

    repo_ids = [repo_id for repo_id, _ in repositories]
    result = await db.execute(
        select(Repository).where(Repository.github_repo_id.in_(repo_ids))
    )
    existing = {repo.github_repo_id: repo for repo in result.scalars().all()}

    created = 0
    updated = 0
    for repo_id, full_name in repositories:
        row = existing.get(repo_id)
        if row:
            row.full_name = full_name
            row.installation_id = installation_id
            row.is_active = True
            updated += 1
            continue

        db.add(
            Repository(
                github_repo_id=repo_id,
                full_name=full_name,
                installation_id=installation_id,
                is_active=True,
            )
        )
        created += 1

    return created, updated


async def _set_repositories_active_for_installation(
    db: AsyncSession,
    *,
    installation_id: int,
    is_active: bool,
) -> int:
    """Toggle active status for all repositories linked to an installation."""
    result = await db.execute(
        select(Repository).where(Repository.installation_id == installation_id)
    )
    rows = result.scalars().all()
    for row in rows:
        row.is_active = is_active
    return len(rows)


async def _deactivate_repositories_by_id(
    db: AsyncSession,
    *,
    repo_ids: list[int],
) -> int:
    """Deactivate repositories matching the provided GitHub repository IDs."""
    if not repo_ids:
        return 0

    result = await db.execute(
        select(Repository).where(Repository.github_repo_id.in_(repo_ids))
    )
    rows = result.scalars().all()
    for row in rows:
        row.is_active = False
    return len(rows)


@asynccontextmanager
async def _installation_db_session():
    """Yield a transactional session for installation webhook operations."""
    if not settings.supabase_uses_postgres:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "installation events require PostgreSQL DSN mode for SQLAlchemy "
                "(SUPABASE_URL must be a postgres URL)."
            ),
        )

    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def _dashboard_db_session():
    """Yield a transactional session for dashboard API operations."""
    if not settings.supabase_uses_postgres:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "dashboard APIs require PostgreSQL DSN mode for SQLAlchemy "
                "(SUPABASE_URL must be a postgres URL)."
            ),
        )

    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def _active_oauth_user_count() -> int:
    """Count active users with stored GitHub OAuth tokens."""
    if not settings.supabase_uses_postgres:
        return 0
    try:
        async with _dashboard_db_session() as db:
            stmt = select(func.count(User.id)).where(
                User.is_active.is_(True),
                User.access_token_encrypted.is_not(None),
                User.access_token_encrypted != "",
            )
            return int((await db.scalar(stmt)) or 0)
    except Exception:
        logger.exception("Could not count active OAuth users.")
        return 0


def _scan_bucket(verdict: Verdict | str) -> str:
    """Map PR verdicts to dashboard tabs."""
    value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    if value == Verdict.PENDING.value:
        return "queue"
    if value == Verdict.PASSED.value:
        return "reviewed"
    return "spam_closed"


def _scan_auto_closed(verdict: Verdict | str) -> bool:
    """Whether verdict results in auto-close behavior."""
    value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    return value == Verdict.FAILED.value


def _scan_to_response(scan: PRScan) -> dict[str, Any]:
    """Normalize PRScan row for dashboard API responses."""
    return {
        "id": str(scan.id),
        "repo_full_name": scan.repo_full_name,
        "pr_number": scan.pr_number,
        "pr_title": scan.pr_title,
        "pr_author": scan.pr_author,
        "pr_url": scan.pr_url,
        "verdict": scan.verdict.value if isinstance(scan.verdict, Verdict) else scan.verdict,
        "bucket": _scan_bucket(scan.verdict),
        "auto_closed": _scan_auto_closed(scan.verdict),
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
        "analysis": {
            "author_account_age_days": scan.author_account_age_days,
            "spam_score": scan.spam_score,
            "is_spam": scan.is_spam,
            "spam_reason": scan.spam_reason,
            "effort_score": scan.effort_score,
            "signal_to_noise_ratio": scan.signal_to_noise_ratio,
            "issue_number": scan.issue_number,
            "issue_aligned": scan.issue_aligned,
            "issue_alignment_score": scan.issue_alignment_score,
            "issue_alignment_reason": scan.issue_alignment_reason,
            "description_match": scan.description_match,
            "description_match_score": scan.description_match_score,
            "description_match_reason": scan.description_match_reason,
            "quality_score": scan.quality_score,
            "quality_issues": scan.quality_issues or [],
            "policy_violations": scan.policy_violations or [],
            "verdict_reason": scan.verdict_reason,
        },
    }


# ── UI + GitHub OAuth helpers ───────────────────────────────────────────────

_GITHUB_OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_GITHUB_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_API_BASE = "https://api.github.com"
_DEV_DEFAULT_PUBLIC_BASE_URL = "http://127.0.0.1:8000"


def _set_flash(request: Request, level: str, message: str) -> None:
    request.session["ui_flash"] = {"level": level, "message": message}


def _pop_flash(request: Request) -> tuple[str | None, str | None]:
    value = request.session.pop("ui_flash", None)
    if not isinstance(value, dict):
        return None, None
    return value.get("level"), value.get("message")


def _effective_public_base_url(request: Request | None = None) -> str:
    """Resolve base URL used for OAuth redirect + webhook target.

    If PUBLIC_BASE_URL remains the default dev value, use the current request
    host/port so local runs on non-8000 ports keep working.
    """
    configured = settings.public_base_url.strip().rstrip("/")
    if request is not None and (
        not configured or configured == _DEV_DEFAULT_PUBLIC_BASE_URL
    ):
        return str(request.base_url).rstrip("/")
    return configured or _DEV_DEFAULT_PUBLIC_BASE_URL


def _github_oauth_redirect_uri(request: Request | None = None) -> str:
    return f"{_effective_public_base_url(request)}/auth/github/callback"


def _webhook_target_url(public_base_url: str) -> str:
    return f"{public_base_url.rstrip('/')}/webhook"


def _is_public_https_base_url(public_base_url: str) -> bool:
    """Whether GitHub can realistically reach this webhook base URL."""
    parsed = urlparse(public_base_url)
    if parsed.scheme != "https":
        return False
    host = parsed.hostname
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


async def _github_exchange_oauth_code(code: str) -> str:
    payload = {
        "client_id": settings.github_oauth_client_id,
        "client_secret": settings.github_oauth_client_secret,
        "code": code,
    }
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(timeout=12) as client:
        resp = await client.post(_GITHUB_OAUTH_TOKEN_URL, data=payload, headers=headers)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAuth token exchange failed ({resp.status_code}).")
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(
            f"OAuth error: {data.get('error_description') or data.get('error')}"
        )
    token = data.get("access_token")
    if not token:
        raise RuntimeError("GitHub OAuth returned no access token.")
    return str(token)


async def _github_get_authenticated_user(token: str) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=12) as client:
        resp = await client.get(f"{_GITHUB_API_BASE}/user", headers=headers)
    if resp.status_code >= 400:
        raise RuntimeError(f"GitHub user lookup failed ({resp.status_code}).")
    return resp.json()


async def _github_list_repositories(token: str) -> list[dict[str, Any]]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "per_page": 100,
        "sort": "updated",
        "direction": "desc",
        "affiliation": "owner,collaborator,organization_member",
    }
    async with httpx.AsyncClient(timeout=12) as client:
        resp = await client.get(f"{_GITHUB_API_BASE}/user/repos", headers=headers, params=params)
    if resp.status_code >= 400:
        raise RuntimeError(f"GitHub repository list failed ({resp.status_code}).")
    repos = resp.json()
    if not isinstance(repos, list):
        return []
    normalized: list[dict[str, Any]] = []
    for repo in repos:
        normalized.append(
            {
                "id": repo.get("id"),
                "full_name": repo.get("full_name", ""),
                "private": bool(repo.get("private", False)),
                "admin": bool(repo.get("permissions", {}).get("admin", False)),
            }
        )
    return normalized


async def _github_get_repository(token: str, repo_full_name: str) -> dict[str, Any]:
    """Fetch one repository by full name for id/visibility metadata."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=12) as client:
        resp = await client.get(f"{_GITHUB_API_BASE}/repos/{repo_full_name}", headers=headers)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"GitHub repository lookup failed for {repo_full_name} "
            f"({resp.status_code})."
        )
    repo = resp.json()
    return {
        "id": repo.get("id"),
        "full_name": repo.get("full_name", repo_full_name),
        "private": bool(repo.get("private", False)),
        "admin": bool(repo.get("permissions", {}).get("admin", False)),
    }


def _build_pull_request_event_payload(
    repo_full_name: str,
    pull_request: dict[str, Any],
) -> dict[str, Any] | None:
    """Build a minimal pull_request webhook-like payload for queue ingestion."""
    pr_number = _coerce_int(pull_request.get("number"))
    if pr_number is None:
        return None

    user = pull_request.get("user") if isinstance(pull_request.get("user"), dict) else {}
    return {
        "action": "opened",
        "repository": {"full_name": repo_full_name},
        "pull_request": {
            "number": pr_number,
            "title": str(pull_request.get("title") or ""),
            "body": str(pull_request.get("body") or ""),
            "html_url": str(pull_request.get("html_url") or ""),
            "user": {
                "login": str(user.get("login") or "unknown"),
                "created_at": str(user.get("created_at") or ""),
            },
        },
    }


async def _github_list_open_pull_requests(
    token: str,
    repo_full_name: str,
    *,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """List open PRs for one repository using the OAuth session token."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "state": "open",
        "sort": "updated",
        "direction": "desc",
        "per_page": max(1, min(limit, 100)),
    }
    async with httpx.AsyncClient(timeout=12) as client:
        resp = await client.get(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/pulls",
            headers=headers,
            params=params,
        )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"Could not list open PRs for {repo_full_name} ({resp.status_code})."
        )
    rows = resp.json()
    if not isinstance(rows, list):
        return []
    return rows


async def _ensure_repo_webhook(
    token: str,
    repo_full_name: str,
    *,
    webhook_target: str,
    webhook_secret: str,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    hook_config = {
        "url": webhook_target,
        "content_type": "json",
        "secret": webhook_secret,
        "insecure_ssl": "0",
    }
    hook_payload = {"name": "web", "active": True, "events": ["pull_request"], "config": hook_config}

    async with httpx.AsyncClient(timeout=12) as client:
        hooks_resp = await client.get(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/hooks",
            headers=headers,
        )
        if hooks_resp.status_code >= 400:
            raise RuntimeError(
                f"Could not read repo hooks ({hooks_resp.status_code}). "
                f"Check repository access."
            )
        hooks = hooks_resp.json()
        existing = None
        if isinstance(hooks, list):
            for hook in hooks:
                if hook.get("config", {}).get("url") == webhook_target:
                    existing = hook
                    break

        if existing:
            hook_id = existing.get("id")
            if hook_id:
                patch_resp = await client.patch(
                    f"{_GITHUB_API_BASE}/repos/{repo_full_name}/hooks/{hook_id}",
                    headers=headers,
                    json={"active": True, "events": ["pull_request"], "config": hook_config},
                )
                if patch_resp.status_code >= 400:
                    raise RuntimeError(
                        f"Webhook update failed ({patch_resp.status_code})."
                    )
                body = patch_resp.json()
                hook_id = _coerce_int(body.get("id")) or _coerce_int(hook_id)
                return {
                    "repo_full_name": repo_full_name,
                    "hook_id": hook_id,
                    "webhook_secret": webhook_secret,
                    "message": f"Repository {repo_full_name} is now authorized (webhook updated).",
                }
            return {
                "repo_full_name": repo_full_name,
                "hook_id": None,
                "webhook_secret": webhook_secret,
                "message": f"Repository {repo_full_name} is already authorized.",
            }

        create_resp = await client.post(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/hooks",
            headers=headers,
            json=hook_payload,
        )
        if create_resp.status_code >= 400:
            raise RuntimeError(
                f"Webhook creation failed ({create_resp.status_code}): {create_resp.text[:180]}"
            )
        created = create_resp.json()
    return {
        "repo_full_name": repo_full_name,
        "hook_id": _coerce_int(created.get("id")),
        "webhook_secret": webhook_secret,
        "message": f"Repository {repo_full_name} is now authorized.",
    }


async def _ensure_repo_webhooks(
    token: str,
    repo_full_names: list[str],
    *,
    webhook_target: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Create/update Sentinel webhook for multiple repositories."""
    unique_repo_names = list(dict.fromkeys(name.strip() for name in repo_full_names if name.strip()))
    if not unique_repo_names:
        return [], []

    tasks = []
    for repo_name in unique_repo_names:
        repo_secret = secrets.token_urlsafe(48)
        tasks.append(
            _ensure_repo_webhook(
                token,
                repo_name,
                webhook_target=webhook_target,
                webhook_secret=repo_secret,
            )
        )
    results = await asyncio.gather(*tasks, return_exceptions=True)

    succeeded: list[dict[str, Any]] = []
    failed: list[str] = []
    for repo_name, result in zip(unique_repo_names, results):
        if isinstance(result, Exception):
            failed.append(f"{repo_name}: {result}")
            continue
        succeeded.append(result)
    return succeeded, failed


async def _existing_pending_pr_numbers(
    db: AsyncSession,
    *,
    repo_full_name: str,
    pr_numbers: list[int],
) -> set[int]:
    """Return PR numbers that already exist in pending state for one repo."""
    if not pr_numbers:
        return set()
    result = await db.execute(
        select(PRScan.pr_number).where(
            PRScan.repo_full_name == repo_full_name,
            PRScan.pr_number.in_(pr_numbers),
            PRScan.verdict == Verdict.PENDING,
        )
    )
    return {int(value) for value in result.scalars().all() if value is not None}


async def _sync_open_prs_for_repositories(
    token: str,
    repo_full_names: list[str],
) -> tuple[int, int, int, list[str]]:
    """Fetch open PRs for repositories and enqueue missing scans."""
    unique_repo_names = list(dict.fromkeys(name.strip() for name in repo_full_names if name.strip()))
    if not unique_repo_names:
        return 0, 0, 0, []

    fetched = 0
    queued = 0
    skipped = 0
    failures: list[str] = []

    for repo_name in unique_repo_names:
        try:
            open_prs = await _github_list_open_pull_requests(token, repo_name, limit=25)
        except Exception as exc:
            failures.append(f"{repo_name}: {exc}")
            continue

        fetched += len(open_prs)
        numbers = [
            number
            for number in (_coerce_int(pr.get("number")) for pr in open_prs)
            if number is not None
        ]
        pending_numbers: set[int] = set()
        if settings.supabase_uses_postgres and numbers:
            try:
                async with _dashboard_db_session() as db:
                    pending_numbers = await _existing_pending_pr_numbers(
                        db,
                        repo_full_name=repo_name,
                        pr_numbers=numbers,
                    )
            except Exception as exc:
                failures.append(f"{repo_name}: pending-check failed ({exc})")

        for pr in open_prs:
            number = _coerce_int(pr.get("number"))
            if number is None:
                continue
            if number in pending_numbers:
                skipped += 1
                continue

            payload = _build_pull_request_event_payload(repo_name, pr)
            if payload is None:
                continue
            try:
                _enqueue_pr(payload)
                queued += 1
            except Exception as exc:
                failures.append(f"{repo_name}#{number}: enqueue failed ({exc})")

    return fetched, queued, skipped, failures


def _parse_repo_names(raw: str) -> list[str]:
    """Parse comma/newline-separated repository names in owner/repo format."""
    if not raw:
        return []
    normalized: list[str] = []
    for token in raw.replace(",", "\n").splitlines():
        name = token.strip()
        if not name or "/" not in name:
            continue
        normalized.append(name)
    return list(dict.fromkeys(normalized))


def _normalize_repo_names(raw: str | list[str]) -> list[str]:
    """Normalize repo names from textarea/list payloads."""
    if isinstance(raw, str):
        return _parse_repo_names(raw)

    normalized: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            continue
        normalized.extend(_parse_repo_names(value))
    return list(dict.fromkeys(normalized))


def _safe_next_redirect_url(value: str | None) -> str | None:
    """Allow same-origin relative paths and external HTTPS URLs."""
    if not value:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None

    if candidate.startswith("/") and not candidate.startswith("//"):
        return candidate

    parsed = urlparse(candidate)
    if parsed.scheme == "https" and parsed.hostname:
        return candidate
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}:
        return candidate
    return None


def _is_external_redirect(next_url: str | None, request: Request | None = None) -> bool:
    """True when next_url points to a different origin than the backend."""
    if not next_url or next_url.startswith("/"):
        return False
    parsed = urlparse(next_url)
    if not parsed.hostname:
        return False
    backend_base = _effective_public_base_url(request)
    backend_parsed = urlparse(backend_base)
    return parsed.hostname != backend_parsed.hostname


def _get_oauth_credentials(request: Request) -> tuple[str | None, str | None, str | None]:
    """Get (oauth_token, github_login, sentinel_user_id) from Authorization header OR session.

    When the React frontend is on a different domain (Vercel) the session cookie
    won't be sent.  The frontend stores the token in localStorage and sends it
    as ``Authorization: Bearer <token>``.
    """
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            # We have a bearer token — try to resolve the user from the DB.
            return token, None, None  # login/id resolved lazily when needed
    # Fallback: session cookie (works when frontend is same-domain).
    return (
        request.session.get("github_oauth_token"),
        request.session.get("github_user_login"),
        request.session.get("sentinel_user_id"),
    )


async def _resolve_bearer_user(token: str) -> tuple[str | None, str | None]:
    """Given a raw GitHub OAuth token, return (github_login, sentinel_user_id).

    Looks up the Users table first; falls back to a live GitHub API call.
    """
    if settings.supabase_uses_postgres:
        try:
            factory = _get_session_factory()
            async with factory() as session:
                result = await session.execute(
                    select(User).where(User.access_token_encrypted == token)
                )
                user_row = result.scalar_one_or_none()
                if user_row:
                    return str(user_row.github_login or ""), str(user_row.id)
        except Exception:
            pass
    # Fallback: ask GitHub directly.
    try:
        gh_user = await _github_get_authenticated_user(token)
        return str(gh_user.get("login", "")), None
    except Exception:
        return None, None


class AuthorizeReposApiPayload(BaseModel):
    repo_full_names: str | list[str]
    sync_open_prs: bool = True


async def _upsert_oauth_user(
    db: AsyncSession,
    *,
    github_user: dict[str, Any],
    oauth_token: str,
) -> int | None:
    """Persist GitHub OAuth user to support multi-user repository ownership."""
    github_user_id = _coerce_int(github_user.get("id"))
    github_login = str(github_user.get("login") or "").strip()
    if github_user_id is None or not github_login:
        return None

    result = await db.execute(
        select(User).where(User.github_user_id == github_user_id)
    )
    row = result.scalar_one_or_none()
    if row:
        row.github_login = github_login
        row.access_token_encrypted = oauth_token
        row.is_active = True
        return int(row.id)

    new_row = User(
        github_user_id=github_user_id,
        github_login=github_login,
        access_token_encrypted=oauth_token,
        is_active=True,
    )
    db.add(new_row)
    await db.flush()
    return int(new_row.id)


async def _link_owner_to_repositories(
    db: AsyncSession,
    *,
    owner_user_id: int,
    repo_full_names: list[str],
) -> int:
    """Attach owner user to repository rows that already exist in DB."""
    if not repo_full_names:
        return 0
    result = await db.execute(
        select(Repository).where(Repository.full_name.in_(repo_full_names))
    )
    rows = result.scalars().all()
    for row in rows:
        row.owner_user_id = owner_user_id
        row.is_active = True
    return len(rows)


async def _upsert_user_repositories(
    db: AsyncSession,
    *,
    owner_user_id: int,
    repositories: list[dict[str, Any]],
) -> tuple[int, int]:
    """Persist repository records for a user from OAuth-selected repo metadata."""
    valid_repositories: list[tuple[int, str]] = []
    for repo in repositories:
        github_repo_id = _coerce_int(repo.get("id"))
        full_name = str(repo.get("full_name") or "").strip()
        if github_repo_id is None or not full_name:
            continue
        valid_repositories.append((github_repo_id, full_name))

    if not valid_repositories:
        return 0, 0

    repo_ids = [repo_id for repo_id, _ in valid_repositories]
    result = await db.execute(
        select(Repository).where(Repository.github_repo_id.in_(repo_ids))
    )
    existing = {row.github_repo_id: row for row in result.scalars().all()}

    created = 0
    updated = 0
    for github_repo_id, full_name in valid_repositories:
        row = existing.get(github_repo_id)
        if row:
            row.full_name = full_name
            row.owner_user_id = owner_user_id
            row.is_active = True
            if row.installation_id is None:
                row.installation_id = 0
            updated += 1
            continue

        db.add(
            Repository(
                github_repo_id=github_repo_id,
                full_name=full_name,
                installation_id=0,
                owner_user_id=owner_user_id,
                is_active=True,
            )
        )
        created += 1
    return created, updated


async def _upsert_repository_webhook_credentials(
    db: AsyncSession,
    *,
    owner_user_id: int,
    webhook_rows: list[dict[str, Any]],
) -> int:
    """Persist per-repository webhook id + secret generated during authorization."""
    if not webhook_rows:
        return 0

    full_names = [
        str(item.get("repo_full_name") or "").strip()
        for item in webhook_rows
        if str(item.get("repo_full_name") or "").strip()
    ]
    if not full_names:
        return 0

    result = await db.execute(
        select(Repository).where(Repository.full_name.in_(full_names))
    )
    existing = {row.full_name: row for row in result.scalars().all()}

    updated = 0
    for item in webhook_rows:
        full_name = str(item.get("repo_full_name") or "").strip()
        webhook_secret = str(item.get("webhook_secret") or "").strip()
        if not full_name or not webhook_secret:
            continue

        row = existing.get(full_name)
        if not row:
            continue
        row.owner_user_id = owner_user_id
        row.webhook_id = _coerce_int(item.get("hook_id"))
        row.webhook_secret_encrypted = webhook_secret
        row.is_active = True
        updated += 1
    return updated


def _render_scan_rows(
    rows: list[dict[str, Any]],
    *,
    empty_message: str,
) -> str:
    if not rows:
        return f"<div class='muted'>{escape(empty_message)}</div>"

    body_rows: list[str] = []
    for row in rows:
        title = str(row.get("pr_title", ""))
        repo = str(row.get("repo_full_name", ""))
        pr_number = row.get("pr_number", "")
        verdict = str(row.get("verdict", "")).lower()
        url = str(row.get("pr_url", ""))
        reason = str(row.get("analysis", {}).get("verdict_reason") or "")
        body_rows.append(
            "<tr>"
            f"<td>{escape(repo)} #{escape(str(pr_number))}</td>"
            f"<td><a href='{escape(url)}' target='_blank' rel='noreferrer'>{escape(title)}</a></td>"
            f"<td>{escape(verdict)}</td>"
            f"<td>{escape(reason[:90])}</td>"
            "</tr>"
        )
    return (
        "<div class='table-wrap'>"
        "<table>"
        "<thead><tr><th>PR</th><th>Title</th><th>Verdict</th><th>Reason</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "</div>"
    )


def _render_authorization_ui(
    *,
    oauth_enabled: bool,
    github_login: str | None,
    webhook_target: str,
    webhook_target_public: bool,
    repositories: list[dict[str, Any]],
    flash_level: str | None,
    flash_message: str | None,
    repo_name_prefill: str,
    dashboard_stats: dict[str, int] | None,
    pending_rows: list[dict[str, Any]],
    reviewed_rows: list[dict[str, Any]],
    spam_rows: list[dict[str, Any]],
    connected_users: list[dict[str, Any]],
    managed_repositories: list[dict[str, Any]],
) -> str:
    notice_html = ""
    if flash_message:
        cls = "ok" if flash_level == "success" else "err"
        notice_html = f"<div class='notice {cls}'>{escape(flash_message)}</div>"

    webhook_help = ""
    if not webhook_target_public:
        webhook_help = (
            "<div class='notice err'>Webhook URL must be a public HTTPS URL. "
            "Set <code>PUBLIC_BASE_URL</code> to your tunnel/domain "
            "(for example: <code>https://your-subdomain.trycloudflare.com</code>) "
            "and restart the app.</div>"
        )

    options: list[str] = []
    if repositories:
        for repo in repositories:
            visibility = "private" if repo.get("private") else "public"
            admin_tag = "admin" if repo.get("admin") else "collaborator"
            full_name = str(repo.get("full_name", ""))
            label = f"{full_name} · {visibility} · {admin_tag}"
            options.append(
                f"<option value='{escape(full_name)}'>{escape(label)}</option>"
            )
    select_disabled = " disabled" if not github_login else ""
    button_disabled = " disabled" if not github_login else ""
    hint = (
        "Connect GitHub first to authorize repositories."
        if not github_login
        else "You can submit multiple repositories at once."
    )
    repos_html = (
        "<form method='post' action='/ui/authorize-repos' class='stack'>"
        "<label for='repo_full_names'>Repository Names (owner/repo)</label>"
        "<textarea id='repo_full_names' name='repo_full_names' rows='4' "
        "placeholder='owner/repo-a&#10;owner/repo-b'>"
        f"{escape(repo_name_prefill)}"
        "</textarea>"
        "<label for='repo_full_name_list'>Or select from connected repositories</label>"
        f"<select id='repo_full_name_list' name='repo_full_name_list' multiple size='8'{select_disabled}>"
        f"{''.join(options)}"
        "</select>"
        "<label class='inline-check'>"
        "<input type='checkbox' name='sync_open_prs' value='1' checked />"
        "<span>Queue existing open PRs immediately</span>"
        "</label>"
        f"<div class='muted'>{escape(hint)}</div>"
        f"<button type='submit'{button_disabled}>Authorize Repositories</button>"
        "</form>"
    )

    connect_html = ""
    if not oauth_enabled:
        connect_html = (
            "<div class='notice err'>Set <code>GITHUB_OAUTH_CLIENT_ID</code> and "
            "<code>GITHUB_OAUTH_CLIENT_SECRET</code> in <code>.env</code> to enable "
            "multi-user repository authorization UI.</div>"
        )
    elif github_login:
        connect_html = (
            f"<div class='row'><strong>Connected as {escape(github_login)}</strong>"
            "<form method='post' action='/auth/github/logout'>"
            "<button class='secondary' type='submit'>Disconnect</button>"
            "</form></div>"
        )
    else:
        connect_html = (
            "<a class='oauth-btn' href='/auth/github/start'>Connect GitHub</a>"
        )

    stats_html = ""
    if dashboard_stats:
        stats_html = (
            "<section class='hero stats-hero'>"
            "<h2>PR Overview</h2>"
            "<div class='stats-grid'>"
            f"<div class='stat'><span>Pending</span><strong>{dashboard_stats.get('queue_pending', 0)}</strong></div>"
            f"<div class='stat'><span>Under Review</span><strong>{dashboard_stats.get('reviewed_approved', 0)}</strong></div>"
            f"<div class='stat'><span>Spam / Closed</span><strong>{dashboard_stats.get('spam_closed', 0)}</strong></div>"
            f"<div class='stat'><span>Repositories</span><strong>{dashboard_stats.get('total_repositories', 0)}</strong></div>"
            f"<div class='stat'><span>Active Repos</span><strong>{dashboard_stats.get('active_repositories', 0)}</strong></div>"
            f"<div class='stat'><span>Total Scans</span><strong>{dashboard_stats.get('total_scans', 0)}</strong></div>"
            "</div>"
            "</section>"
        )

    users_html = (
        "<div class='muted'>No connected users yet.</div>"
        if not connected_users
        else (
            "<div class='table-wrap'><table>"
            "<thead><tr><th>GitHub Login</th><th>GitHub ID</th><th>Status</th></tr></thead>"
            "<tbody>"
            + "".join(
                "<tr>"
                f"<td>{escape(str(user.get('github_login', '')))}</td>"
                f"<td>{escape(str(user.get('github_user_id', '')))}</td>"
                f"<td>{'active' if user.get('is_active') else 'inactive'}</td>"
                "</tr>"
                for user in connected_users
            )
            + "</tbody></table></div>"
        )
    )

    repos_html_table = (
        "<div class='muted'>No repositories stored yet.</div>"
        if not managed_repositories
        else (
            "<div class='table-wrap'><table>"
            "<thead><tr><th>Repository</th><th>Owner User ID</th><th>Installation</th><th>Status</th></tr></thead>"
            "<tbody>"
            + "".join(
                "<tr>"
                f"<td>{escape(str(repo.get('full_name', '')))}</td>"
                f"<td>{escape(str(repo.get('owner_user_id') or '-'))}</td>"
                f"<td>{escape(str(repo.get('installation_id') or 0))}</td>"
                f"<td>{'active' if repo.get('is_active') else 'inactive'}</td>"
                "</tr>"
                for repo in managed_repositories
            )
            + "</tbody></table></div>"
        )
    )

    pending_html = _render_scan_rows(
        pending_rows,
        empty_message="No pending PRs currently in queue.",
    )
    reviewed_html = _render_scan_rows(
        reviewed_rows,
        empty_message="No reviewed PRs yet.",
    )
    spam_html = _render_scan_rows(
        spam_rows,
        empty_message="No spam/closed PRs yet.",
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sentinel Multi-Repo Authorization</title>
  <style>
    :root {{
      --bg: #f7efe1;
      --card: #fff8ee;
      --ink: #1f2937;
      --muted: #5f6b7a;
      --accent: #0f766e;
      --accent-2: #155e75;
      --danger: #9f1239;
      --ok-bg: #d1fae5;
      --err-bg: #ffe4e6;
      --border: #d6c5ab;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Avenir Next", "Gill Sans", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 10% 10%, #efe2c5, transparent 40%),
        radial-gradient(circle at 90% 20%, #d9f2ee, transparent 35%),
        var(--bg);
      min-height: 100vh;
    }}
    .wrap {{
      max-width: 960px;
      margin: 0 auto;
      padding: 24px 16px 56px;
    }}
    .hero {{
      border: 1px solid var(--border);
      background: linear-gradient(140deg, #fff8ee, #f0fbff);
      border-radius: 18px;
      padding: 20px;
      box-shadow: 0 12px 24px rgba(14, 23, 38, 0.08);
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: clamp(1.5rem, 3.2vw, 2.2rem);
      letter-spacing: 0.01em;
    }}
    p {{ margin: 0 0 12px; color: var(--muted); line-height: 1.5; }}
    .grid {{
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 16px;
      margin-top: 16px;
    }}
    .card {{
      border: 1px solid var(--border);
      background: var(--card);
      border-radius: 16px;
      padding: 16px;
    }}
    .notice {{
      border-radius: 10px;
      padding: 10px 12px;
      margin: 0 0 12px;
      font-size: 0.95rem;
    }}
    .notice.ok {{ background: var(--ok-bg); }}
    .notice.err {{ background: var(--err-bg); color: var(--danger); }}
    .oauth-btn, button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 10px 14px;
      border-radius: 10px;
      border: none;
      text-decoration: none;
      color: #fff;
      background: linear-gradient(120deg, var(--accent), var(--accent-2));
      font-weight: 600;
      cursor: pointer;
    }}
    button:disabled {{
      opacity: 0.55;
      cursor: not-allowed;
    }}
    button.secondary {{
      background: #334155;
    }}
    .stack {{ display: flex; flex-direction: column; gap: 10px; }}
    .inline-check {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
    }}
    .inline-check input {{
      width: 16px;
      height: 16px;
      accent-color: var(--accent);
    }}
    label {{ font-weight: 600; font-size: 0.95rem; }}
    select {{
      padding: 10px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      min-height: 46px;
    }}
    textarea {{
      padding: 10px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      font-family: "SFMono-Regular", Menlo, Consolas, monospace;
      line-height: 1.4;
    }}
    .row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }}
    .muted {{ color: var(--muted); font-size: 0.95rem; }}
    code {{
      background: rgba(15, 118, 110, 0.12);
      padding: 2px 5px;
      border-radius: 6px;
    }}
    .stats-hero {{ margin-top: 16px; }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}
    .stat {{
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #fff;
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .stat span {{
      color: var(--muted);
      font-size: 0.85rem;
    }}
    .stat strong {{
      font-size: 1.2rem;
    }}
    .panes {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 16px;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #fff;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 540px;
    }}
    th, td {{
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid #ece7de;
      vertical-align: top;
      font-size: 0.9rem;
    }}
    th {{
      background: #fbf5ea;
      color: var(--muted);
      font-weight: 700;
    }}
    .full {{ grid-column: 1 / -1; }}
    @media (max-width: 760px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .stats-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .panes {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <h1>Sentinel Multi-User Repository Authorization</h1>
      <p>Connect GitHub, provide repository names (or select multiple repos), and authorize Sentinel webhooks in one step for multi-user/multi-repo setup.</p>
      {notice_html}
      <div class="grid">
        <article class="card">
          <h2>1. GitHub Configuration</h2>
          <p class="muted">OAuth scopes requested: <code>repo</code> and <code>read:user</code>.</p>
          <p class="muted">Webhook target: <code>{escape(webhook_target)}</code></p>
          <p class="muted">Webhook secret is generated per repository automatically during authorization.</p>
          <p class="muted">Repository webhook event: <code>pull_request</code>. App-level events <code>installation</code> and <code>installation_repositories</code> are handled when your GitHub App sends them.</p>
          {webhook_help}
          {connect_html}
        </article>
        <article class="card">
          <h2>2. Repositories</h2>
          <p class="muted">Authorize one or many repositories in a single submit.</p>
          {repos_html}
        </article>
      </div>
    </section>
    {stats_html}
    <section class="panes">
      <article class="card">
        <h2>Pending Queue</h2>
        {pending_html}
      </article>
      <article class="card">
        <h2>Under Review</h2>
        {reviewed_html}
      </article>
      <article class="card full">
        <h2>Spam / Closed</h2>
        {spam_html}
      </article>
      <article class="card">
        <h2>Connected GitHub Users</h2>
        {users_html}
      </article>
      <article class="card">
        <h2>Managed Repositories</h2>
        {repos_html_table}
      </article>
    </section>
  </main>
</body>
</html>"""


# ── Routes ──────────────────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/ui", status_code=302)


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
async def ui_home(request: Request):
    flash_level, flash_message = _pop_flash(request)
    github_login = request.session.get("github_user_login")
    oauth_token = request.session.get("github_oauth_token")
    repo_name_prefill = str(request.session.get("ui_repo_name_prefill", ""))
    repositories: list[dict[str, Any]] = []
    dashboard_stats: dict[str, int] | None = None
    pending_rows: list[dict[str, Any]] = []
    reviewed_rows: list[dict[str, Any]] = []
    spam_rows: list[dict[str, Any]] = []
    connected_users: list[dict[str, Any]] = []
    managed_repositories: list[dict[str, Any]] = []
    effective_public_base_url = _effective_public_base_url(request)
    webhook_target = _webhook_target_url(effective_public_base_url)
    webhook_target_public = _is_public_https_base_url(effective_public_base_url)

    if oauth_token:
        try:
            repositories = await _github_list_repositories(str(oauth_token))
        except Exception as exc:
            request.session.pop("github_oauth_token", None)
            request.session.pop("github_user_login", None)
            request.session.pop("github_user_id", None)
            request.session.pop("sentinel_user_id", None)
            flash_level = "error"
            flash_message = (
                "Connected GitHub session expired or failed. "
                f"Please reconnect. ({exc})"
            )

    if settings.supabase_uses_postgres:
        try:
            async with _dashboard_db_session() as db:
                verdict_counts_stmt = (
                    select(PRScan.verdict, func.count(PRScan.id))
                    .group_by(PRScan.verdict)
                )
                verdict_rows = (await db.execute(verdict_counts_stmt)).all()
                verdict_counts: dict[str, int] = {}
                for verdict, count in verdict_rows:
                    value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
                    verdict_counts[value] = int(count)

                pending = verdict_counts.get(Verdict.PENDING.value, 0)
                reviewed = verdict_counts.get(Verdict.PASSED.value, 0)
                failed = verdict_counts.get(Verdict.FAILED.value, 0)
                soft_fail = verdict_counts.get(Verdict.SOFT_FAIL.value, 0)
                total_scans = int((await db.scalar(select(func.count(PRScan.id)))) or 0)
                total_repositories = int((await db.scalar(select(func.count(Repository.id)))) or 0)
                active_repositories = int(
                    (
                        await db.scalar(
                            select(func.count(Repository.id)).where(Repository.is_active.is_(True))
                        )
                    )
                    or 0
                )
                dashboard_stats = {
                    "queue_pending": pending,
                    "reviewed_approved": reviewed,
                    "spam_closed": failed + soft_fail,
                    "auto_closed": failed,
                    "needs_clarification": soft_fail,
                    "total_scans": total_scans,
                    "total_repositories": total_repositories,
                    "active_repositories": active_repositories,
                }

                pending_scans = (
                    await db.execute(
                        select(PRScan)
                        .where(PRScan.verdict == Verdict.PENDING)
                        .order_by(PRScan.created_at.desc())
                        .limit(8)
                    )
                ).scalars().all()
                reviewed_scans = (
                    await db.execute(
                        select(PRScan)
                        .where(PRScan.verdict == Verdict.PASSED)
                        .order_by(PRScan.created_at.desc())
                        .limit(8)
                    )
                ).scalars().all()
                spam_scans = (
                    await db.execute(
                        select(PRScan)
                        .where(PRScan.verdict.in_([Verdict.FAILED, Verdict.SOFT_FAIL]))
                        .order_by(PRScan.created_at.desc())
                        .limit(8)
                    )
                ).scalars().all()
                pending_rows = [_scan_to_response(scan) for scan in pending_scans]
                reviewed_rows = [_scan_to_response(scan) for scan in reviewed_scans]
                spam_rows = [_scan_to_response(scan) for scan in spam_scans]

                user_rows = (
                    await db.execute(
                        select(User).order_by(User.updated_at.desc()).limit(12)
                    )
                ).scalars().all()
                connected_users = [
                    {
                        "github_user_id": int(row.github_user_id),
                        "github_login": row.github_login,
                        "is_active": bool(row.is_active),
                    }
                    for row in user_rows
                ]

                repo_rows = (
                    await db.execute(
                        select(Repository).order_by(Repository.updated_at.desc()).limit(20)
                    )
                ).scalars().all()
                managed_repositories = [
                    {
                        "full_name": row.full_name,
                        "owner_user_id": row.owner_user_id,
                        "installation_id": int(row.installation_id),
                        "is_active": bool(row.is_active),
                    }
                    for row in repo_rows
                ]
        except Exception as exc:
            if not flash_message:
                flash_level = "error"
                flash_message = f"Could not load dashboard snapshot: {exc}"

    html = _render_authorization_ui(
        oauth_enabled=settings.github_oauth_enabled,
        github_login=str(github_login) if github_login else None,
        webhook_target=webhook_target,
        webhook_target_public=webhook_target_public,
        repositories=repositories,
        flash_level=flash_level,
        flash_message=flash_message,
        repo_name_prefill=repo_name_prefill,
        dashboard_stats=dashboard_stats,
        pending_rows=pending_rows,
        reviewed_rows=reviewed_rows,
        spam_rows=spam_rows,
        connected_users=connected_users,
        managed_repositories=managed_repositories,
    )
    return HTMLResponse(content=html)


@app.get("/auth/github/start", include_in_schema=False)
async def github_auth_start(request: Request, next: str | None = None):
    if not settings.github_oauth_enabled:
        _set_flash(
            request,
            "error",
            "GitHub OAuth is not configured. Set GITHUB_OAUTH_CLIENT_ID and "
            "GITHUB_OAUTH_CLIENT_SECRET in .env.",
        )
        return RedirectResponse(url="/ui", status_code=302)

    safe_next = _safe_next_redirect_url(next)
    if safe_next:
        request.session["github_oauth_next_url"] = safe_next
    else:
        request.session.pop("github_oauth_next_url", None)

    state = secrets.token_urlsafe(24)
    request.session["github_oauth_state"] = state
    query = urlencode(
        {
            "client_id": settings.github_oauth_client_id,
            "redirect_uri": _github_oauth_redirect_uri(request),
            "scope": "repo read:user",
            "state": state,
        }
    )
    return RedirectResponse(url=f"{_GITHUB_OAUTH_AUTHORIZE_URL}?{query}", status_code=302)


@app.get("/auth/github/callback", include_in_schema=False)
async def github_auth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
):
    expected_state = request.session.pop("github_oauth_state", None)
    next_url = _safe_next_redirect_url(request.session.pop("github_oauth_next_url", None))
    if not code or not state or state != expected_state:
        _set_flash(request, "error", "Invalid GitHub OAuth state or missing code.")
        return RedirectResponse(url=next_url or "/ui", status_code=302)

    try:
        token = await _github_exchange_oauth_code(code)
        user = await _github_get_authenticated_user(token)
        github_login = user.get("login", "unknown")

        # Always persist to session (works for same-domain /ui)
        request.session["github_oauth_token"] = token
        request.session["github_user_login"] = github_login
        request.session["github_user_id"] = str(user.get("id", ""))

        if settings.supabase_uses_postgres:
            async with _dashboard_db_session() as db:
                sentinel_user_id = await _upsert_oauth_user(
                    db,
                    github_user=user,
                    oauth_token=token,
                )
                if sentinel_user_id is not None:
                    request.session["sentinel_user_id"] = str(sentinel_user_id)

        # Cross-domain redirect: pass token in URL hash so the frontend can
        # store it in localStorage.  The hash fragment is never sent to the
        # server, keeping the token out of access logs.
        if next_url and _is_external_redirect(next_url, request):
            separator = "#" if "#" not in next_url else "&"
            fragment = urlencode({"auth_token": token, "github_login": github_login})
            return RedirectResponse(
                url=f"{next_url}{separator}{fragment}",
                status_code=302,
            )

        _set_flash(
            request,
            "success",
            "GitHub connected. Enter repository names or select multiple repositories to authorize.",
        )
    except Exception as exc:
        _set_flash(request, "error", f"GitHub OAuth failed: {exc}")

    return RedirectResponse(url=next_url or "/ui", status_code=302)


@app.post("/auth/github/logout", include_in_schema=False)
async def github_auth_logout(request: Request):
    request.session.pop("github_oauth_token", None)
    request.session.pop("github_user_login", None)
    request.session.pop("github_user_id", None)
    request.session.pop("sentinel_user_id", None)
    request.session.pop("github_oauth_state", None)
    request.session.pop("github_oauth_next_url", None)
    request.session.pop("ui_repo_name_prefill", None)
    _set_flash(request, "success", "GitHub account disconnected.")
    return RedirectResponse(url="/ui", status_code=302)


@app.post("/ui/authorize-repos", include_in_schema=False)
async def authorize_repositories(request: Request):
    oauth_token = request.session.get("github_oauth_token")
    if not oauth_token:
        _set_flash(request, "error", "Connect GitHub before authorizing a repository.")
        return RedirectResponse(url="/ui", status_code=302)

    form = await request.form()
    selected_repo_names = [str(v).strip() for v in form.getlist("repo_full_name_list")]
    typed_repo_names = _parse_repo_names(str(form.get("repo_full_names", "")).strip())
    sync_open_prs_raw = str(form.get("sync_open_prs", "1")).strip().lower()
    sync_open_prs = sync_open_prs_raw not in {"0", "false", "off", "no"}
    repo_full_names = list(dict.fromkeys(
        [name for name in (*selected_repo_names, *typed_repo_names) if name and "/" in name]
    ))

    request.session["ui_repo_name_prefill"] = "\n".join(typed_repo_names)

    if not repo_full_names:
        _set_flash(
            request,
            "error",
            "Provide at least one repository in owner/name format or select from the list.",
        )
        return RedirectResponse(url="/ui", status_code=302)

    effective_public_base_url = _effective_public_base_url(request)
    if not _is_public_https_base_url(effective_public_base_url):
        _set_flash(
            request,
            "error",
            (
                "Webhook setup requires PUBLIC_BASE_URL to be a public HTTPS URL. "
                f"Current base URL is {effective_public_base_url}. "
                "Set PUBLIC_BASE_URL to your public tunnel/domain and retry."
            ),
        )
        return RedirectResponse(url="/ui", status_code=302)
    webhook_target = _webhook_target_url(effective_public_base_url)

    visible_repo_by_name: dict[str, dict[str, Any]] = {}
    try:
        visible_repositories = await _github_list_repositories(str(oauth_token))
        visible_repo_by_name = {
            str(repo.get("full_name", "")).strip(): repo for repo in visible_repositories
        }
    except Exception:
        visible_repo_by_name = {}

    try:
        succeeded_rows, failed = await _ensure_repo_webhooks(
            str(oauth_token),
            repo_full_names,
            webhook_target=webhook_target,
        )
        succeeded = [
            str(item.get("repo_full_name") or "").strip()
            for item in succeeded_rows
            if str(item.get("repo_full_name") or "").strip()
        ]
        sentinel_user_id = _coerce_int(request.session.get("sentinel_user_id"))
        linked_count = 0
        created_repos = 0
        updated_repos = 0
        webhook_credentials_saved = 0
        fetched_open_prs = 0
        queued_open_prs = 0
        skipped_open_prs = 0
        sync_failures: list[str] = []
        metadata_failures: list[str] = []
        if settings.supabase_uses_postgres and sentinel_user_id is not None:
            repositories_to_persist: list[dict[str, Any]] = []
            for full_name in succeeded:
                meta = visible_repo_by_name.get(full_name)
                if meta is None:
                    try:
                        meta = await _github_get_repository(str(oauth_token), full_name)
                    except Exception as exc:
                        metadata_failures.append(f"{full_name}: {exc}")
                        continue
                repositories_to_persist.append(meta)

            async with _dashboard_db_session() as db:
                linked_count = await _link_owner_to_repositories(
                    db,
                    owner_user_id=sentinel_user_id,
                    repo_full_names=succeeded,
                )
                created_repos, updated_repos = await _upsert_user_repositories(
                    db,
                    owner_user_id=sentinel_user_id,
                    repositories=repositories_to_persist,
                )
                webhook_credentials_saved = await _upsert_repository_webhook_credentials(
                    db,
                    owner_user_id=sentinel_user_id,
                    webhook_rows=succeeded_rows,
                )

        if sync_open_prs and succeeded:
            (
                fetched_open_prs,
                queued_open_prs,
                skipped_open_prs,
                sync_failures,
            ) = await _sync_open_prs_for_repositories(str(oauth_token), succeeded)

        combined_failures = failed + metadata_failures + sync_failures
        if combined_failures:
            failed_preview = "; ".join(combined_failures[:3])
            _set_flash(
                request,
                "error",
                (
                    f"Authorized {len(succeeded)} repos, failed {len(combined_failures)}. "
                    f"Linked {linked_count} repos; persisted repo records "
                    f"(created={created_repos}, updated={updated_repos}, "
                    f"webhook_credentials={webhook_credentials_saved}); "
                    f"open PRs fetched={fetched_open_prs}, queued={queued_open_prs}, "
                    f"skipped={skipped_open_prs}. "
                    f"Failures: {failed_preview}"
                ),
            )
        else:
            _set_flash(
                request,
                "success",
                (
                    f"Authorized {len(succeeded)} repositories successfully. "
                    f"Linked {linked_count} repos; persisted repo records "
                    f"(created={created_repos}, updated={updated_repos}, "
                    f"webhook_credentials={webhook_credentials_saved}); "
                    f"open PRs fetched={fetched_open_prs}, queued={queued_open_prs}, "
                    f"skipped={skipped_open_prs}."
                ),
            )
    except Exception as exc:
        _set_flash(request, "error", f"Repository authorization failed: {exc}")
    return RedirectResponse(url="/ui", status_code=302)


@app.post("/ui/authorize-repo", include_in_schema=False)
async def authorize_repository_legacy(request: Request):
    """Backward-compatible alias for older UI form action."""
    return await authorize_repositories(request)


@app.get("/api/setup/status")
async def setup_status(request: Request):
    """Setup metadata for the React quick-start panel."""
    oauth_token, github_login, _ = _get_oauth_credentials(request)

    # If we got a bearer token but no login, resolve it.
    if oauth_token and not github_login:
        github_login, _ = await _resolve_bearer_user(oauth_token)

    effective_public_base_url = _effective_public_base_url(request)

    return {
        "oauth_enabled": settings.github_oauth_enabled,
        "connected": bool(oauth_token and github_login),
        "github_login": str(github_login) if github_login else None,
        "webhook_target": _webhook_target_url(effective_public_base_url),
        "webhook_target_public": _is_public_https_base_url(effective_public_base_url),
        "connect_path": "/auth/github/start",
        "disconnect_path": "/auth/github/logout",
    }


@app.post("/api/setup/logout")
async def setup_logout(request: Request):
    """Clear GitHub session values for React UI."""
    request.session.pop("github_oauth_token", None)
    request.session.pop("github_user_login", None)
    request.session.pop("github_user_id", None)
    request.session.pop("sentinel_user_id", None)
    request.session.pop("github_oauth_state", None)
    request.session.pop("github_oauth_next_url", None)
    request.session.pop("ui_repo_name_prefill", None)
    return {"ok": True, "message": "Disconnected GitHub session."}


@app.post("/api/setup/authorize-repos")
async def setup_authorize_repositories(request: Request, payload: AuthorizeReposApiPayload):
    """Authorize repositories from React UI and optionally queue open PR scans."""
    oauth_token, _, _ = _get_oauth_credentials(request)
    if not oauth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Connect GitHub before authorizing repositories.",
        )

    repo_full_names = _normalize_repo_names(payload.repo_full_names)
    if not repo_full_names:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide at least one repository in owner/repo format.",
        )

    effective_public_base_url = _effective_public_base_url(request)
    webhook_target_public = _is_public_https_base_url(effective_public_base_url)
    webhook_target = _webhook_target_url(effective_public_base_url)

    visible_repo_by_name: dict[str, dict[str, Any]] = {}
    try:
        visible_repositories = await _github_list_repositories(str(oauth_token))
        visible_repo_by_name = {
            str(repo.get("full_name", "")).strip(): repo for repo in visible_repositories
        }
    except Exception:
        visible_repo_by_name = {}

    failed: list[str] = []
    if webhook_target_public:
        succeeded_rows, failed = await _ensure_repo_webhooks(
            str(oauth_token),
            repo_full_names,
            webhook_target=webhook_target,
        )
    else:
        succeeded_rows = [{"repo_full_name": name, "hook_id": None, "webhook_secret": ""} for name in repo_full_names]
        failed.append(
            "Webhook setup skipped because PUBLIC_BASE_URL is not a public HTTPS URL."
        )
    succeeded = [
        str(item.get("repo_full_name") or "").strip()
        for item in succeeded_rows
        if str(item.get("repo_full_name") or "").strip()
    ]

    _, _, _raw_sentinel_id = _get_oauth_credentials(request)
    sentinel_user_id = _coerce_int(_raw_sentinel_id)
    # If bearer-token auth, resolve sentinel_user_id from DB.
    if sentinel_user_id is None and oauth_token:
        _, resolved_id = await _resolve_bearer_user(str(oauth_token))
        sentinel_user_id = _coerce_int(resolved_id)
    linked_count = 0
    created_repos = 0
    updated_repos = 0
    webhook_credentials_saved = 0
    fetched_open_prs = 0
    queued_open_prs = 0
    skipped_open_prs = 0
    sync_failures: list[str] = []
    metadata_failures: list[str] = []

    if settings.supabase_uses_postgres and sentinel_user_id is not None:
        repositories_to_persist: list[dict[str, Any]] = []
        for full_name in succeeded:
            meta = visible_repo_by_name.get(full_name)
            if meta is None:
                try:
                    meta = await _github_get_repository(str(oauth_token), full_name)
                except Exception as exc:
                    metadata_failures.append(f"{full_name}: {exc}")
                    continue
            repositories_to_persist.append(meta)

        async with _dashboard_db_session() as db:
            linked_count = await _link_owner_to_repositories(
                db,
                owner_user_id=sentinel_user_id,
                repo_full_names=succeeded,
            )
            created_repos, updated_repos = await _upsert_user_repositories(
                db,
                owner_user_id=sentinel_user_id,
                repositories=repositories_to_persist,
            )
            webhook_credentials_saved = await _upsert_repository_webhook_credentials(
                db,
                owner_user_id=sentinel_user_id,
                webhook_rows=succeeded_rows,
            )

    if payload.sync_open_prs and succeeded:
        (
            fetched_open_prs,
            queued_open_prs,
            skipped_open_prs,
            sync_failures,
        ) = await _sync_open_prs_for_repositories(str(oauth_token), succeeded)

    combined_failures = failed + metadata_failures + sync_failures
    logger.info(
        "UI authorization summary: repos=%d succeeded=%d failures=%d queued_prs=%d",
        len(repo_full_names),
        len(succeeded),
        len(combined_failures),
        queued_open_prs,
    )

    if combined_failures:
        message = (
            f"Authorized {len(succeeded)} repos, failed {len(combined_failures)}. "
            f"Queued open PRs={queued_open_prs}."
        )
    else:
        message = (
            f"Authorized {len(succeeded)} repositories successfully. "
            f"Queued open PRs={queued_open_prs}."
        )

    return {
        "ok": len(combined_failures) == 0,
        "message": message,
        "webhook_target_public": webhook_target_public,
        "webhook_target": webhook_target,
        "authorized_repositories": succeeded,
        "failures": combined_failures,
        "counts": {
            "requested_repositories": len(repo_full_names),
            "authorized_repositories": len(succeeded),
            "failed_repositories": len(combined_failures),
            "linked_repositories": linked_count,
            "created_repositories": created_repos,
            "updated_repositories": updated_repos,
            "saved_webhook_credentials": webhook_credentials_saved,
            "fetched_open_prs": fetched_open_prs,
            "queued_open_prs": queued_open_prs,
            "skipped_open_prs": skipped_open_prs,
        },
    }


@app.get("/api/dashboard/stats")
async def dashboard_stats(repo_full_name: str | None = None):
    """Dashboard counters used by Queue / Reviewed / Spam tabs."""
    async with _dashboard_db_session() as db:
        verdict_counts_stmt = (
            select(PRScan.verdict, func.count(PRScan.id))
            .group_by(PRScan.verdict)
        )
        if repo_full_name:
            verdict_counts_stmt = verdict_counts_stmt.where(
                PRScan.repo_full_name == repo_full_name
            )
        verdict_rows = (await db.execute(verdict_counts_stmt)).all()

        verdict_counts: dict[str, int] = {}
        for verdict, count in verdict_rows:
            value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
            verdict_counts[value] = int(count)

        pending = verdict_counts.get(Verdict.PENDING.value, 0)
        reviewed = verdict_counts.get(Verdict.PASSED.value, 0)
        failed = verdict_counts.get(Verdict.FAILED.value, 0)
        soft_fail = verdict_counts.get(Verdict.SOFT_FAIL.value, 0)

        total_scans_stmt = select(func.count(PRScan.id))
        if repo_full_name:
            total_scans_stmt = total_scans_stmt.where(PRScan.repo_full_name == repo_full_name)
        total_scans = int((await db.scalar(total_scans_stmt)) or 0)

        total_repositories = int(
            (await db.scalar(select(func.count(Repository.id)))) or 0
        )
        active_repositories = int(
            (
                await db.scalar(
                    select(func.count(Repository.id)).where(Repository.is_active.is_(True))
                )
            )
            or 0
        )

        return {
            "repo_filter": repo_full_name,
            "stats": {
                "queue_pending": pending,
                "reviewed_approved": reviewed,
                "spam_closed": failed + soft_fail,
                "auto_closed": failed,
                "needs_clarification": soft_fail,
                "total_scans": total_scans,
                "total_repositories": total_repositories,
                "active_repositories": active_repositories,
            },
            "verdict_breakdown": verdict_counts,
        }


@app.get("/api/prs/queue")
async def prs_queue(limit: int = 50, repo_full_name: str | None = None):
    """Queue tab: PRs still pending Sentinel verdict."""
    limit = max(1, min(limit, 200))
    async with _dashboard_db_session() as db:
        stmt = (
            select(PRScan)
            .where(PRScan.verdict == Verdict.PENDING)
            .order_by(PRScan.created_at.desc())
            .limit(limit)
        )
        if repo_full_name:
            stmt = stmt.where(PRScan.repo_full_name == repo_full_name)
        rows = (await db.execute(stmt)).scalars().all()

    items = [_scan_to_response(row) for row in rows]
    return {"items": items, "count": len(items)}


@app.get("/api/prs/reviewed")
async def prs_reviewed(limit: int = 50, repo_full_name: str | None = None):
    """Reviewed tab: PRs approved by Sentinel and promoted to maintainers."""
    limit = max(1, min(limit, 200))
    async with _dashboard_db_session() as db:
        stmt = (
            select(PRScan)
            .where(PRScan.verdict == Verdict.PASSED)
            .order_by(PRScan.created_at.desc())
            .limit(limit)
        )
        if repo_full_name:
            stmt = stmt.where(PRScan.repo_full_name == repo_full_name)
        rows = (await db.execute(stmt)).scalars().all()

    items = [_scan_to_response(row) for row in rows]
    return {"items": items, "count": len(items)}


@app.get("/api/prs/spam-closed")
async def prs_spam_closed(
    limit: int = 50,
    include_soft_fail: bool = True,
    repo_full_name: str | None = None,
):
    """Spam/Closed tab: auto-closed and optionally soft-failed PRs."""
    limit = max(1, min(limit, 200))
    verdicts = [Verdict.FAILED]
    if include_soft_fail:
        verdicts.append(Verdict.SOFT_FAIL)

    async with _dashboard_db_session() as db:
        stmt = (
            select(PRScan)
            .where(PRScan.verdict.in_(verdicts))
            .order_by(PRScan.created_at.desc())
            .limit(limit)
        )
        if repo_full_name:
            stmt = stmt.where(PRScan.repo_full_name == repo_full_name)
        rows = (await db.execute(stmt)).scalars().all()

    items = [_scan_to_response(row) for row in rows]
    return {"items": items, "count": len(items)}


@app.get("/api/prs/{scan_id}")
async def pr_scan_detail(scan_id: int):
    """PR detail: complete verdict + analysis breakdown."""
    async with _dashboard_db_session() as db:
        stmt = select(PRScan).where(PRScan.id == scan_id)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PR scan not found.",
            )
    return _scan_to_response(scan)


@app.get("/health")
async def health():
    """Keep-alive endpoint for UptimeRobot."""
    return {"status": "ok"}


@app.get("/health/services")
async def health_services():
    """Diagnostic endpoint — tests connectivity to Redis, Groq, and Supabase."""
    results: dict[str, Any] = {}
    oauth_users = await _active_oauth_user_count()

    # ── Redis (Upstash) ─────────────────────────────────────────────────
    if settings.use_celery_worker:
        try:
            import redis as redis_lib
            r = redis_lib.from_url(settings.redis_url, socket_timeout=5)
            pong = r.ping()
            results["redis"] = {"status": "ok", "ping": pong}
        except Exception as e:
            results["redis"] = {"status": "error", "detail": str(e)}
    else:
        results["redis"] = {
            "status": "ok",
            "mode": "inline",
            "detail": "Celery worker disabled; Redis not required.",
        }

    # ── Groq API ────────────────────────────────────────────────────────
    try:
        from groq import Groq
        client = Groq(api_key=settings.groq_api_key)
        resp = client.chat.completions.create(
            model=settings.groq_model,
            messages=[{"role": "user", "content": "Say OK"}],
            max_tokens=5,
        )
        reply = resp.choices[0].message.content or ""
        results["groq"] = {"status": "ok", "reply": reply.strip()}
    except Exception as e:
        results["groq"] = {"status": "error", "detail": str(e)}

    # ── GitHub API ──────────────────────────────────────────────────────
    try:
        from github import Auth, Github

        gh = Github(auth=Auth.Token(settings.github_token))
        login = gh.get_user().login
        github_payload: dict[str, Any] = {"status": "ok", "login": login}
        if oauth_users > 0:
            github_payload["oauth_connected_users"] = oauth_users
        results["github"] = github_payload
    except Exception as e:
        detail = str(e)
        if settings.github_token_is_placeholder and oauth_users > 0:
            results["github"] = {
                "status": "ok",
                "mode": "oauth_user_tokens",
                "oauth_connected_users": oauth_users,
                "detail": (
                    "Global GITHUB_TOKEN is placeholder; using per-user OAuth "
                    "tokens for UI-connected repositories."
                ),
            }
        else:
            if settings.github_token_is_placeholder:
                detail = (
                    f"{detail} | hint: GITHUB_TOKEN appears to be a placeholder "
                    "and no active OAuth user tokens were found."
                )
            results["github"] = {"status": "error", "detail": detail}

    # ── Supabase ────────────────────────────────────────────────────────
    supabase_mode = "postgres" if settings.supabase_uses_postgres else "rest"
    try:
        if settings.supabase_uses_postgres:
            from sqlalchemy import text

            from app.database import _get_engine

            engine = _get_engine()
            async with engine.connect() as conn:
                result = await conn.execute(text("SELECT 1"))
                val = result.scalar()
            results["supabase"] = {"status": "ok", "mode": "postgres", "select_1": val}
        else:
            import httpx

            auth_health_endpoint = f"{settings.supabase_rest_base_url}/auth/v1/health"
            auth_headers = {
                "apikey": settings.supabase_key,
                "Authorization": f"Bearer {settings.supabase_key}",
            }
            async with httpx.AsyncClient(timeout=settings.supabase_http_timeout_sec) as client:
                auth_resp = await client.get(auth_health_endpoint, headers=auth_headers)
                if auth_resp.status_code >= 400:
                    raise RuntimeError(
                        f"Supabase auth health failed ({auth_resp.status_code}) at "
                        f"{auth_health_endpoint}: {auth_resp.text[:180]}"
                    )
            results["supabase"] = {
                "status": "ok",
                "mode": "rest",
                "auth_health_status": auth_resp.status_code,
            }
            if settings.supabase_probe_rest_table:
                rest_probe_endpoint = (
                    f"{settings.supabase_rest_base_url}/rest/v1/pr_scans?select=id&limit=1"
                )
                headers = {
                    "apikey": settings.supabase_key,
                    "Authorization": f"Bearer {settings.supabase_key}",
                }
                async with httpx.AsyncClient(
                    timeout=settings.supabase_http_timeout_sec
                ) as client:
                    resp = await client.get(rest_probe_endpoint, headers=headers)
                probe_status: dict[str, Any] = {"status_code": resp.status_code}
                if resp.status_code >= 400:
                    probe_status["detail"] = resp.text[:180]
                else:
                    rows = resp.json()
                    probe_status["rows_returned"] = (
                        len(rows) if isinstance(rows, list) else None
                    )
                results["supabase"]["rest_probe"] = probe_status
    except Exception as e:
        detail = str(e)
        if "Name or service not known" in detail or "Could not resolve host" in detail:
            detail = (
                f"{detail} | hint: verify SUPABASE_URL project ref in Supabase Settings > API."
            )
        results["supabase"] = {
            "status": "error",
            "mode": supabase_mode,
            "detail": detail,
        }

    all_ok = all(s.get("status") == "ok" for s in results.values())
    return {"all_services_ok": all_ok, "services": results}


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
):
    """Receive GitHub webhook events and enqueue for processing."""
    body = await request.body()
    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook payload type.",
        )

    await _verify_signature(body, x_hub_signature_256, payload)
    action = str(payload.get("action", ""))

    if x_github_event == "pull_request":
        # Only process newly opened / updated PRs
        if action not in ("opened", "synchronize", "reopened"):
            return {"message": f"Ignored action: {action}"}

        # Enqueue the heavy pipeline work to Celery
        task_id = _enqueue_pr(payload)
        logger.info(
            "Enqueued PR %s#%s → task %s",
            payload.get("repository", {}).get("full_name", "?"),
            payload.get("pull_request", {}).get("number", "?"),
            task_id,
        )
        return {"message": "Processing", "task_id": task_id}

    if x_github_event == "installation":
        installation_id = _coerce_int(payload.get("installation", {}).get("id"))
        if installation_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing installation.id in installation event payload.",
            )

        if action == "created":
            repositories = _extract_repository_rows(payload.get("repositories", []))
            async with _installation_db_session() as db:
                created, updated = await _upsert_repositories(
                    db,
                    installation_id=installation_id,
                    repositories=repositories,
                )
            message = (
                f"🎉 Installed on {len(repositories)} repos "
                f"(created={created}, updated={updated})"
            )
            print(message)
            logger.info(message)
            return {
                "message": message,
                "installation_id": installation_id,
                "created": created,
                "updated": updated,
            }

        if action in ("deleted", "suspend", "unsuspend"):
            is_active = action == "unsuspend"
            async with _installation_db_session() as db:
                affected = await _set_repositories_active_for_installation(
                    db,
                    installation_id=installation_id,
                    is_active=is_active,
                )
            state = "active" if is_active else "inactive"
            message = (
                f"Installation {installation_id} marked {state} for "
                f"{affected} repos (action={action})."
            )
            print(message)
            logger.info(message)
            return {
                "message": message,
                "installation_id": installation_id,
                "affected_repositories": affected,
            }

        return {"message": f"Ignored installation action: {action}"}

    if x_github_event == "installation_repositories":
        installation_id = _coerce_int(payload.get("installation", {}).get("id"))
        if installation_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Missing installation.id in installation_repositories event payload."
                ),
            )

        if action == "added":
            repositories = _extract_repository_rows(
                payload.get("repositories_added", [])
            )
            async with _installation_db_session() as db:
                created, updated = await _upsert_repositories(
                    db,
                    installation_id=installation_id,
                    repositories=repositories,
                )
            message = (
                f"Added {len(repositories)} repos for installation "
                f"{installation_id} (created={created}, updated={updated})."
            )
            print(message)
            logger.info(message)
            return {
                "message": message,
                "installation_id": installation_id,
                "created": created,
                "updated": updated,
            }

        if action == "removed":
            repo_ids = _extract_repository_ids(payload.get("repositories_removed", []))
            async with _installation_db_session() as db:
                affected = await _deactivate_repositories_by_id(db, repo_ids=repo_ids)
            message = (
                f"Removed {len(repo_ids)} repos for installation {installation_id} "
                f"(deactivated={affected})."
            )
            print(message)
            logger.info(message)
            return {
                "message": message,
                "installation_id": installation_id,
                "deactivated": affected,
            }

        return {"message": f"Ignored installation_repositories action: {action}"}

    return {"message": f"Ignored event: {x_github_event}"}


# ── Test endpoint (development only) ───────────────────────────────────────

SAMPLE_PAYLOAD: dict[str, Any] = {
    "action": "opened",
    "repository": {
        "full_name": "octocat/Hello-World",
    },
    "pull_request": {
        "number": 1,
        "title": "Fix typo in README",
        "body": "This PR fixes a small typo in the README. Fixes #42",
        "html_url": "https://github.com/octocat/Hello-World/pull/1",
        "user": {
            "login": "octocat",
            "created_at": "2011-01-25T18:44:36Z",
        },
    },
}


@app.post("/webhook/test", status_code=status.HTTP_202_ACCEPTED)
async def webhook_test():
    """**DEV ONLY** — Trigger the pipeline with a sample PR payload.

    No HMAC verification. Usage::

        curl -X POST http://localhost:8000/webhook/test
    """
    task_id = _enqueue_pr(SAMPLE_PAYLOAD)
    logger.info("Test payload enqueued → task %s", task_id)
    return {
        "message": "Test payload enqueued",
        "task_id": task_id,
        "sample_repo": SAMPLE_PAYLOAD["repository"]["full_name"],
        "sample_pr": SAMPLE_PAYLOAD["pull_request"]["number"],
    }
