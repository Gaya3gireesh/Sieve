"""
Sentinel — FastAPI entry point.

Handles GitHub webhooks and exposes a health-check endpoint.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from contextlib import asynccontextmanager
from html import escape
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.database import _get_session_factory
from app.models import PRScan, Repository, Verdict

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
            "Worker GitHub API calls will fail until a real token is set."
        )
    logger.info(
        "Supabase mode: %s",
        "postgres" if settings.supabase_uses_postgres else "rest",
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


# ── Lazy worker import ──────────────────────────────────────────────────────


def _enqueue_pr(payload: dict[str, Any]) -> str:
    """Lazily import the Celery task and enqueue a PR for processing.

    This avoids importing worker.py (which creates a Celery app and
    GroqClient) at module-load time, so FastAPI can start even if
    Redis / Groq are temporarily unreachable.
    """
    from app.worker import process_pr

    task = process_pr.delay(payload)
    return task.id


# ── Signature verification ──────────────────────────────────────────────────


def _verify_signature(payload_body: bytes, signature: str | None) -> None:
    """Verify the GitHub HMAC-SHA256 webhook signature."""
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-Hub-Signature-256 header.",
        )
    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(),
        payload_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
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


def _set_flash(request: Request, level: str, message: str) -> None:
    request.session["ui_flash"] = {"level": level, "message": message}


def _pop_flash(request: Request) -> tuple[str | None, str | None]:
    value = request.session.pop("ui_flash", None)
    if not isinstance(value, dict):
        return None, None
    return value.get("level"), value.get("message")


def _github_oauth_redirect_uri() -> str:
    return f"{settings.public_base_url.rstrip('/')}/auth/github/callback"


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
                "full_name": repo.get("full_name", ""),
                "private": bool(repo.get("private", False)),
                "admin": bool(repo.get("permissions", {}).get("admin", False)),
            }
        )
    return normalized


async def _ensure_repo_webhook(token: str, repo_full_name: str) -> str:
    webhook_target = f"{settings.public_base_url.rstrip('/')}/webhook"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    hook_config = {
        "url": webhook_target,
        "content_type": "json",
        "secret": settings.github_webhook_secret,
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
                return f"Repository {repo_full_name} is now authorized (webhook updated)."
            return f"Repository {repo_full_name} is already authorized."

        create_resp = await client.post(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/hooks",
            headers=headers,
            json=hook_payload,
        )
        if create_resp.status_code >= 400:
            raise RuntimeError(
                f"Webhook creation failed ({create_resp.status_code}): {create_resp.text[:180]}"
            )
    return f"Repository {repo_full_name} is now authorized."


def _render_authorization_ui(
    *,
    oauth_enabled: bool,
    github_login: str | None,
    repositories: list[dict[str, Any]],
    flash_level: str | None,
    flash_message: str | None,
) -> str:
    notice_html = ""
    if flash_message:
        cls = "ok" if flash_level == "success" else "err"
        notice_html = f"<div class='notice {cls}'>{escape(flash_message)}</div>"

    repos_html = ""
    if github_login:
        if repositories:
            options = []
            for repo in repositories:
                visibility = "private" if repo.get("private") else "public"
                admin_tag = "admin" if repo.get("admin") else "collaborator"
                full_name = str(repo.get("full_name", ""))
                label = f"{full_name} · {visibility} · {admin_tag}"
                options.append(
                    f"<option value='{escape(full_name)}'>{escape(label)}</option>"
                )
            repos_html = (
                "<form method='post' action='/ui/authorize-repo' class='stack'>"
                "<label for='repo_full_name'>Choose Repository</label>"
                "<select id='repo_full_name' name='repo_full_name' required>"
                f"{''.join(options)}"
                "</select>"
                "<button type='submit'>Authorize Repository</button>"
                "</form>"
            )
        else:
            repos_html = (
                "<div class='muted'>No repositories visible yet. "
                "Try reconnecting GitHub or verify token scopes.</div>"
            )

    connect_html = ""
    if not oauth_enabled:
        connect_html = (
            "<div class='notice err'>Set <code>GITHUB_OAUTH_CLIENT_ID</code> and "
            "<code>GITHUB_OAUTH_CLIENT_SECRET</code> in <code>.env</code> to enable "
            "repository authorization UI.</div>"
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

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sentinel Repository Authorization</title>
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
    button.secondary {{
      background: #334155;
    }}
    .stack {{ display: flex; flex-direction: column; gap: 10px; }}
    label {{ font-weight: 600; font-size: 0.95rem; }}
    select {{
      padding: 10px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      min-height: 42px;
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
    @media (max-width: 760px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <h1>Sentinel Repository Authorization</h1>
      <p>Connect GitHub, select a repository, and authorize Sentinel by creating or updating a <code>pull_request</code> webhook pointing to this service.</p>
      {notice_html}
      <div class="grid">
        <article class="card">
          <h2>1. Connect Account</h2>
          <p class="muted">OAuth scopes requested: <code>repo</code> and <code>read:user</code>.</p>
          {connect_html}
        </article>
        <article class="card">
          <h2>2. Authorize Repository</h2>
          <p class="muted">Sentinel will configure webhook target: <code>{escape(settings.public_base_url.rstrip('/'))}/webhook</code></p>
          {repos_html}
        </article>
      </div>
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
    repositories: list[dict[str, Any]] = []

    if oauth_token:
        try:
            repositories = await _github_list_repositories(str(oauth_token))
        except Exception as exc:
            request.session.pop("github_oauth_token", None)
            request.session.pop("github_user_login", None)
            flash_level = "error"
            flash_message = (
                "Connected GitHub session expired or failed. "
                f"Please reconnect. ({exc})"
            )

    html = _render_authorization_ui(
        oauth_enabled=settings.github_oauth_enabled,
        github_login=str(github_login) if github_login else None,
        repositories=repositories,
        flash_level=flash_level,
        flash_message=flash_message,
    )
    return HTMLResponse(content=html)


@app.get("/auth/github/start", include_in_schema=False)
async def github_auth_start(request: Request):
    if not settings.github_oauth_enabled:
        _set_flash(
            request,
            "error",
            "GitHub OAuth is not configured. Set GITHUB_OAUTH_CLIENT_ID and "
            "GITHUB_OAUTH_CLIENT_SECRET in .env.",
        )
        return RedirectResponse(url="/ui", status_code=302)

    state = secrets.token_urlsafe(24)
    request.session["github_oauth_state"] = state
    query = urlencode(
        {
            "client_id": settings.github_oauth_client_id,
            "redirect_uri": _github_oauth_redirect_uri(),
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
    if not code or not state or state != expected_state:
        _set_flash(request, "error", "Invalid GitHub OAuth state or missing code.")
        return RedirectResponse(url="/ui", status_code=302)

    try:
        token = await _github_exchange_oauth_code(code)
        user = await _github_get_authenticated_user(token)
        request.session["github_oauth_token"] = token
        request.session["github_user_login"] = user.get("login", "unknown")
        _set_flash(request, "success", "GitHub connected. Select a repository to authorize.")
    except Exception as exc:
        _set_flash(request, "error", f"GitHub OAuth failed: {exc}")

    return RedirectResponse(url="/ui", status_code=302)


@app.post("/auth/github/logout", include_in_schema=False)
async def github_auth_logout(request: Request):
    request.session.pop("github_oauth_token", None)
    request.session.pop("github_user_login", None)
    request.session.pop("github_oauth_state", None)
    _set_flash(request, "success", "GitHub account disconnected.")
    return RedirectResponse(url="/ui", status_code=302)


@app.post("/ui/authorize-repo", include_in_schema=False)
async def authorize_repository(request: Request):
    oauth_token = request.session.get("github_oauth_token")
    if not oauth_token:
        _set_flash(request, "error", "Connect GitHub before authorizing a repository.")
        return RedirectResponse(url="/ui", status_code=302)

    form = await request.form()
    repo_full_name = str(form.get("repo_full_name", "")).strip()
    if not repo_full_name or "/" not in repo_full_name:
        _set_flash(request, "error", "Choose a valid repository in owner/name format.")
        return RedirectResponse(url="/ui", status_code=302)

    try:
        message = await _ensure_repo_webhook(str(oauth_token), repo_full_name)
        _set_flash(request, "success", message)
    except Exception as exc:
        _set_flash(request, "error", f"Authorization failed for {repo_full_name}: {exc}")
    return RedirectResponse(url="/ui", status_code=302)


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

    # ── Redis (Upstash) ─────────────────────────────────────────────────
    try:
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url, socket_timeout=5)
        pong = r.ping()
        results["redis"] = {"status": "ok", "ping": pong}
    except Exception as e:
        results["redis"] = {"status": "error", "detail": str(e)}

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
        results["github"] = {"status": "ok", "login": login}
    except Exception as e:
        detail = str(e)
        if settings.github_token_is_placeholder:
            detail = f"{detail} | hint: GITHUB_TOKEN appears to be a placeholder."
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
    _verify_signature(body, x_hub_signature_256)
    payload = await request.json()
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
