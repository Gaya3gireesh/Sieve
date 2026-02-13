"""
Sentinel — FastAPI entry point.

Handles GitHub webhooks and exposes a health-check endpoint.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, status

from app.config import get_settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
settings = get_settings()

# ── Lifespan ────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
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


# ── Routes ──────────────────────────────────────────────────────────────────


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

    # ── Supabase (PostgreSQL) ───────────────────────────────────────────
    try:
        from sqlalchemy import text
        from app.database import _get_engine
        import asyncio

        engine = _get_engine()

        async def _test_db():
            async with engine.connect() as conn:
                result = await conn.execute(text("SELECT 1"))
                return result.scalar()

        # Run the async DB check
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside FastAPI's event loop, use it directly
            val = await _test_db()
        else:
            val = asyncio.run(_test_db())

        results["supabase"] = {"status": "ok", "select_1": val}
    except Exception as e:
        results["supabase"] = {"status": "error", "detail": str(e)}

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

    # Only handle pull_request events
    if x_github_event != "pull_request":
        return {"message": f"Ignored event: {x_github_event}"}

    payload = await request.json()
    action = payload.get("action", "")

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
