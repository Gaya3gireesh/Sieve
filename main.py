"""Run Sentinel API with: `uv run main.py`."""

from __future__ import annotations

import os
import subprocess
import sys

import uvicorn

from app.config import get_settings


def _should_start_worker() -> bool:
    raw = os.getenv("START_WORKER", "true").strip().lower()
    return raw not in {"0", "false", "off", "no"}


def _start_worker() -> subprocess.Popen[str] | None:
    settings = get_settings()
    if not settings.use_celery_worker:
        return None
    if not _should_start_worker():
        return None

    cmd = [
        sys.executable,
        "-m",
        "celery",
        "-A",
        "app.worker.celery_app",
        "worker",
        "--loglevel=INFO",
        "--pool=solo",
    ]
    print("Starting Celery worker...", flush=True)
    return subprocess.Popen(cmd)


def _stop_worker(worker: subprocess.Popen[str] | None) -> None:
    if worker is None:
        return
    if worker.poll() is not None:
        return
    print("Stopping Celery worker...", flush=True)
    worker.terminate()
    try:
        worker.wait(timeout=10)
    except subprocess.TimeoutExpired:
        worker.kill()


def main() -> None:
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    reload_enabled = os.getenv("RELOAD", "false").strip().lower() == "true"
    worker = None
    try:
        if reload_enabled:
            print("RELOAD=true: skipping auto worker start.", flush=True)
        else:
            worker = _start_worker()
        uvicorn.run("app.main:app", host=host, port=port, reload=reload_enabled)
    finally:
        _stop_worker(worker)


if __name__ == "__main__":
    main()
