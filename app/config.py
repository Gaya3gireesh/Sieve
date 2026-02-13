"""
Sentinel — Configuration via pydantic-settings.

Loads all secrets and config from environment variables (or .env file).
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Supabase / PostgreSQL ──
    supabase_url: str  # e.g. postgresql+asyncpg://user:pass@host:5432/db
    supabase_key: str

    # ── Groq (Llama-3-70b) ──
    groq_api_key: str

    # ── Upstash Redis ──
    redis_url: str  # e.g. rediss://default:xxx@endpoint.upstash.io:6379

    # ── GitHub ──
    github_webhook_secret: str
    github_token: str

    # ── Tuning knobs (sensible defaults) ──
    spam_threshold: float = 0.7
    effort_snr_threshold: float = 0.10  # 10 % signal-to-noise minimum
    groq_model: str = "llama-3.3-70b-versatile"
    max_diff_chunk_tokens: int = 6000  # leave headroom within 8 K window


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton of the app settings."""
    return Settings()  # type: ignore[call-arg]
