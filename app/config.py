"""
Sentinel — Configuration via pydantic-settings.

Loads all secrets and config from environment variables (or .env file).
"""

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Supabase ──
    # Supports either:
    # 1) PostgreSQL DSN: postgresql+asyncpg://...
    # 2) Project URL: https://<project-ref>.supabase.co
    supabase_url: str
    supabase_key: str

    # ── Groq (Llama-3-70b) ──
    groq_api_key: str

    # ── Upstash Redis ──
    redis_url: str  # e.g. rediss://default:xxx@endpoint.upstash.io:6379

    # ── GitHub ──
    github_webhook_secret: str
    github_token: str
    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""

    # ── Tuning knobs (sensible defaults) ──
    spam_threshold: float = 0.7
    effort_snr_threshold: float = 0.10  # 10 % signal-to-noise minimum
    groq_model: str = "llama-3.3-70b-versatile"
    max_diff_chunk_tokens: int = 6000  # leave headroom within 8 K window
    quality_soft_fail_threshold: float = 0.55
    quality_fail_threshold: float = 0.35
    vague_description_min_chars: int = 40
    supabase_http_timeout_sec: float = 6.0
    supabase_probe_rest_table: bool = False
    public_base_url: str = "http://127.0.0.1:8000"
    ui_session_secret: str = "sentinel-dev-session-secret"

    @model_validator(mode="after")
    def validate_supabase_url(self) -> "Settings":
        """Allow Supabase PostgreSQL DSN or HTTPS project URL."""
        parsed = urlparse(self.supabase_url)
        if parsed.scheme in ("http", "https"):
            if not parsed.netloc:
                raise ValueError("SUPABASE_URL must be a valid HTTPS URL.")
            if not self.supabase_key:
                raise ValueError("SUPABASE_KEY is required when using HTTPS SUPABASE_URL.")
            return self

        if parsed.scheme.startswith("postgresql"):
            if not parsed.netloc:
                raise ValueError("SUPABASE_URL PostgreSQL DSN is invalid.")
            return self

        raise ValueError(
            "SUPABASE_URL must be either a PostgreSQL DSN or an HTTPS Supabase project URL."
        )

    @property
    def supabase_uses_postgres(self) -> bool:
        parsed = urlparse(self.supabase_url)
        return parsed.scheme.startswith("postgresql")

    @property
    def supabase_rest_base_url(self) -> str:
        parsed = urlparse(self.supabase_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                "SUPABASE_URL is not an HTTPS project URL; REST endpoint is unavailable."
            )
        return self.supabase_url.rstrip("/")

    @property
    def github_token_is_placeholder(self) -> bool:
        """Best-effort detection of obvious placeholder tokens."""
        token = self.github_token.strip().lower()
        markers = (
            "your_personal_access",
            "ghp_your",
            "placeholder",
            "test_token",
            "test-token",
        )
        return any(marker in token for marker in markers)

    @property
    def supabase_key_is_publishable(self) -> bool:
        """True when key likely cannot write to DB tables."""
        return self.supabase_key.strip().lower().startswith("sb_publishable_")

    @property
    def github_oauth_enabled(self) -> bool:
        return bool(
            self.github_oauth_client_id.strip()
            and self.github_oauth_client_secret.strip()
        )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton of the app settings."""
    return Settings()  # type: ignore[call-arg]
