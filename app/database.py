"""
Sentinel — Async database engine & session factory.

Uses SQLAlchemy async with asyncpg for Supabase (PostgreSQL).
Engine creation is deferred until first use so the app can start
even if the database is temporarily unreachable.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings


_engine = None
_session_factory = None


def _get_engine():
    """Lazily create the async engine on first call."""
    global _engine
    if _engine is None:
        settings = get_settings()
        if not settings.supabase_uses_postgres:
            raise RuntimeError(
                "SUPABASE_URL is configured as HTTPS project URL. "
                "SQLAlchemy engine requires PostgreSQL DSN mode."
            )
        _engine = create_async_engine(
            settings.supabase_url,
            echo=False,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
    return _engine


def _get_session_factory():
    """Lazily create the session factory on first call."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            _get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def get_db() -> AsyncSession:  # type: ignore[misc]
    """FastAPI dependency — yields a transactional async session."""
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
