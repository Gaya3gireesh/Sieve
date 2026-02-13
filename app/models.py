"""
Sentinel — SQLAlchemy models.

Defines the PRScan table that records every pull-request analysis.
"""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


# ── Base class ──────────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    """Shared declarative base for all models."""


# ── Enums ───────────────────────────────────────────────────────────────────


class Verdict(str, enum.Enum):
    """Possible outcomes of a Sentinel scan."""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    SOFT_FAIL = "soft_fail"


# ── Models ──────────────────────────────────────────────────────────────────


class PRScan(Base):
    """One row per pull-request scan."""

    __tablename__ = "pr_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # ── PR metadata ──
    repo_full_name = Column(String(256), nullable=False, index=True)
    pr_number = Column(Integer, nullable=False)
    pr_author = Column(String(128), nullable=False)
    pr_title = Column(String(512), nullable=False)
    pr_url = Column(String(1024), nullable=False)

    # ── Analysis scores ──
    author_account_age_days = Column(Integer, nullable=True)
    spam_score = Column(Float, nullable=True)
    effort_score = Column(Float, nullable=True)
    signal_to_noise_ratio = Column(Float, nullable=True)

    # ── Verdict ──
    verdict = Column(
        Enum(Verdict, name="verdict_enum"),
        nullable=False,
        default=Verdict.PENDING,
    )
    verdict_reason = Column(Text, nullable=True)
    policy_violations = Column(JSON, nullable=True)  # list of violation dicts

    # ── Timestamps ──
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<PRScan {self.repo_full_name}#{self.pr_number} "
            f"verdict={self.verdict}>"
        )
