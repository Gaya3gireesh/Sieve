"""
Sentinel — SQLAlchemy models.

Defines database tables for pull-request scans and GitHub App repositories.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
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

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    # ── PR metadata ──
    repo_full_name = Column(String(256), nullable=False, index=True)
    pr_number = Column(Integer, nullable=False)
    pr_author = Column(String(128), nullable=False)
    pr_title = Column(String(512), nullable=False)
    pr_url = Column(String(1024), nullable=False)
    repository_id = Column(BigInteger, ForeignKey("repositories.id"), nullable=True, index=True)

    # ── Analysis scores ──
    author_account_age_days = Column(Integer, nullable=True)
    spam_score = Column(Float, nullable=True)
    is_spam = Column(Boolean, nullable=True)
    spam_reason = Column(Text, nullable=True)
    effort_score = Column(Float, nullable=True)
    signal_to_noise_ratio = Column(Float, nullable=True)
    issue_number = Column(Integer, nullable=True)
    issue_aligned = Column(Boolean, nullable=True)
    issue_alignment_score = Column(Float, nullable=True)
    issue_alignment_reason = Column(Text, nullable=True)
    description_match = Column(Boolean, nullable=True)
    description_match_score = Column(Float, nullable=True)
    description_match_reason = Column(Text, nullable=True)
    quality_score = Column(Float, nullable=True)
    quality_issues = Column(JSON, nullable=True)

    # ── Verdict ──
    verdict = Column(
        Enum(Verdict, name="verdict_enum", native_enum=False),
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


class Repository(Base):
    """One row per GitHub repository connected through App installation."""

    __tablename__ = "repositories"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    owner_user_id = Column(BigInteger, ForeignKey("sentinel_users.id"), nullable=True, index=True)
    github_repo_id = Column(BigInteger, nullable=False, unique=True, index=True)
    full_name = Column(String(256), nullable=False, index=True)
    installation_id = Column(BigInteger, nullable=False, index=True)
    webhook_id = Column(BigInteger, nullable=True, index=True)
    webhook_secret_encrypted = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
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
            f"<Repository {self.full_name} repo_id={self.github_repo_id} "
            f"installation_id={self.installation_id} active={self.is_active}>"
        )


class User(Base):
    """One row per repository-owner user connected via GitHub OAuth."""

    __tablename__ = "sentinel_users"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    github_user_id = Column(BigInteger, nullable=False, unique=True, index=True)
    github_login = Column(String(128), nullable=False, unique=True, index=True)
    access_token_encrypted = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
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
        return f"<User {self.github_login} github_user_id={self.github_user_id}>"
