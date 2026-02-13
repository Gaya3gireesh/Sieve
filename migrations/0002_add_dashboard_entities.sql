-- Sentinel schema expansion for owner dashboard + richer PR analysis records.
-- Safe to run multiple times.

CREATE TABLE IF NOT EXISTS sentinel_users (
    id BIGSERIAL PRIMARY KEY,
    github_user_id BIGINT NOT NULL UNIQUE,
    github_login VARCHAR(128) NOT NULL UNIQUE,
    access_token_encrypted TEXT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_sentinel_users_github_user_id ON sentinel_users (github_user_id);
CREATE INDEX IF NOT EXISTS ix_sentinel_users_github_login ON sentinel_users (github_login);
CREATE INDEX IF NOT EXISTS ix_sentinel_users_is_active ON sentinel_users (is_active);

CREATE TABLE IF NOT EXISTS repositories (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NULL,
    github_repo_id BIGINT NOT NULL UNIQUE,
    full_name VARCHAR(256) NOT NULL,
    installation_id BIGINT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS github_repo_id BIGINT,
    ADD COLUMN IF NOT EXISTS full_name VARCHAR(256),
    ADD COLUMN IF NOT EXISTS installation_id BIGINT,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS owner_user_id BIGINT NULL;

CREATE INDEX IF NOT EXISTS ix_repositories_owner_user_id ON repositories (owner_user_id);
CREATE INDEX IF NOT EXISTS ix_repositories_github_repo_id ON repositories (github_repo_id);
CREATE INDEX IF NOT EXISTS ix_repositories_full_name ON repositories (full_name);
CREATE INDEX IF NOT EXISTS ix_repositories_installation_id ON repositories (installation_id);
CREATE INDEX IF NOT EXISTS ix_repositories_is_active ON repositories (is_active);

ALTER TABLE pr_scans
    ADD COLUMN IF NOT EXISTS repo_full_name VARCHAR(256),
    ADD COLUMN IF NOT EXISTS pr_author VARCHAR(128),
    ADD COLUMN IF NOT EXISTS pr_title VARCHAR(512),
    ADD COLUMN IF NOT EXISTS pr_url VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS author_account_age_days INTEGER,
    ADD COLUMN IF NOT EXISTS spam_score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS signal_to_noise_ratio DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS quality_score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS quality_issues JSONB,
    ADD COLUMN IF NOT EXISTS verdict VARCHAR(32),
    ADD COLUMN IF NOT EXISTS verdict_reason TEXT,
    ADD COLUMN IF NOT EXISTS policy_violations JSONB,
    ADD COLUMN IF NOT EXISTS repository_id BIGINT NULL,
    ADD COLUMN IF NOT EXISTS is_spam BOOLEAN NULL,
    ADD COLUMN IF NOT EXISTS spam_reason TEXT NULL,
    ADD COLUMN IF NOT EXISTS issue_number INTEGER NULL,
    ADD COLUMN IF NOT EXISTS issue_aligned BOOLEAN NULL,
    ADD COLUMN IF NOT EXISTS issue_alignment_score DOUBLE PRECISION NULL,
    ADD COLUMN IF NOT EXISTS issue_alignment_reason TEXT NULL,
    ADD COLUMN IF NOT EXISTS description_match BOOLEAN NULL,
    ADD COLUMN IF NOT EXISTS description_match_score DOUBLE PRECISION NULL,
    ADD COLUMN IF NOT EXISTS description_match_reason TEXT NULL;

UPDATE pr_scans
SET
    pr_title = COALESCE(pr_title, title),
    repo_full_name = COALESCE(repo_full_name, ''),
    verdict = COALESCE(
        verdict,
        CASE
            WHEN LOWER(COALESCE(status, '')) IN ('pending', 'queued') THEN 'pending'
            WHEN LOWER(COALESCE(status, '')) IN ('passed', 'approved', 'reviewed') THEN 'passed'
            WHEN LOWER(COALESCE(status, '')) IN ('failed', 'rejected', 'closed') THEN 'failed'
            WHEN LOWER(COALESCE(status, '')) IN ('soft_fail', 'needs_clarification') THEN 'soft_fail'
            WHEN LOWER(COALESCE(spam_verdict, '')) IN ('spam', 'slop') THEN 'failed'
            ELSE 'pending'
        END
    );

CREATE INDEX IF NOT EXISTS ix_pr_scans_repository_id ON pr_scans (repository_id);
CREATE INDEX IF NOT EXISTS ix_pr_scans_issue_number ON pr_scans (issue_number);
CREATE INDEX IF NOT EXISTS ix_pr_scans_is_spam ON pr_scans (is_spam);
CREATE INDEX IF NOT EXISTS ix_pr_scans_repo_full_name ON pr_scans (repo_full_name);
CREATE INDEX IF NOT EXISTS ix_pr_scans_verdict ON pr_scans (verdict);
