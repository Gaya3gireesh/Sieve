-- Per-repository webhook credentials for plug-and-play OAuth onboarding.
-- Safe to run multiple times.

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS webhook_id BIGINT NULL,
    ADD COLUMN IF NOT EXISTS webhook_secret_encrypted TEXT NULL;

CREATE INDEX IF NOT EXISTS ix_repositories_webhook_id ON repositories (webhook_id);
