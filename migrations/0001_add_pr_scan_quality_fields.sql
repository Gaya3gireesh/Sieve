-- Sentinel schema update
-- Adds deep-analysis columns used by worker persistence.

ALTER TABLE pr_scans
ADD COLUMN IF NOT EXISTS quality_score DOUBLE PRECISION;

ALTER TABLE pr_scans
ADD COLUMN IF NOT EXISTS quality_issues JSON;
