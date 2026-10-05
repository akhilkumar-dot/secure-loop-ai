-- Migration: 20261005_validation_columns.sql
-- Adds deterministic validation columns to patches, renames test_pass_rate to syntax_pass_rate,
-- adds error_message to scan_runs, and adds other category to security_scores.
--
-- Run this migration BEFORE deploying the updated application code.

-- ── patches table: new validation columns ─────────────────────────────────
ALTER TABLE patches
  ADD COLUMN IF NOT EXISTS validation_diff_applies   boolean,
  ADD COLUMN IF NOT EXISTS validation_syntax_ok      boolean,
  ADD COLUMN IF NOT EXISTS validation_method         text
    CHECK (validation_method IN ('deterministic', 'llm-opinion')),
  ADD COLUMN IF NOT EXISTS validation_llm_review     text;

-- ── scan_runs: rename test_pass_rate → syntax_pass_rate, add error_message ──
-- NOTE: Supabase/PostgreSQL does not support RENAME COLUMN in all versions.
-- If your version is >= 12 the following works; otherwise add a new column.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='scan_runs' AND column_name='test_pass_rate'
  ) THEN
    ALTER TABLE scan_runs RENAME COLUMN test_pass_rate TO syntax_pass_rate;
  END IF;
END $$;

ALTER TABLE scan_runs
  ADD COLUMN IF NOT EXISTS syntax_pass_rate   numeric,
  ADD COLUMN IF NOT EXISTS error_message      text;

-- ── security_scores: add other category ────────────────────────────────────
ALTER TABLE security_scores
  ADD COLUMN IF NOT EXISTS other numeric NOT NULL DEFAULT 100;
