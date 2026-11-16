-- Migration: 20261117_review3_learning_tables.sql
--
-- Review 3 schema additions:
--   1. Add tier, vuln_class, question_id, misconception_id to education_checks
--   2. Create recurring_misconceptions table
--   3. Create mastery_profiles table
--
-- Safe to re-run (uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. education_checks — add Review-3 columns
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE education_checks
  ADD COLUMN IF NOT EXISTS question_id    text,
  ADD COLUMN IF NOT EXISTS vuln_class     text CHECK (vuln_class IN ('sqli','xss','csrf','insecure_deserialization','other')),
  ADD COLUMN IF NOT EXISTS tier           text CHECK (tier IN ('easy','medium','hard')),
  ADD COLUMN IF NOT EXISTS misconception_id text;

-- Index for fast per-user per-class lookups (recurrence detection + tier check)
CREATE INDEX IF NOT EXISTS idx_education_checks_user_vulnclass
  ON education_checks (user_id, vuln_class, answered_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. recurring_misconceptions
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recurring_misconceptions (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  vuln_class              text NOT NULL,
  misconception_id        text NOT NULL,
  misconception_label     text NOT NULL,
  supporting_attempt_ids  text[] NOT NULL DEFAULT '{}',
  occurrences             integer NOT NULL DEFAULT 0,
  flagged_at              timestamptz NOT NULL DEFAULT now(),
  resolved_at             timestamptz,

  -- One live flag per user × misconception; upsert on conflict
  UNIQUE (user_id, misconception_id)
);

ALTER TABLE recurring_misconceptions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own recurring_misconceptions" ON recurring_misconceptions;
CREATE POLICY "Users manage own recurring_misconceptions" ON recurring_misconceptions
  FOR ALL USING (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_recurring_misconceptions_user_unresolved
  ON recurring_misconceptions (user_id, resolved_at)
  WHERE resolved_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. mastery_profiles — per-user per-vuln-class SM-2 tracking
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mastery_profiles (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  vuln_class          text NOT NULL CHECK (vuln_class IN ('sqli','xss','csrf','insecure_deserialization')),
  attempts_count      integer NOT NULL DEFAULT 0,
  correct_count       integer NOT NULL DEFAULT 0,
  tier_reached        text NOT NULL DEFAULT 'easy' CHECK (tier_reached IN ('easy','medium','hard')),
  next_review_at      timestamptz,
  interval_days       integer NOT NULL DEFAULT 1,
  ease_factor         numeric NOT NULL DEFAULT 2.5,
  last_reviewed_at    timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),

  UNIQUE (user_id, vuln_class)
);

ALTER TABLE mastery_profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own mastery_profiles" ON mastery_profiles;
CREATE POLICY "Users manage own mastery_profiles" ON mastery_profiles
  FOR ALL USING (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_mastery_profiles_user_next_review
  ON mastery_profiles (user_id, next_review_at)
  WHERE next_review_at IS NOT NULL;

