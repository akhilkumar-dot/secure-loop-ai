-- Migration: 20261005_full_schema_rls.sql
--
-- Full schema definition with RLS policies and CASCADE foreign keys.
-- This is the canonical source of truth for the database structure.
-- Safe to run idempotently (uses IF NOT EXISTS / CREATE OR REPLACE).

-- ─────────────────────────────────────────────────────────────────────────────
-- Enable UUID generation
-- ─────────────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────────────────────
-- profiles (one per auth.users row — created by trigger or on first login)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS profiles (
  id              uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name    text,
  github_token    text,           -- plaintext (deprecated — see migration note below)
  gemini_api_key  text,           -- plaintext (deprecated)
  llm_provider    text NOT NULL DEFAULT 'gemini',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
-- NOTE: github_token and gemini_api_key will be encrypted in a future migration
-- (§3 of the refactor plan). Columns will be renamed to github_token_enc / ai_api_key_enc.

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own profile" ON profiles;
CREATE POLICY "Users manage own profile" ON profiles
  FOR ALL USING (auth.uid() = id);

-- ─────────────────────────────────────────────────────────────────────────────
-- projects
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id        uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name            text NOT NULL,
  source_type     text NOT NULL CHECK (source_type IN ('git', 'zip')),
  repo_url        text,
  default_branch  text NOT NULL DEFAULT 'main',
  last_scan_id    uuid,
  created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Owners manage own projects" ON projects;
CREATE POLICY "Owners manage own projects" ON projects
  FOR ALL USING (owner_id = auth.uid());

-- ─────────────────────────────────────────────────────────────────────────────
-- scan_runs
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_runs (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id            uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status                text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','scanning','explaining','patching','validating','done','failed')),
  started_at            timestamptz NOT NULL DEFAULT now(),
  finished_at           timestamptz,
  commit_sha            text,
  tools                 text[] NOT NULL DEFAULT '{}',
  findings_count        integer NOT NULL DEFAULT 0,
  -- Metrics (computed after scan; 0.0–1.0 fractions)
  patch_success_rate    numeric,   -- diffs that applied / total
  syntax_pass_rate      numeric,   -- syntax_ok === true / total (was test_pass_rate)
  vuln_removal_rate     numeric,   -- vulnerability_gone === true / total
  new_vulns_rate        numeric,   -- patches with new_issues > 0 / total
  acceptance_rate       numeric,   -- developer-accepted / total (updated after decisions)
  time_to_fix_seconds   integer,
  error_message         text,
  created_at            timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Project owners access scan_runs" ON scan_runs;
CREATE POLICY "Project owners access scan_runs" ON scan_runs
  FOR ALL USING (
    project_id IN (SELECT id FROM projects WHERE owner_id = auth.uid())
  );

-- ─────────────────────────────────────────────────────────────────────────────
-- findings
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_run_id          uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  project_id           uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  tool                 text NOT NULL
    CHECK (tool IN ('semgrep','zap','sast-rules','gemini-llm-heuristic')),
  rule_id              text NOT NULL,
  cwe                  text,
  severity             text NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  file_path            text NOT NULL,
  line_start           integer,
  line_end             integer,
  vulnerability_class  text CHECK (vulnerability_class IN ('sqli','xss','csrf','insecure_deserialization','other')),
  raw_message          text,
  status               text NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','explained','patched','validated','accepted','rejected','likely_false_positive','dismissed')),
  code_lines           jsonb,
  created_at           timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Project owners access findings" ON findings;
CREATE POLICY "Project owners access findings" ON findings
  FOR ALL USING (
    project_id IN (SELECT id FROM projects WHERE owner_id = auth.uid())
  );

-- ─────────────────────────────────────────────────────────────────────────────
-- explanations
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS explanations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  what_it_is      text,
  why_it_happened text,
  owasp_category  text,
  how_fix_works   text,
  model           text,
  confidence      text CHECK (confidence IN ('high','medium','low','not_applicable')),
  is_applicable   boolean,
  error_type      text CHECK (error_type IN ('false_positive','transient_error')),
  generated_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE explanations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Project owners access explanations" ON explanations;
CREATE POLICY "Project owners access explanations" ON explanations
  FOR ALL USING (
    finding_id IN (
      SELECT id FROM findings
      WHERE project_id IN (SELECT id FROM projects WHERE owner_id = auth.uid())
    )
  );

-- ─────────────────────────────────────────────────────────────────────────────
-- patches
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS patches (
  id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id                  uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  diff                        text,
  explanation_id              uuid REFERENCES explanations(id) ON DELETE SET NULL,
  model                       text,
  generated_at                timestamptz NOT NULL DEFAULT now(),
  -- Deterministic validation fields
  validation_diff_applies     boolean,
  validation_vulnerability_gone boolean,
  validation_syntax_ok        boolean,
  validation_new_issues       integer NOT NULL DEFAULT 0,
  validation_method           text CHECK (validation_method IN ('deterministic','llm-opinion')),
  validation_llm_review       text,
  -- Legacy / shared validation fields
  validation_logs             text[],
  validation_validated_at     timestamptz,
  validation_verdict          text CHECK (validation_verdict IN ('accepted','rejected')),
  validation_failed_check     text
);

ALTER TABLE patches ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Project owners access patches" ON patches;
CREATE POLICY "Project owners access patches" ON patches
  FOR ALL USING (
    finding_id IN (
      SELECT id FROM findings
      WHERE project_id IN (SELECT id FROM projects WHERE owner_id = auth.uid())
    )
  );

-- ─────────────────────────────────────────────────────────────────────────────
-- developer_decisions
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS developer_decisions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  patch_id    uuid NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action      text NOT NULL CHECK (action IN ('accept','reject')),
  is_override boolean NOT NULL DEFAULT false,
  decided_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE developer_decisions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own decisions" ON developer_decisions;
CREATE POLICY "Users manage own decisions" ON developer_decisions
  FOR ALL USING (user_id = auth.uid());

-- ─────────────────────────────────────────────────────────────────────────────
-- education_checks
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS education_checks (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id    uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  question      text NOT NULL,
  options       text[] NOT NULL,
  correct_index integer NOT NULL,
  user_answer   integer,
  correct       boolean,
  answered_at   timestamptz
);

ALTER TABLE education_checks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own education_checks" ON education_checks;
CREATE POLICY "Users manage own education_checks" ON education_checks
  FOR ALL USING (user_id = auth.uid());

-- ─────────────────────────────────────────────────────────────────────────────
-- security_scores
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_scores (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id      uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  overall         numeric NOT NULL,
  sqli            numeric NOT NULL,
  xss             numeric NOT NULL,
  csrf            numeric NOT NULL,
  deserialization numeric NOT NULL,
  other           numeric NOT NULL DEFAULT 100,
  computed_at     timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE security_scores ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Project owners access security_scores" ON security_scores;
CREATE POLICY "Project owners access security_scores" ON security_scores
  FOR ALL USING (
    project_id IN (SELECT id FROM projects WHERE owner_id = auth.uid())
  );
