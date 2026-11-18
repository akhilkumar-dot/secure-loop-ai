-- Migration: decision actions enhancements
-- Adds false_positive_suppressions table and extra columns on developer_decisions

-- ── false_positive_suppressions ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS false_positive_suppressions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  project_id          uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id          uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  rule_id             text,
  file_path           text NOT NULL,
  line_start          integer,
  vulnerability_class text,
  -- reason_code is one of: test_code | not_exploitable | accepted_risk | wrong_detection | other
  reason_code         text NOT NULL,
  reason_text         text,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- Allow the authenticated user to manage their own suppressions
ALTER TABLE false_positive_suppressions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own suppressions"
  ON false_positive_suppressions
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- ── developer_decisions columns ───────────────────────────────────────────
-- Add rejection_note and validation_was_rejected if they don't exist yet
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'developer_decisions' AND column_name = 'rejection_note'
  ) THEN
    ALTER TABLE developer_decisions ADD COLUMN rejection_note text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'developer_decisions' AND column_name = 'validation_was_rejected'
  ) THEN
    ALTER TABLE developer_decisions ADD COLUMN validation_was_rejected boolean NOT NULL DEFAULT false;
  END IF;
END $$;

