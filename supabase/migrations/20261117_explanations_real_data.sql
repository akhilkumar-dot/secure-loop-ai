-- Add columns to findings and explanations for real Semgrep scan inputs and structured explanations
ALTER TABLE public.findings ADD COLUMN IF NOT EXISTS matched_text TEXT;

ALTER TABLE public.explanations 
  ADD COLUMN IF NOT EXISTS attack_idea TEXT,
  ADD COLUMN IF NOT EXISTS key_takeaway TEXT,
  ADD COLUMN IF NOT EXISTS likely_false_positive BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS false_positive_reason TEXT,
  ADD COLUMN IF NOT EXISTS confidence_note TEXT,
  ADD COLUMN IF NOT EXISTS raw_explanation JSONB;

