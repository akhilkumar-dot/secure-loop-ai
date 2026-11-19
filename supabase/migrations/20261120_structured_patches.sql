-- Migration: 20261120_structured_patches.sql
-- Adds structured patch fields to store start_line, end_line, original_code, replacement_code, behavior_note, is_valid, and invalid_reason.

ALTER TABLE patches 
  ADD COLUMN IF NOT EXISTS start_line integer,
  ADD COLUMN IF NOT EXISTS end_line integer,
  ADD COLUMN IF NOT EXISTS original_code text,
  ADD COLUMN IF NOT EXISTS replacement_code text,
  ADD COLUMN IF NOT EXISTS behavior_note text,
  ADD COLUMN IF NOT EXISTS is_valid boolean,
  ADD COLUMN IF NOT EXISTS invalid_reason text;

