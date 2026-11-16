-- Migration: add ai_api_key column to profiles
-- Users can save their Gemini / OpenRouter / OpenAI key once in Settings
-- and have it auto-loaded on every scan page (never stored in the client bundle).
--
-- The column is text (nullable). RLS on profiles already restricts each user
-- to their own row, so no additional policy is needed.

ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS ai_api_key text DEFAULT NULL;

COMMENT ON COLUMN profiles.ai_api_key IS
  'User-supplied AI API key (Gemini / OpenRouter / OpenAI). '
  'Stored server-side under the user''s own RLS-protected row. '
  'Never exposed in the client bundle or to other users.';

