-- Create ai_cache table to store model outputs without keys
CREATE TABLE IF NOT EXISTS public.ai_cache (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  task TEXT NOT NULL,
  provider TEXT NOT NULL,
  model_id TEXT NOT NULL,
  output JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT ai_cache_user_finding_task_version UNIQUE (user_id, finding_id, prompt_version, task)
);

ALTER TABLE public.ai_cache ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can only read and manage their own ai_cache" ON public.ai_cache;
CREATE POLICY "Users can only read and manage their own ai_cache"
  ON public.ai_cache
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

