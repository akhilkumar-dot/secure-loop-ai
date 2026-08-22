ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_tool_check;
ALTER TABLE findings ADD CONSTRAINT findings_tool_check CHECK (tool IN ('semgrep', 'zap', 'sast-rules', 'gemini-llm-heuristic'));
