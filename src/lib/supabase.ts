import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = import.meta.env["VITE_SUPABASE_URL"] as string | undefined;
const SUPABASE_ANON_KEY = import.meta.env["VITE_SUPABASE_ANON_KEY"] as string | undefined;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error(
    "Missing Supabase configuration. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env file.",
  );
}

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Types matching our schema
export type { User, Session } from "@supabase/supabase-js";

export interface DbProject {
  id: string;
  owner_id: string;
  name: string;
  source_type: "git" | "zip";
  repo_url?: string;
  default_branch: string;
  last_scan_id?: string;
  created_at: string;
}

export interface DbScanRun {
  id: string;
  project_id: string;
  status: "queued" | "scanning" | "explaining" | "patching" | "validating" | "done" | "failed";
  started_at: string;
  finished_at?: string;
  commit_sha?: string;
  tools: string[];
  findings_count: number;
  /** patch_success_rate: diffs that applied / total patches */
  patch_success_rate?: number;
  /** syntax_pass_rate: patches with syntax_ok === true / total (renamed from test_pass_rate) */
  syntax_pass_rate?: number;
  /** vuln_removal_rate: patches with vulnerability_gone === true / total */
  vuln_removal_rate?: number;
  /** new_vulns_rate: patches with new_issues > 0 / total */
  new_vulns_rate?: number;
  /** acceptance_rate: developer-accepted / total (0 at scan time, updated after decisions) */
  acceptance_rate?: number;
  time_to_fix_seconds?: number;
  error_message?: string;
  created_at: string;
}

export interface DbFinding {
  id: string;
  scan_run_id: string;
  project_id: string;
  tool: "semgrep" | "zap" | "sast-rules" | "gemini-llm-heuristic";
  rule_id: string;
  cwe?: string;
  severity: "critical" | "high" | "medium" | "low";
  file_path: string;
  line_start?: number;
  line_end?: number;
  vulnerability_class?: "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";
  raw_message?: string;
  status:
    | "open"
    | "explained"
    | "patched"
    | "validated"
    | "accepted"
    | "rejected"
    | "likely_false_positive"
    | "dismissed";
  code_lines?: Array<{ n: number; code: string; vuln?: boolean }>;
  created_at: string;
}

export interface DbExplanation {
  id: string;
  finding_id: string;
  what_it_is?: string;
  why_it_happened?: string;
  owasp_category?: string;
  how_fix_works?: string;
  model?: string;
  confidence?: "high" | "medium" | "low" | "not_applicable";
  is_applicable?: boolean;
  error_type?: "false_positive" | "transient_error";
  generated_at: string;
}

export interface DbPatch {
  id: string;
  finding_id: string;
  diff?: string;
  explanation_id?: string;
  model?: string;
  generated_at: string;
  /** Deterministic: did the unified diff apply cleanly? */
  validation_diff_applies?: boolean;
  /** Deterministic (SAST): is the original rule_id absent from patched file? null = not checked (llm-heuristic) */
  validation_vulnerability_gone?: boolean | null;
  /** Deterministic: syntax check result. null = not checked (non-JS/TS) */
  validation_syntax_ok?: boolean | null;
  /** Count of NEW SAST findings introduced by the patch */
  validation_new_issues: number;
  /** "deterministic" = SAST re-scan was used; "llm-opinion" = used for llm-heuristic findings */
  validation_method?: "deterministic" | "llm-opinion";
  validation_logs?: string[];
  validation_validated_at?: string;
  validation_verdict?: "accepted" | "rejected";
  validation_failed_check?: string;
  /** Non-binding human-readable LLM review comment */
  validation_llm_review?: string;
}

export interface DbSecurityScore {
  id: string;
  project_id: string;
  user_id: string;
  overall: number;
  sqli: number;
  xss: number;
  csrf: number;
  deserialization: number;
  /** Covers command injection, path traversal, hardcoded secrets, session misconfig */
  other: number;
  computed_at: string;
}

export interface DbProfile {
  id: string;
  display_name?: string;
  /** @deprecated Use github_token_enc. Plaintext token — to be removed after migration. */
  github_token?: string;
  /** @deprecated Use ai_api_key_enc. Plaintext key — to be removed after migration. */
  gemini_api_key?: string;
  llm_provider: string;
  created_at: string;
  updated_at: string;
}

export interface DbDeveloperDecision {
  id: string;
  patch_id: string;
  user_id: string;
  action: "accept" | "reject";
  is_override: boolean;
  decided_at: string;
}

export interface DbEducationCheck {
  id: string;
  finding_id: string;
  user_id: string;
  question: string;
  options: string[];
  correct_index: number;
  user_answer?: number;
  correct?: boolean;
  answered_at?: string;
}
