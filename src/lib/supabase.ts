import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://tzdlytanerwfadbqzhue.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR6ZGx5dGFuZXJ3ZmFkYnF6aHVlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODcyODIxNzMsImV4cCI6MjEwMjg1ODE3M30.0zhMPFzcPeL2dfWy90ZaZZ8nti8posjm1HPNbb3gu4c";

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
  patch_success_rate?: number;
  test_pass_rate?: number;
  vuln_removal_rate?: number;
  new_vulns_rate?: number;
  acceptance_rate?: number;
  time_to_fix_seconds?: number;
  created_at: string;
}

export interface DbFinding {
  id: string;
  scan_run_id: string;
  project_id: string;
  tool: "semgrep" | "zap";
  rule_id: string;
  cwe?: string;
  severity: "critical" | "high" | "medium" | "low";
  file_path: string;
  line_start?: number;
  line_end?: number;
  vulnerability_class?: "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";
  raw_message?: string;
  status: "open" | "explained" | "patched" | "validated" | "accepted" | "rejected";
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
  generated_at: string;
}

export interface DbPatch {
  id: string;
  finding_id: string;
  diff?: string;
  explanation_id?: string;
  model?: string;
  generated_at: string;
  validation_vulnerability_gone?: boolean;
  validation_tests_passed?: boolean;
  validation_new_issues: number;
  validation_logs?: string[];
  validation_validated_at?: string;
  validation_verdict?: "accepted" | "rejected";
  validation_failed_check?: string;
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
  computed_at: string;
}

export interface DbProfile {
  id: string;
  display_name?: string;
  github_token?: string;
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
