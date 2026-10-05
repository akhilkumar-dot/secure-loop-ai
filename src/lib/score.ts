/**
 * src/lib/score.ts
 *
 * Security score computation and persistence.
 * Moved here from scan.$projectId.tsx so it can be called both at end-of-scan
 * and after every developer accept/reject decision.
 *
 * Score categories:
 *   sqli          CWE-89, CWE-943
 *   xss           CWE-79
 *   csrf          CWE-352
 *   deserialization CWE-502
 *   other         CWE-78 (command injection), CWE-22 (path traversal),
 *                 CWE-798 (hardcoded secrets), CWE-614/1004/331/400 (session)
 */

import { supabase } from "./supabase";

export interface ScoreBreakdown {
  overall: number;
  sqli: number;
  xss: number;
  csrf: number;
  deserialization: number;
  other: number;
}

type FindingRow = {
  vulnerability_class?: string | null;
  cwe?: string | null;
  severity?: string | null;
  status?: string | null;
  patches?: Array<{ validation_verdict?: string | null }> | null;
};

/** Severity weight for deduction (lower score = worse) */
const SEVERITY_DEDUCTION: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

/** CWE → score category override (when vulnerability_class is "other" or missing) */
function cweToCategory(cwe: string | null | undefined): string {
  if (!cwe) return "other";
  if (cwe.startsWith("CWE-89") || cwe.startsWith("CWE-943")) return "sqli";
  if (cwe.startsWith("CWE-79")) return "xss";
  if (cwe.startsWith("CWE-352")) return "csrf";
  if (cwe.startsWith("CWE-502")) return "deserialization";
  return "other";
}

function findingCategory(f: FindingRow): string {
  const vc = f.vulnerability_class;
  if (vc && vc !== "other") return vc === "insecure_deserialization" ? "deserialization" : vc;
  return cweToCategory(f.cwe);
}

/**
 * Compute a security score from a list of findings (with optional patch join).
 *
 * Rules:
 *  - Start each category at 100.
 *  - For each OPEN finding (not developer-accepted, not dismissed):
 *      deduct SEVERITY_DEDUCTION[severity] from that category.
 *  - Findings where the developer accepted (status="accepted") OR
 *    validation_verdict="accepted" AND status not "rejected" do NOT deduct.
 *  - Floor each category at 0.
 *  - Overall = average of all five categories.
 */
export function computeScore(findings: FindingRow[]): ScoreBreakdown {
  const deductions: Record<string, number> = {
    sqli: 0,
    xss: 0,
    csrf: 0,
    deserialization: 0,
    other: 0,
  };

  for (const f of findings) {
    // Skip dismissed or developer-accepted findings
    if (f.status === "dismissed" || f.status === "accepted") continue;

    // Check if patch was validated+accepted (auto-accepted by AI and not overridden)
    const patchArr = Array.isArray(f.patches) ? f.patches : f.patches ? [f.patches] : [];
    const patchVerdict = patchArr[0]?.validation_verdict;
    // If AI accepted AND developer has not yet decided, still show as finding until developer acts
    // Only reduce deduction if developer explicitly accepted
    if (f.status === "accepted") continue;

    const cat = findingCategory(f);
    const deduction = SEVERITY_DEDUCTION[f.severity ?? "low"] ?? 3;
    deductions[cat] = (deductions[cat] ?? 0) + deduction;
    void patchVerdict; // used for future per-category crediting
  }

  const sqli = Math.max(0, 100 - (deductions["sqli"] ?? 0));
  const xss = Math.max(0, 100 - (deductions["xss"] ?? 0));
  const csrf = Math.max(0, 100 - (deductions["csrf"] ?? 0));
  const deserialization = Math.max(0, 100 - (deductions["deserialization"] ?? 0));
  const other = Math.max(0, 100 - (deductions["other"] ?? 0));
  const overall = Math.round((sqli + xss + csrf + deserialization + other) / 5);

  return { overall, sqli, xss, csrf, deserialization, other };
}

/**
 * Recompute the score for a project and insert a new security_scores row.
 * Call this (a) at the end of a scan and (b) after every developer accept/reject.
 */
export async function recomputeScore(projectId: string, userId: string): Promise<ScoreBreakdown> {
  // Fetch all findings for the project with their patch verdicts
  const { data: findings, error } = await supabase
    .from("findings")
    .select("vulnerability_class, cwe, severity, status, patches(validation_verdict)")
    .eq("project_id", projectId);

  if (error) {
    console.error("[score] Failed to fetch findings for score computation:", error);
    return { overall: 0, sqli: 0, xss: 0, csrf: 0, deserialization: 0, other: 0 };
  }

  const score = computeScore((findings ?? []) as FindingRow[]);

  await supabase.from("security_scores").insert({
    project_id: projectId,
    user_id: userId,
    overall: score.overall,
    sqli: score.sqli,
    xss: score.xss,
    csrf: score.csrf,
    deserialization: score.deserialization,
    other: score.other,
    computed_at: new Date().toISOString(),
  });

  return score;
}
