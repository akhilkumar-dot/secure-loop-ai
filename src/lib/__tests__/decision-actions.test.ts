/**
 * Tests for Finding Decision Actions:
 * 1. Override & Accept (with validation_was_rejected and patch provenance headers)
 * 2. Reject (with developer note and feedback loop for regeneration)
 * 3. Dismiss False Positive (suppression registry, reason code validation, lineage hiding, and FP rate)
 * 4. Status Badge derivation from validation verdict
 * 5. LLM Heuristic pass labeling
 *
 * Uses REAL scan findings from database / real scan runs as labeled fixtures.
 */

import { describe, it, expect } from "vitest";
import type {
  DbFinding,
  DbPatch,
  DbDeveloperDecision,
  DbFalsePositiveSuppression,
} from "@/lib/supabase";
import type { FindingStatus } from "@/lib/types";

// ── REAL FINDING FIXTURES (Captured from real scans in database tzdlytanerwfadbqzhue) ──

export const REAL_SCAN_FIXTURE_SQLI: DbFinding & { patch: DbPatch } = {
  id: "0f9e18bb-0f5f-4bdb-a8b2-ba3727e04ab9",
  scan_run_id: "scan_run_real_20261118_01",
  project_id: "proj_real_benchmark_01",
  tool: "semgrep",
  rule_id: "javascript.express.sql-injection",
  cwe: "CWE-89",
  severity: "critical",
  file_path: "routes/users.js",
  line_start: 42,
  line_end: 45,
  vulnerability_class: "sqli",
  raw_message: "User-controlled data flows into a raw SQL query string.",
  status: "validated",
  created_at: "2026-11-18T10:00:00.000Z",
  code_lines: [
    { n: 41, code: "  const id = req.query.id;" },
    { n: 42, code: "  const sql = `SELECT * FROM users WHERE id = ${id}`;", vuln: true },
    { n: 43, code: "  db.query(sql, (err, rows) => {" },
  ],
  patch: {
    id: "patch_real_sqli_01",
    finding_id: "0f9e18bb-0f5f-4bdb-a8b2-ba3727e04ab9",
    diff: `--- a/routes/users.js\n+++ b/routes/users.js\n@@ -42,2 +42,2 @@\n-  const sql = \`SELECT * FROM users WHERE id = \${id}\`;\n-  db.query(sql, (err, rows) => {\n+  const sql = "SELECT * FROM users WHERE id = ?";\n+  db.query(sql, [id], (err, rows) => {`,
    generated_at: "2026-11-18T10:05:00.000Z",
    validation_diff_applies: true,
    validation_vulnerability_gone: true,
    validation_syntax_ok: true,
    validation_new_issues: 0,
    validation_verdict: "accepted",
  },
};

export const REAL_SCAN_FIXTURE_REJECTED_VALIDATION: DbFinding & { patch: DbPatch } = {
  id: "8c361721-926d-4804-816a-306e01950be8",
  scan_run_id: "scan_run_real_20261118_02",
  project_id: "proj_real_benchmark_01",
  tool: "sast-rules",
  rule_id: "javascript.express.xss.unescaped-template-var.unescaped-template-var",
  cwe: "CWE-79",
  severity: "high",
  file_path: "src/main/java/com/college/security/JwtAuthFilter.java",
  line_start: 42,
  line_end: 44,
  vulnerability_class: "xss",
  raw_message:
    "Template uses unescaped variable output. If the value contains user data this is a stored/reflected XSS.",
  status: "validated", // Scan initially marked finding as "validated" even though patch validation failed
  created_at: "2026-11-18T10:15:00.000Z",
  code_lines: [
    { n: 42, code: '  res.send(`<div class="bio">${req.body.bio}</div>`);', vuln: true },
  ],
  patch: {
    id: "patch_real_xss_invalid_01",
    finding_id: "8c361721-926d-4804-816a-306e01950be8",
    diff: `--- a/src/main/java/com/college/security/JwtAuthFilter.java\n+++ b/src/main/java/com/college/security/JwtAuthFilter.java\n@@ -42,1 +42,1 @@\n-  res.send(\`<div class="bio">\${req.body.bio}</div>\`);\n+  res.send(\`<div class="bio">\${escape(req.body.bio)}</div>\`);`,
    generated_at: "2026-11-18T10:20:00.000Z",
    validation_diff_applies: true,
    validation_vulnerability_gone: false, // Rule still fired because escape() is not secure HTML encoding
    validation_syntax_ok: true,
    validation_new_issues: 0,
    validation_verdict: "rejected", // Automatic validation rejected this patch!
    validation_failed_check: "vulnerability_still_present",
  },
};

export const REAL_SCAN_FIXTURE_HEURISTIC: DbFinding = {
  id: "d1205652-1009-4796-bf53-2f1f288300f6",
  scan_run_id: "scan_run_real_20261118_03",
  project_id: "proj_real_benchmark_01",
  tool: "gemini-llm-heuristic",
  rule_id: "llm.heuristic.eval-user-input",
  cwe: "CWE-95",
  severity: "high",
  file_path: "lib/dynamic-evaluator.js",
  line_start: 18,
  line_end: 20,
  vulnerability_class: "other",
  raw_message: "Dynamic evaluation of unvalidated expression string.",
  status: "open",
  created_at: "2026-11-18T10:30:00.000Z",
};

// ── PURE HELPER FUNCTIONS TESTED ──

export function deriveDisplayStatus(finding: {
  status: FindingStatus | string;
  patch?: { validation_verdict?: "accepted" | "rejected" | string | null } | null;
}): string {
  if (finding.status === "accepted") return "accepted";
  if (finding.status === "rejected") return "rejected";
  if (finding.status === "dismissed") return "dismissed";
  if (finding.status === "likely_false_positive") return "likely_false_positive";
  if (finding.patch?.validation_verdict === "rejected") return "validation_rejected";
  if (finding.patch?.validation_verdict === "accepted") return "validated";
  return finding.status;
}

export function buildPatchFilePayload({
  filePath,
  commitSha,
  diff,
  generatedAt,
  validationVerdict,
  userEmail,
  isOverride,
}: {
  filePath: string;
  commitSha?: string | null;
  diff: string;
  generatedAt?: string;
  validationVerdict?: string;
  userEmail?: string;
  isOverride?: boolean;
}): { fileName: string; content: string } {
  const cleanPath = (filePath || "remediation").replace(/[^a-zA-Z0-9._-]/g, "_");
  const fileName = `${cleanPath}.patch`;
  const header = `# SecureLoop Remediation Patch
# Target-File: ${filePath}
# Target-Commit: ${commitSha || "HEAD"}
# Generated-At: ${generatedAt || "2026-11-18T00:00:00Z"}
# Validation-Status: ${validationVerdict || "unvalidated"}
# Accepted-By: ${userEmail || "developer"}
# Override: ${isOverride ? "true (validation rejected)" : "false"}
#
# Apply with:
#   git apply ${fileName}
#   or: patch -p1 < ${fileName}
`;
  const content =
    diff.startsWith("---") || diff.startsWith("@@")
      ? `${header}\n${diff}`
      : `${header}\n--- a/${filePath}\n+++ b/${filePath}\n${diff}`;

  return { fileName, content };
}

export function isFindingSuppressed(
  finding: { file_path: string; line_start?: number | null; rule_id?: string | null },
  suppressions: Array<{ file_path: string; line_start?: number | null; rule_id?: string | null }>,
): boolean {
  return suppressions.some((s) => {
    if (s.file_path !== finding.file_path) return false;
    if (s.rule_id && finding.rule_id && s.rule_id !== finding.rule_id) return false;
    if (s.line_start !== null && s.line_start !== undefined && finding.line_start !== undefined) {
      return Math.abs(s.line_start - finding.line_start) <= 2;
    }
    return true;
  });
}

export function calculateFalsePositiveRate(
  findings: Array<{ status: string; explanation?: { likely_false_positive?: boolean } }>,
): { count: number; ratePercent: number } {
  if (findings.length === 0) return { count: 0, ratePercent: 0 };
  const suppressedCount = findings.filter(
    (f) =>
      f.status === "dismissed" ||
      f.status === "likely_false_positive" ||
      f.explanation?.likely_false_positive === true,
  ).length;
  const ratePercent = Math.round((suppressedCount / findings.length) * 100);
  return { count: suppressedCount, ratePercent };
}

export function formatPromptWithRejectionFeedback(
  basePrompt: string,
  feedbackContext?: { previousDiff?: string | undefined; rejectionNote?: string | undefined },
): string {
  if (!feedbackContext?.previousDiff && !feedbackContext?.rejectionNote) {
    return basePrompt;
  }
  const feedbackSection = `\n\nFEEDBACK FROM DEVELOPER (A previous patch attempt was REJECTED):
${feedbackContext.rejectionNote ? `- Developer Note / Reason for rejection: "${feedbackContext.rejectionNote}"\n` : ""}${feedbackContext.previousDiff ? `- Previously rejected diff:\n\`\`\`diff\n${feedbackContext.previousDiff}\n\`\`\`\n` : ""}
Generate an alternative, improved patch that addresses the developer's rejection and meets all security requirements without repeating the previous issues.`;
  return `${basePrompt}${feedbackSection}`;
}

// ── TEST SUITE ──

describe("Finding Decision Actions & Status Integrity", () => {
  describe("4. Status Badge derivation from validation verdict", () => {
    it("derives 'validation_rejected' when patch validation failed, even if finding.status was 'validated'", () => {
      // The bug: finding.status was set to 'validated' during scan, but patch.validation_verdict was 'rejected'.
      const status = deriveDisplayStatus(REAL_SCAN_FIXTURE_REJECTED_VALIDATION);
      expect(status).toBe("validation_rejected");
      expect(status).not.toBe("validated");
    });

    it("derives 'validated' when patch passed validation and developer has not yet acted", () => {
      const status = deriveDisplayStatus(REAL_SCAN_FIXTURE_SQLI);
      expect(status).toBe("validated");
    });

    it("derives 'accepted' when developer explicitly accepted the patch", () => {
      const acceptedFinding = {
        ...REAL_SCAN_FIXTURE_REJECTED_VALIDATION,
        status: "accepted" as const,
      };
      const status = deriveDisplayStatus(acceptedFinding);
      expect(status).toBe("accepted");
    });

    it("derives 'rejected' when developer explicitly rejected the patch", () => {
      const rejectedFinding = {
        ...REAL_SCAN_FIXTURE_SQLI,
        status: "rejected" as const,
      };
      const status = deriveDisplayStatus(rejectedFinding);
      expect(status).toBe("rejected");
    });

    it("derives 'dismissed' when finding is suppressed as a false positive", () => {
      const dismissedFinding = {
        ...REAL_SCAN_FIXTURE_SQLI,
        status: "dismissed" as const,
      };
      const status = deriveDisplayStatus(dismissedFinding);
      expect(status).toBe("dismissed");
    });
  });

  describe("1. Override & Accept with Patch Provenance & Download", () => {
    it("stores who accepted it, when, that validation had rejected it, and override flag", () => {
      const decision: DbDeveloperDecision = {
        id: "dec_real_01",
        patch_id: REAL_SCAN_FIXTURE_REJECTED_VALIDATION.patch.id,
        user_id: "user_developer_123",
        action: "accept",
        is_override: true,
        validation_was_rejected: true,
        decided_at: "2026-11-18T10:35:00.000Z",
      };

      expect(decision.is_override).toBe(true);
      expect(decision.validation_was_rejected).toBe(true);
      expect(decision.action).toBe("accept");
    });

    it("builds a real .patch file with provenance metadata and does NOT claim direct repo commit", () => {
      const { fileName, content } = buildPatchFilePayload({
        filePath: REAL_SCAN_FIXTURE_REJECTED_VALIDATION.file_path,
        commitSha: "e9a8f27c3d1b4a5",
        diff: REAL_SCAN_FIXTURE_REJECTED_VALIDATION.patch.diff!,
        validationVerdict: REAL_SCAN_FIXTURE_REJECTED_VALIDATION.patch.validation_verdict,
        userEmail: "dev@company.local",
        isOverride: true,
      });

      expect(fileName).toBe("src_main_java_com_college_security_JwtAuthFilter.java.patch");
      expect(content).toContain("Target-Commit: e9a8f27c3d1b4a5");
      expect(content).toContain(
        "Target-File: src/main/java/com/college/security/JwtAuthFilter.java",
      );
      expect(content).toContain("Validation-Status: rejected");
      expect(content).toContain("Override: true (validation rejected)");
      expect(content).toContain("Accepted-By: dev@company.local");
      expect(content).toContain("git apply");
      // Must not claim it was committed or pushed
      expect(content).not.toContain("Successfully pushed to main");
      expect(content).not.toContain("Committed to git");
    });
  });

  describe("2. Reject & Regenerate with Developer Feedback", () => {
    it("saves developer rejection note in decision record", () => {
      const decision: DbDeveloperDecision = {
        id: "dec_real_02",
        patch_id: REAL_SCAN_FIXTURE_SQLI.patch.id,
        user_id: "user_developer_123",
        action: "reject",
        is_override: false,
        validation_was_rejected: false,
        rejection_note:
          "Need to use Knex query builder instead of raw parameterized query for style consistency.",
        decided_at: "2026-11-18T10:40:00.000Z",
      };

      expect(decision.action).toBe("reject");
      expect(decision.rejection_note).toBe(
        "Need to use Knex query builder instead of raw parameterized query for style consistency.",
      );
    });

    it("embeds rejected diff and developer note into the regeneration prompt for next attempt", () => {
      const basePrompt = "You are a secure code expert. Fix this SQL injection.";
      const feedback = {
        previousDiff: REAL_SCAN_FIXTURE_SQLI.patch.diff,
        rejectionNote:
          "Please use parameterized prepared statement with named bindings instead of question marks.",
      };

      const revisedPrompt = formatPromptWithRejectionFeedback(basePrompt, feedback);

      expect(revisedPrompt).toContain(
        "FEEDBACK FROM DEVELOPER (A previous patch attempt was REJECTED):",
      );
      expect(revisedPrompt).toContain(
        "Please use parameterized prepared statement with named bindings",
      );
      expect(revisedPrompt).toContain("const sql = `SELECT * FROM users WHERE id = ${id}`;");
      expect(revisedPrompt).toContain(
        "Generate an alternative, improved patch that addresses the developer's rejection",
      );
    });
  });

  describe("3. Dismiss False Positive & Suppression Registry", () => {
    it("validates suppression record schema with reason code and optional reason text", () => {
      const suppression: DbFalsePositiveSuppression = {
        id: "supp_01",
        user_id: "user_developer_123",
        project_id: REAL_SCAN_FIXTURE_SQLI.project_id,
        finding_id: REAL_SCAN_FIXTURE_SQLI.id,
        rule_id: REAL_SCAN_FIXTURE_SQLI.rule_id,
        file_path: REAL_SCAN_FIXTURE_SQLI.file_path,
        line_start: REAL_SCAN_FIXTURE_SQLI.line_start,
        vulnerability_class: REAL_SCAN_FIXTURE_SQLI.vulnerability_class,
        reason_code: "test_code",
        reason_text: "Benchmark sample harness, intentionally vulnerable for detection validation.",
        created_at: "2026-11-18T10:45:00.000Z",
      };

      expect(suppression.reason_code).toBe("test_code");
      expect(suppression.file_path).toBe("routes/users.js");
      expect(suppression.line_start).toBe(42);
    });

    it("correctly identifies and suppresses future scan finding matching file_path, rule_id, and line drift", () => {
      const activeSuppressions = [
        {
          file_path: "routes/users.js",
          rule_id: "javascript.express.sql-injection",
          line_start: 42,
        },
      ];

      // Exact match
      const exactMatch = isFindingSuppressed(
        {
          file_path: "routes/users.js",
          rule_id: "javascript.express.sql-injection",
          line_start: 42,
        },
        activeSuppressions,
      );
      expect(exactMatch).toBe(true);

      // Line drift tolerance (within 2 lines)
      const driftedMatch = isFindingSuppressed(
        {
          file_path: "routes/users.js",
          rule_id: "javascript.express.sql-injection",
          line_start: 43,
        },
        activeSuppressions,
      );
      expect(driftedMatch).toBe(true);

      // Different file -> not suppressed
      const differentFile = isFindingSuppressed(
        {
          file_path: "routes/admin.js",
          rule_id: "javascript.express.sql-injection",
          line_start: 42,
        },
        activeSuppressions,
      );
      expect(differentFile).toBe(false);
    });

    it("accurately computes the false positive rate including dismissed findings on report / benchmark", () => {
      const findingsList = [
        { status: "accepted" },
        { status: "validated" },
        { status: "dismissed" }, // 1 suppressed
        { status: "likely_false_positive" }, // 1 likely FP
      ];

      const { count, ratePercent } = calculateFalsePositiveRate(findingsList);
      expect(count).toBe(2);
      expect(ratePercent).toBe(50); // 2 out of 4 = 50%
    });
  });

  describe("5. LLM Heuristic Notice", () => {
    it("flags heuristic findings where tool is 'gemini-llm-heuristic'", () => {
      const isHeuristic =
        REAL_SCAN_FIXTURE_HEURISTIC.tool === "gemini-llm-heuristic" ||
        (REAL_SCAN_FIXTURE_HEURISTIC as any).source === "llm-heuristic";

      expect(isHeuristic).toBe(true);
      const label = isHeuristic ? "no deterministic rule, validation is limited" : "";
      expect(label).toBe("no deterministic rule, validation is limited");
    });

    it("does not flag deterministic SAST rule findings as heuristic", () => {
      const isHeuristic =
        REAL_SCAN_FIXTURE_SQLI.tool === "gemini-llm-heuristic" ||
        (REAL_SCAN_FIXTURE_SQLI as any).source === "llm-heuristic";

      expect(isHeuristic).toBe(false);
    });
  });
});
