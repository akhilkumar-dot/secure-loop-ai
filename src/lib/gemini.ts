/**
 * Gemini AI service — real security analysis, explanations, and patch generation.
 * Uses gemini-2.0-flash for speed and cost-efficiency.
 */
import { GoogleGenerativeAI, SchemaType } from "@google/generative-ai";

const apiKey =
  (import.meta as any).env?.VITE_GEMINI_API_KEY ?? "";

let _client: GoogleGenerativeAI | null = null;
function getClient(key?: string): GoogleGenerativeAI {
  const k = key || apiKey;
  if (!_client || key) _client = new GoogleGenerativeAI(k);
  return _client;
}

const MODEL = "gemini-2.0-flash";

/* ─────────────────────────────────────────────────────────────────────────── */
/* Types                                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

export interface GeminiFinding {
  rule_id: string;
  cwe: string;
  severity: "critical" | "high" | "medium" | "low";
  file_path: string;
  line_start: number;
  line_end: number;
  vulnerability_class: "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";
  raw_message: string;
  code_lines: Array<{ n: number; code: string; vuln: boolean }>;
}

export interface GeminiExplanation {
  what_it_is: string;
  why_it_happened: string;
  owasp_category: string;
  how_fix_works: string;
}

export interface GeminiPatch {
  diff: string;
  explanation: string;
}

export interface GeminiValidation {
  vulnerability_gone: boolean;
  tests_passed: boolean;
  new_issues: number;
  verdict: "accepted" | "rejected";
  logs: string[];
  failed_check?: string;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 1. Vulnerability scanner                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

export async function analyzeCodeForVulnerabilities(
  files: Array<{ path: string; content: string }>,
  apiKeyOverride?: string,
): Promise<GeminiFinding[]> {
  const client = getClient(apiKeyOverride);
  const model = client.getGenerativeModel({
    model: MODEL,
    generationConfig: {
      responseMimeType: "application/json",
      temperature: 0.1,
    },
  });

  // Limit file sizes to avoid token limits
  const trimmedFiles = files
    .filter((f) => f.content.trim().length > 0)
    .slice(0, 20)
    .map((f) => ({
      path: f.path,
      content: f.content.slice(0, 8000), // max 8k chars per file
    }));

  if (trimmedFiles.length === 0) return [];

  const fileBlocks = trimmedFiles
    .map((f) => `=== FILE: ${f.path} ===\n${f.content}`)
    .join("\n\n");

  const prompt = `You are a professional security code auditor. Analyze the following source code files for security vulnerabilities.

IMPORTANT: Return ONLY valid JSON matching this exact schema. Do not include any markdown or explanation outside the JSON.

Schema:
{
  "findings": [
    {
      "rule_id": "string (e.g. javascript.express.sql-injection)",
      "cwe": "string (e.g. CWE-89)",
      "severity": "critical" | "high" | "medium" | "low",
      "file_path": "string (exact filename from input)",
      "line_start": number,
      "line_end": number,
      "vulnerability_class": "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other",
      "raw_message": "string (concise technical description of the vulnerability)",
      "code_lines": [
        { "n": number, "code": "string (exact line content)", "vuln": boolean }
      ]
    }
  ]
}

Rules:
- Only report REAL vulnerabilities, not style issues
- code_lines should include 2-3 lines of context around the vulnerable line
- Mark the vulnerable line(s) with vuln: true
- Focus on: SQL injection, XSS, CSRF, path traversal, insecure deserialization, hardcoded secrets, command injection, IDOR, open redirects, prototype pollution
- If no vulnerabilities are found, return { "findings": [] }

SOURCE CODE:
${fileBlocks}`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    const parsed = JSON.parse(text);
    return (parsed.findings ?? []) as GeminiFinding[];
  } catch (err) {
    console.error("Gemini scan error:", err);
    return [];
  }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 2. Explanation generator                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

export async function generateExplanation(
  finding: {
    vulnerability_class?: string;
    cwe?: string;
    raw_message?: string;
    file_path: string;
    code_lines?: Array<{ n: number; code: string; vuln?: boolean }>;
  },
  apiKeyOverride?: string,
): Promise<GeminiExplanation> {
  const client = getClient(apiKeyOverride);
  const model = client.getGenerativeModel({
    model: MODEL,
    generationConfig: {
      responseMimeType: "application/json",
      temperature: 0.3,
    },
  });

  const codeContext = finding.code_lines
    ?.map((l) => `${l.n}: ${l.code}`)
    .join("\n") ?? "";

  const prompt = `You are a secure code educator. Explain the following security vulnerability to a developer in clear, practical terms.

Vulnerability details:
- Type: ${finding.vulnerability_class} (${finding.cwe})
- File: ${finding.file_path}
- Message: ${finding.raw_message}
- Code:
${codeContext}

Return ONLY valid JSON with this schema:
{
  "what_it_is": "2-3 sentences explaining what the vulnerability is and what an attacker can do",
  "why_it_happened": "2-3 sentences explaining why this code pattern introduces the vulnerability",
  "owasp_category": "OWASP Top 10 category (e.g. A03:2021 — Injection)",
  "how_fix_works": "2-3 sentences explaining how the recommended fix eliminates the vulnerability"
}`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    return JSON.parse(text) as GeminiExplanation;
  } catch (err) {
    console.error("Gemini explanation error:", err);
    return {
      what_it_is: "Could not generate explanation.",
      why_it_happened: "Could not generate explanation.",
      owasp_category: "Unknown",
      how_fix_works: "Could not generate explanation.",
    };
  }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 3. Patch generator                                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

export async function generatePatch(
  finding: {
    vulnerability_class?: string;
    cwe?: string;
    raw_message?: string;
    file_path: string;
    code_lines?: Array<{ n: number; code: string; vuln?: boolean }>;
  },
  fullFileContent?: string,
  apiKeyOverride?: string,
): Promise<GeminiPatch> {
  const client = getClient(apiKeyOverride);
  const model = client.getGenerativeModel({
    model: MODEL,
    generationConfig: {
      responseMimeType: "application/json",
      temperature: 0.2,
    },
  });

  const codeContext = finding.code_lines
    ?.map((l) => `${l.n}: ${l.code}`)
    .join("\n") ?? "";

  const fileCtx = fullFileContent
    ? `\nFull file context (first 3000 chars):\n${fullFileContent.slice(0, 3000)}`
    : "";

  const prompt = `You are a secure code expert. Generate a precise, minimal fix for this security vulnerability.

Vulnerability:
- Type: ${finding.vulnerability_class} (${finding.cwe})
- File: ${finding.file_path}
- Message: ${finding.raw_message}
- Vulnerable code:
${codeContext}
${fileCtx}

Return ONLY valid JSON with this schema:
{
  "diff": "unified diff format showing the exact change (use - for removed lines, + for added lines, include @@ header)",
  "explanation": "1-2 sentences explaining what the patch does and why it fixes the vulnerability"
}

The diff must be minimal (only change what's necessary to fix the vulnerability). Include import statements if new dependencies are needed.`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    return JSON.parse(text) as GeminiPatch;
  } catch (err) {
    console.error("Gemini patch error:", err);
    return {
      diff: "// Patch generation failed",
      explanation: "Could not generate patch.",
    };
  }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 4. Sandbox validator (Gemini re-analysis of patched code)                   */
/* ─────────────────────────────────────────────────────────────────────────── */

export async function validatePatch(
  finding: {
    vulnerability_class?: string;
    cwe?: string;
    raw_message?: string;
    code_lines?: Array<{ n: number; code: string; vuln?: boolean }>;
  },
  patchDiff: string,
  apiKeyOverride?: string,
): Promise<GeminiValidation> {
  const client = getClient(apiKeyOverride);
  const model = client.getGenerativeModel({
    model: MODEL,
    generationConfig: {
      responseMimeType: "application/json",
      temperature: 0.1,
    },
  });

  const originalCode = finding.code_lines
    ?.map((l) => `${l.n}: ${l.code}`)
    .join("\n") ?? "";

  const prompt = `You are a security code reviewer validating a patch. Determine if this patch correctly fixes the vulnerability without introducing new issues.

Original vulnerability:
- Type: ${finding.vulnerability_class} (${finding.cwe})
- Message: ${finding.raw_message}
- Original code:
${originalCode}

Proposed patch (unified diff):
${patchDiff}

Evaluate:
1. Does the patch eliminate the original vulnerability? (vulnerability_gone)
2. Does the patch look syntactically correct and unlikely to break tests? (tests_passed)
3. Does the patch introduce any new security issues? Count them (new_issues)
4. Overall verdict: "accepted" if vulnerability is gone and no critical new issues, "rejected" otherwise

Return ONLY valid JSON:
{
  "vulnerability_gone": boolean,
  "tests_passed": boolean,
  "new_issues": number,
  "verdict": "accepted" | "rejected",
  "failed_check": "string or null — reason for rejection if rejected",
  "logs": ["array of strings — brief validation log lines, max 6"]
}`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    const parsed = JSON.parse(text);
    return {
      vulnerability_gone: parsed.vulnerability_gone ?? false,
      tests_passed: parsed.tests_passed ?? false,
      new_issues: parsed.new_issues ?? 0,
      verdict: parsed.verdict ?? "rejected",
      logs: parsed.logs ?? [],
      failed_check: parsed.failed_check ?? undefined,
    };
  } catch (err) {
    console.error("Gemini validation error:", err);
    return {
      vulnerability_gone: false,
      tests_passed: false,
      new_issues: 0,
      verdict: "rejected",
      logs: ["Validation failed — could not parse AI response"],
      failed_check: "validation_error",
    };
  }
}
