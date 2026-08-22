/**
 * OpenAI / AI Pipeline Service
 * Multi-model security analysis, explanations, patch generation, and validation using OpenAI API.
 */
import { OpenAIProvider, OpenAIProvidersExhaustedError } from "./openai";
import { CohereProvider, CohereProvidersExhaustedError } from "./cohere";
import { OpenRouterProvider, AllProvidersExhaustedError } from "./openrouter";

export class QuotaExceededError extends Error {
  isQuota = true;
  retryAfterSec?: number;
  constructor(message: string, retryAfterSec?: number) {
    super(message);
    this.name = "QuotaExceededError";
    if (retryAfterSec !== undefined) {
      this.retryAfterSec = retryAfterSec;
    }
  }
}

// In-memory cache for explanations of identical rule/message patterns within a run
const explanationCache = new Map<string, GeminiExplanation>();

function getProvider(apiKeyOverride?: string): OpenAIProvider | CohereProvider | OpenRouterProvider {
  const openaiKey =
    apiKeyOverride ||
    (typeof process !== "undefined" && (process as any).env?.["OPENAI_API_KEY"]) ||
    (import.meta as any).env?.VITE_OPENAI_API_KEY;

  if (openaiKey && (openaiKey.startsWith("sk-proj-") || openaiKey.startsWith("sk-") || !apiKeyOverride)) {
    return new OpenAIProvider(apiKeyOverride ? { apiKey: apiKeyOverride } : {});
  }

  const cohereKey =
    apiKeyOverride ||
    (typeof process !== "undefined" && (process as any).env?.["COHERE_API_KEY"]) ||
    (import.meta as any).env?.VITE_COHERE_API_KEY;

  if (cohereKey && cohereKey.length > 0 && !cohereKey.startsWith("sk-")) {
    return new CohereProvider(apiKeyOverride ? { apiKey: apiKeyOverride } : {});
  }

  const openrouterKey =
    apiKeyOverride ||
    (typeof process !== "undefined" && (process as any).env?.["OPENROUTER_API_KEY"]) ||
    (import.meta as any).env?.VITE_OPENROUTER_API_KEY;

  if (openrouterKey) {
    return new OpenRouterProvider(apiKeyOverride ? { apiKey: apiKeyOverride } : {});
  }

  return new OpenAIProvider(apiKeyOverride ? { apiKey: apiKeyOverride } : {});
}

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
  code_lines: Array<{ n: number; code: string; vuln?: boolean }>;
}

export interface GeminiExplanation {
  what_it_is: string;
  why_it_happened: string;
  owasp_category: string;
  how_fix_works: string;
  model?: string;
  confidence?: "high" | "medium" | "low" | "not_applicable";
  is_applicable?: boolean;
  error_type?: "false_positive" | "transient_error";
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
/* 1. SAST + LLM code analyzer                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

export async function analyzeCodeForVulnerabilities(
  files: Array<{ path: string; content: string }>,
  apiKeyOverride?: string,
): Promise<GeminiFinding[]> {
  const provider = getProvider(apiKeyOverride);

  const fileBlocks = files
    .map((f) => `--- FILE: ${f.path} ---\n${f.content}`)
    .join("\n\n");

  const prompt = `You are a static code security analyzer. Analyze the provided source code for real security vulnerabilities (SQLi, XSS, CSRF, insecure deserialization, command injection, path traversal, hardcoded secrets).

IMPORTANT: Return ONLY valid JSON matching this exact schema. Do not include any markdown or explanation outside the JSON.

Schema:
{
  "findings": [
    {
      "rule_id": "string",
      "cwe": "string",
      "severity": "critical" | "high" | "medium" | "low",
      "file_path": "string",
      "line_start": number,
      "line_end": number,
      "vulnerability_class": "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other",
      "raw_message": "string",
      "code_lines": [
        { "n": number, "code": "string", "vuln": boolean }
      ]
    }
  ]
}

SOURCE CODE:
${fileBlocks}`;

  try {
    const res = await provider.generateChatCompletion(
      [{ role: "user", content: prompt }],
      "explanation_generation",
      { responseFormatJson: true, temperature: 0.1 },
    );
    const parsed = JSON.parse(res.content);
    return (parsed.findings ?? []) as GeminiFinding[];
  } catch (err) {
    console.error("OpenRouter scan error:", err);
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
  const cacheKey = `${finding.vulnerability_class}:${finding.cwe}:${finding.raw_message}`;
  if (explanationCache.has(cacheKey)) {
    console.log(`[OpenRouter Cache] Reusing cached explanation for ${cacheKey}`);
    return explanationCache.get(cacheKey)!;
  }

  const provider = getProvider(apiKeyOverride);

  const codeContext = finding.code_lines
    ?.map((l) => `${l.n}: ${l.code}`)
    .join("\n") ?? "";

  const prompt = `You are a secure code educator. Analyze and explain the following security vulnerability.

Vulnerability details:
- Type: ${finding.vulnerability_class} (${finding.cwe})
- File: ${finding.file_path}
- Message: ${finding.raw_message}
- Code:
${codeContext}

Evaluate whether this code actually contains the described vulnerability.
Return ONLY valid JSON with this schema:
{
  "is_applicable": boolean (true if the code contains this vulnerability, false if it is a false positive),
  "confidence": "high" | "medium" | "low" | "not_applicable",
  "what_it_is": "2-3 sentences explaining what the vulnerability is (or if false positive, why the code is safe)",
  "why_it_happened": "2-3 sentences explaining why this code pattern introduced it or why the rule matched",
  "owasp_category": "OWASP Top 10 category (e.g. A03:2021 — Injection)",
  "how_fix_works": "2-3 sentences explaining how the recommended fix eliminates the vulnerability"
}`;

  try {
    const res = await provider.generateChatCompletion(
      [{ role: "user", content: prompt }],
      "explanation_generation",
      { responseFormatJson: true, temperature: 0.3 },
    );
    const parsed = JSON.parse(res.content) as GeminiExplanation;
    parsed.model = res.modelUsed;
    if (parsed.is_applicable === false || parsed.confidence === "not_applicable") {
      parsed.error_type = "false_positive";
    }
    explanationCache.set(cacheKey, parsed);
    return parsed;
  } catch (err: any) {
    console.error("OpenRouter explanation error:", err);
    const isExhausted = err instanceof AllProvidersExhaustedError || err?.isExhausted;

    if (isExhausted) {
      return {
        what_it_is: "OpenRouter rate limit or quota exceeded across candidate models.",
        why_it_happened: "Rate limit reached during scan. Re-run scan later or configure a paid OpenRouter API key.",
        owasp_category: "Quota Exceeded (OpenRouter)",
        how_fix_works: "Re-run scan later or provide a paid OpenRouter API key in Settings.",
        error_type: "transient_error",
        confidence: "not_applicable",
        is_applicable: false,
      };
    }

    return {
      what_it_is: "AI Explanation generation failed — retry available.",
      why_it_happened: `AI service error: ${err?.message || String(err)}.`,
      owasp_category: "Transient Failure",
      how_fix_works: "Click retry to attempt generating the explanation again.",
      error_type: "transient_error",
      confidence: "low",
      is_applicable: true,
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
  const provider = getProvider(apiKeyOverride);

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
    const res = await provider.generateChatCompletion(
      [{ role: "user", content: prompt }],
      "patch_generation",
      { responseFormatJson: true, temperature: 0.2 },
    );
    return JSON.parse(res.content) as GeminiPatch;
  } catch (err: any) {
    console.error("OpenRouter patch error:", err);
    const isExhausted = err instanceof AllProvidersExhaustedError || err?.isExhausted;
    return {
      diff: isExhausted
        ? "// Patch skipped — OpenRouter model fallback quota exceeded."
        : "// Patch generation failed due to an AI error. Click retry to regenerate.",
      explanation: isExhausted
        ? "Patch generation skipped because all candidate models hit OpenRouter rate limits."
        : `Could not generate patch: ${err?.message || "AI error"}.`,
    };
  }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 4. Sandbox validator (AI re-analysis of patched code)                       */
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
  const provider = getProvider(apiKeyOverride);

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
    const res = await provider.generateChatCompletion(
      [{ role: "user", content: prompt }],
      "patch_generation",
      { responseFormatJson: true, temperature: 0.1 },
    );
    const parsed = JSON.parse(res.content);
    return {
      vulnerability_gone: parsed.vulnerability_gone ?? false,
      tests_passed: parsed.tests_passed ?? false,
      new_issues: parsed.new_issues ?? 0,
      verdict: parsed.verdict ?? "rejected",
      logs: parsed.logs ?? [],
      failed_check: parsed.failed_check ?? undefined,
    };
  } catch (err: any) {
    console.error("OpenRouter validation error:", err);
    const isExhausted = err instanceof AllProvidersExhaustedError || err?.isExhausted;
    return {
      vulnerability_gone: false,
      tests_passed: false,
      new_issues: 0,
      verdict: "rejected",
      logs: isExhausted
        ? ["Validation skipped — OpenRouter rate limits reached across candidate models"]
        : ["Validation failed — could not parse AI response"],
      failed_check: isExhausted ? "quota_exceeded" : "validation_error",
    };
  }
}
