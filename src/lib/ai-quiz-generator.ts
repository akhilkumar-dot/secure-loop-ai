/**
 * src/lib/ai-quiz-generator.ts
 *
 * Generates a contextual multiple-choice quiz question using the AI provider
 * (Gemini, Groq, OpenRouter, OpenAI, Cohere, FreeLLMAPI, etc.) based on the
 * actual finding's vulnerability class, CWE, file path, raw scanner message,
 * and surrounding code snippet.
 *
 * Returns a TieredQuestion-compatible object so it slots directly into the
 * existing quiz UI without any changes to that component.
 *
 * Falls back gracefully — callers should catch and fall back to pickQuestion().
 */

import { z } from "zod";
import { getProvider } from "./ai-pipeline";
import { extractFirstJson } from "./explanation-service";
import type { Tier, VulnClass, TieredQuestion, TieredOption } from "./quiz-bank";

// ── Zod schema to validate the AI's JSON response ──────────────────────────

export const AiQuizResponseSchema = z.object({
  question: z.string().min(10),
  options: z
    .array(
      z.object({
        text: z.string().min(2),
        misconceptionId: z.string().nullable().optional(),
      }),
    )
    .length(4),
  correctIndex: z.number().int().min(0).max(3),
  explanation: z.string().optional(),
  source: z.string().optional(),
});

export type AiQuizResponse = z.infer<typeof AiQuizResponseSchema>;

export const AiMultiQuizResponseSchema = z.object({
  questions: z.array(AiQuizResponseSchema).min(1),
});

export type AiMultiQuizResponse = z.infer<typeof AiMultiQuizResponseSchema>;

// ── Context type passed by the finding page ─────────────────────────────────

export interface FindingQuizContext {
  /** e.g. "sqli", "xss", "csrf", "insecure_deserialization", "other", or any raw scanner class */
  vulnClass: VulnClass | string;
  /** e.g. "easy" | "medium" | "hard" */
  tier: Tier;
  /** CWE string such as "CWE-89" */
  cwe?: string | null;
  /** File path of the finding, e.g. "routes/users.js" */
  filePath?: string | null;
  /** Scanner message / description */
  rawMessage?: string | null;
  /** Up to ~600 chars of code context around the finding */
  codeSnippet?: string | null;
  /** rule_id from scanner, e.g. "javascript.express.sql-injection" */
  ruleId?: string | null;
  /** Severity: critical | high | medium | low */
  severity?: string | null;
}

// ── Prompt builder ───────────────────────────────────────────────────────────

export function buildQuizPrompt(ctx: FindingQuizContext): string {
  const tierGuide = {
    easy: "conceptual understanding (why this pattern is dangerous, what the vulnerability class means in practice)",
    medium:
      "mechanics & remediation (how the attack executes, how to properly fix the vulnerable code, common bypass pitfalls)",
    hard: "subtle edge-cases, defense-in-depth, framework internals, or implementation traps a senior engineer must understand",
  }[ctx.tier];

  const codeBlock =
    ctx.codeSnippet && ctx.codeSnippet.trim()
      ? `\n<CODE_SNIPPET>\n${ctx.codeSnippet.slice(0, 800)}\n</CODE_SNIPPET>`
      : "";

  return `You are a cybersecurity education specialist creating interactive quiz questions for a developer who just analyzed a real security finding in their codebase.

FINDING DETAILS:
- Vulnerability Class: ${ctx.vulnClass} (${ctx.cwe ?? "unknown CWE"})
- File: ${ctx.filePath ?? "unknown file"}
- Severity: ${ctx.severity ?? "unknown"}
- Scanner Rule: ${ctx.ruleId ?? "n/a"}
- Scanner Message: "${ctx.rawMessage ?? ""}"${codeBlock}

GOAL:
Generate EXACTLY THREE progressive multiple-choice quiz questions related to this finding at the **${ctx.tier.toUpperCase()}** difficulty tier:
1. Question 1 (Root Cause & Detection): What makes this specific line or pattern vulnerable?
2. Question 2 (Exploitation & Impact): How could an attacker exploit this pattern, and what payload or scenario triggers it?
3. Question 3 (Remediation & Defense): What is the most robust and secure way to fix this vulnerability?
Tier Focus: ${tierGuide}.

CRITICAL REQUIREMENTS:
1. Ground every question directly in this specific vulnerability pattern, code context, or technology stack. Do NOT generate generic textbook trivia.
2. For each question, provide exactly 4 distinct options (index 0, 1, 2, 3).
3. For each question, exactly ONE option is the correct, defensible answer. Set "misconceptionId": null for the correct option.
4. The remaining 3 options must reflect realistic, common developer misunderstandings or pseudo-fixes. Set "misconceptionId" to a short descriptive identifier (e.g. "thinks_client_sanitization_is_sufficient", "trusts_weak_regex_filter", "confuses_encoding_with_encryption").
5. Keep each question concise (1-3 sentences).
6. Keep each option succinct (under 25 words).
7. Respond ONLY with a valid JSON object matching the schema below. No markdown fences, no conversational preamble.

REQUIRED JSON FORMAT:
{
  "questions": [
    {
      "question": "Question 1: Root cause analysis question text...",
      "options": [
        { "text": "Accurate, secure explanation", "misconceptionId": null },
        { "text": "Plausible but flawed alternative", "misconceptionId": "misconception_tag_1" },
        { "text": "Another incorrect misconception", "misconceptionId": "misconception_tag_2" },
        { "text": "Third common mistake", "misconceptionId": "misconception_tag_3" }
      ],
      "correctIndex": 0,
      "explanation": "Brief explanation of why this answer is correct.",
      "source": "Authoritative guide (e.g. OWASP ASVS, Cheat Sheet, or MITRE CWE)"
    },
    {
      "question": "Question 2: Attack vector / exploit mechanism question text...",
      "options": [
        { "text": "Common misconception about attack vector", "misconceptionId": "misconception_tag_4" },
        { "text": "Accurate explanation of how the attack triggers", "misconceptionId": null },
        { "text": "Incorrect belief about exploit preconditions", "misconceptionId": "misconception_tag_5" },
        { "text": "Flawed assumption about sanitization", "misconceptionId": "misconception_tag_6" }
      ],
      "correctIndex": 1,
      "explanation": "Brief explanation of the exploitation mechanics.",
      "source": "MITRE CWE"
    },
    {
      "question": "Question 3: Remediation / architectural fix question text...",
      "options": [
        { "text": "Ineffective band-aid fix", "misconceptionId": "misconception_tag_7" },
        { "text": "Another flawed fix", "misconceptionId": "misconception_tag_8" },
        { "text": "Comprehensive, canonical secure pattern", "misconceptionId": null },
        { "text": "False belief about framework default security", "misconceptionId": "misconception_tag_9" }
      ],
      "correctIndex": 2,
      "explanation": "Brief explanation of the canonical fix.",
      "source": "OWASP Remediation Cheat Sheet"
    }
  ]
}`;
}

// ── Map arbitrary class to known VulnClass for UI / DB compatibility ────────

export function normalizeVulnClass(raw: string | undefined | null): VulnClass {
  if (raw === "sqli" || raw === "xss" || raw === "csrf" || raw === "insecure_deserialization") {
    return raw;
  }
  const map: Record<string, VulnClass> = {
    other: "sqli",
    ssrf: "xss",
    rce: "sqli",
    lfi: "sqli",
    xxe: "xss",
    idor: "sqli",
    ssti: "xss",
    path_traversal: "sqli",
    open_redirect: "xss",
    command_injection: "sqli",
  };
  return (raw && map[raw]) || "sqli";
}

// ── Main exported generator functions ─────────────────────────────────────────

/**
 * Generate AI quiz questions grounded in the specific finding.
 * Returns up to 3 progressive questions (Root Cause, Exploitation, Remediation).
 *
 * @param ctx       Finding context (vuln class, CWE, code, etc.)
 * @param apiKey    Primary AI API key (Gemini, Groq, OpenRouter, OpenAI, etc.)
 * @param backupKey Optional secondary API key if primary fails
 * @returns         An array of TieredQuestion objects ready for the quiz UI
 */
export async function generateAiQuizQuestions(
  ctx: FindingQuizContext,
  apiKey: string,
  backupKey?: string | null,
): Promise<TieredQuestion[]> {
  const keysToTry = [apiKey, backupKey].filter((k): k is string => Boolean(k && k.trim()));

  if (keysToTry.length === 0) {
    throw new Error("No AI API key available for quiz generation.");
  }

  const prompt = buildQuizPrompt(ctx);
  let lastError: Error | null = null;
  let rawContent: string | null = null;

  for (const currentKey of keysToTry) {
    try {
      const provider = getProvider(currentKey);
      const isGemini = currentKey.startsWith("AQ.") || currentKey.startsWith("AIza");
      const isGroq = currentKey.startsWith("gsk_");

      const result = await provider.generateChatCompletion(
        [
          {
            role: "system",
            content:
              "You are a cybersecurity educator. You output only valid JSON matching the requested schema. No prose or markdown.",
          },
          { role: "user", content: prompt },
        ],
        "default",
        {
          temperature: 0.3,
          responseFormatJson: true,
          ...(isGemini ? {} : isGroq ? {} : {}),
        },
      );

      rawContent = result.content;
      break; // Successfully got content
    } catch (err: any) {
      console.warn(
        `[ai-quiz] Provider attempt failed with key prefix ${currentKey.slice(0, 6)}:`,
        err?.message,
      );
      lastError = err;
    }
  }

  if (!rawContent) {
    throw lastError || new Error("All AI providers failed to generate quiz questions.");
  }

  // Robust JSON extraction using extractFirstJson (handles code blocks and prose)
  const jsonStr = extractFirstJson(rawContent);

  let parsedList: AiQuizResponse[] = [];
  try {
    const rawJson = JSON.parse(jsonStr);
    if (Array.isArray(rawJson)) {
      parsedList = rawJson.map((q) => AiQuizResponseSchema.parse(q));
    } else if (rawJson && Array.isArray(rawJson.questions)) {
      const multi = AiMultiQuizResponseSchema.parse(rawJson);
      parsedList = multi.questions;
    } else {
      const single = AiQuizResponseSchema.parse(rawJson);
      parsedList = [single];
    }
  } catch (parseErr: any) {
    console.error("[ai-quiz] Failed to parse AI quiz JSON. Raw content:", rawContent);
    throw new Error(
      `AI returned invalid quiz JSON structure: ${parseErr?.message ?? "unknown error"}`,
    );
  }

  if (parsedList.length === 0) {
    throw new Error("AI returned empty list of quiz questions.");
  }

  // Ensure normalized VulnClass for DB & spaced repetition engine
  const normalizedClass = normalizeVulnClass(ctx.vulnClass);
  const now = Date.now();

  return parsedList.map((parsed, idx) => {
    const options: TieredOption[] = parsed.options.map((o) => ({
      text: o.text,
      misconceptionId: o.misconceptionId ?? null,
    }));

    return {
      id: `ai_${normalizedClass}_${ctx.tier}_${now}_${idx + 1}`,
      vulnClass: normalizedClass,
      tier: ctx.tier,
      question: parsed.question,
      options,
      correctIndex: parsed.correctIndex,
      source:
        parsed.source ||
        `Finding ${ctx.filePath ? `${ctx.filePath} · ` : ""}${ctx.cwe ? `${ctx.cwe} · ` : ""}${ctx.vulnClass.toString().toUpperCase()} (Q${idx + 1})`,
    };
  });
}

/**
 * Generate a single AI quiz question grounded in the specific finding.
 * Backwards compatible helper that returns the first question.
 */
export async function generateAiQuizQuestion(
  ctx: FindingQuizContext,
  apiKey: string,
  backupKey?: string | null,
): Promise<TieredQuestion> {
  const questions = await generateAiQuizQuestions(ctx, apiKey, backupKey);
  const first = questions[0];
  if (!first) {
    throw new Error("No quiz question was returned.");
  }
  return first;
}
