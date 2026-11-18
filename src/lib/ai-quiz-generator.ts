/**
 * src/lib/ai-quiz-generator.ts
 *
 * Generates a contextual multiple-choice quiz question using the AI provider
 * (Gemini, Groq, OpenRouter, etc.) based on the actual finding's vulnerability
 * class, CWE, file path, raw scanner message, and surrounding code snippet.
 *
 * Returns a TieredQuestion-compatible object so it slots directly into the
 * existing quiz UI without any changes to that component.
 *
 * Falls back gracefully — callers should catch and fall back to pickQuestion().
 */

import { z } from "zod";
import { GeminiProvider, GeminiProviderExhaustedError } from "./gemini-provider";
import { GroqProvider, GroqProvidersExhaustedError } from "./groq";
import { OpenAIProvider, OpenAIProvidersExhaustedError } from "./openai";
import { OpenRouterProvider, AllProvidersExhaustedError } from "./openrouter";
import type { Tier, VulnClass, TieredQuestion, TieredOption } from "./quiz-bank";

// ── Zod schema to validate the AI's JSON response ──────────────────────────

const AiQuizResponseSchema = z.object({
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

type AiQuizResponse = z.infer<typeof AiQuizResponseSchema>;

// ── Context type passed by the finding page ─────────────────────────────────

export interface FindingQuizContext {
  /** e.g. "sqli", "xss", "csrf", "insecure_deserialization", "other" */
  vulnClass: VulnClass;
  /** e.g. "easy" | "medium" | "hard" */
  tier: Tier;
  /** CWE string such as "CWE-89" */
  cwe?: string | null;
  /** File path of the finding, e.g. "routes/users.js" */
  filePath?: string | null;
  /** Scanner message / description */
  rawMessage?: string | null;
  /** Up to ~400 chars of code context around the finding */
  codeSnippet?: string | null;
  /** rule_id from scanner, e.g. "javascript.express.sql-injection" */
  ruleId?: string | null;
  /** Severity: critical | high | medium | low */
  severity?: string | null;
}

// ── Prompt builder ───────────────────────────────────────────────────────────

function buildPrompt(ctx: FindingQuizContext): string {
  const tierGuide = {
    easy: "conceptual understanding (why this is dangerous, what the vulnerability class means)",
    medium: "mechanics (how the attack works, what the fix looks like, common pitfalls)",
    hard:
      "nuanced edge-cases, bypass techniques, or subtle implementation details a senior developer should know",
  }[ctx.tier];

  const codeBlock =
    ctx.codeSnippet && ctx.codeSnippet.trim()
      ? `\n<CODE_CONTEXT>\n${ctx.codeSnippet.slice(0, 600)}\n</CODE_CONTEXT>`
      : "";

  return `You are a secure-code education expert creating a quiz question for a developer who just reviewed a real security finding in their codebase.

FINDING CONTEXT:
- Vulnerability class: ${ctx.vulnClass} (${ctx.cwe ?? "unknown CWE"})
- File: ${ctx.filePath ?? "unknown file"}
- Severity: ${ctx.severity ?? "unknown"}
- Scanner rule: ${ctx.ruleId ?? "n/a"}
- Scanner message: "${ctx.rawMessage ?? ""}"${codeBlock}

TASK:
Generate ONE multiple-choice quiz question at the **${ctx.tier.toUpperCase()}** difficulty tier.
Tier focus: ${tierGuide}.

The question MUST be directly relevant to the specific vulnerability shown above — not a generic textbook question.
Reference the actual code pattern, file type, or CWE when appropriate.

RULES:
1. Exactly 4 options (A–D).
2. Exactly one correct answer.
3. The three wrong options should represent realistic misconceptions a developer might hold, not obviously absurd choices.
4. The correct answer must be unambiguous and defensible.
5. For wrong options, set misconceptionId to a short snake_case label describing the misconception (e.g. "assumes_escaping_is_sufficient", "trusts_client_validation"). Set it to null for the correct option.
6. Keep the question concise (1–3 sentences max).
7. Keep each option under 20 words.

Respond with ONLY valid JSON in this exact shape (no markdown fences):
{
  "question": "...",
  "options": [
    { "text": "...", "misconceptionId": null },
    { "text": "...", "misconceptionId": "example_misconception" },
    { "text": "...", "misconceptionId": "another_misconception" },
    { "text": "...", "misconceptionId": "third_misconception" }
  ],
  "correctIndex": 0,
  "explanation": "One sentence explaining why the correct answer is right.",
  "source": "OWASP / CWE reference URL if applicable"
}`;
}

// ── Provider resolver ────────────────────────────────────────────────────────

type AnyProvider = GeminiProvider | GroqProvider | OpenAIProvider | OpenRouterProvider;

function resolveProvider(apiKey: string): AnyProvider | null {
  const key = (apiKey || "").trim();
  if (!key) return null;
  if (key.startsWith("AQ.") || key.startsWith("AIza")) return new GeminiProvider(key);
  if (key.startsWith("gsk_")) return new GroqProvider({ apiKey: key });
  if (key.startsWith("sk-or-")) return new OpenRouterProvider({ apiKey: key });
  if (key.startsWith("sk-proj-") || key.startsWith("sk-")) return new OpenAIProvider({ apiKey: key });
  // Fallback: try Groq (many free keys don't have a clear prefix)
  if (key.length > 20) return new GroqProvider({ apiKey: key });
  return null;
}

// ── Main exported function ───────────────────────────────────────────────────

/**
 * Generate an AI quiz question grounded in the specific finding.
 *
 * @param ctx    Finding context (vuln class, CWE, code, etc.)
 * @param apiKey The user's AI API key (from sessionStorage or env)
 * @returns      A TieredQuestion ready for the quiz UI
 * @throws       Error if no key, all providers fail, or JSON validation fails
 */
export async function generateAiQuizQuestion(
  ctx: FindingQuizContext,
  apiKey: string,
): Promise<TieredQuestion> {
  const provider = resolveProvider(apiKey);
  if (!provider) {
    throw new Error("No valid AI API key available for quiz generation.");
  }

  const prompt = buildPrompt(ctx);

  let rawContent: string;
  try {
    const result = await provider.generateChatCompletion(
      [
        {
          role: "system",
          content:
            "You are a security education assistant. Always respond with valid JSON only, no markdown.",
        },
        { role: "user", content: prompt },
      ],
      "default",
      { temperature: 0.4, responseFormatJson: true },
    );
    rawContent = result.content;
  } catch (err) {
    // Re-throw typed exhaustion errors so caller can distinguish provider failure from parse failure
    if (
      err instanceof GeminiProviderExhaustedError ||
      err instanceof GroqProvidersExhaustedError ||
      err instanceof OpenAIProvidersExhaustedError ||
      err instanceof AllProvidersExhaustedError
    ) {
      throw err;
    }
    throw new Error(`AI quiz generation failed: ${(err as Error).message}`);
  }

  // Strip markdown fences if the model added them despite instructions
  let jsonStr = rawContent.trim();
  if (jsonStr.startsWith("```")) {
    jsonStr = jsonStr.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  }

  let parsed: AiQuizResponse;
  try {
    parsed = AiQuizResponseSchema.parse(JSON.parse(jsonStr));
  } catch {
    throw new Error(
      `AI returned invalid quiz JSON. Raw: ${jsonStr.slice(0, 200)}`,
    );
  }

  // Convert to TieredQuestion shape
  const options: TieredOption[] = parsed.options.map((o) => ({
    text: o.text,
    misconceptionId: o.misconceptionId ?? null,
  }));

  const question: TieredQuestion = {
    id: `ai_generated_${ctx.vulnClass}_${ctx.tier}_${Date.now()}`,
    vulnClass: ctx.vulnClass,
    tier: ctx.tier,
    question: parsed.question,
    options,
    correctIndex: parsed.correctIndex,
    source:
      parsed.source ??
      `OWASP ${ctx.vulnClass.toUpperCase()} · ${ctx.cwe ?? ""}`,
  };

  return question;
}

