/**
 * src/lib/explanation-service.ts
 *
 * Implements Steps 2, 3, 4, 5 of AI Explanation Generation:
 * - One LLM call per finding producing both technical and simplified explanations.
 * - Temperature 0.2 - 0.3.
 * - Strict adherence to spec system prompt and user prompt templates.
 * - Native JSON schema mode for Gemini; strict JSON Schema Structured Outputs for Groq; defensive parsing for OpenRouter / OpenAI.
 * - Schema order: likely_false_positive and confidence_note at the FRONT.
 * - Provider detection, rate limiting, exponential backoff, and backup key fallback.
 * - Diagnostic logging (provider, model, finish_reason, completion_tokens, max_tokens, raw_length).
 * - max_tokens config (1500 base, 2500 on length truncation retry).
 * - Specific retry listing missing or invalid fields.
 * - Final failure handling: likely_false_positive stored as null ("not assessed"), confidence_note as "".
 * - Post-generation grounding check against inspected snippet.
 * - Supabase caching keyed by user + finding + prompt version.
 * - ZERO dummy, mock, fallback, or canned text anywhere.
 */

import { z } from "zod";
import { SchemaType, type ResponseSchema } from "@google/generative-ai";
import {
  extractAndVerifySnippet,
  buildPromptInputData,
  EXPLANATION_SYSTEM_PROMPT,
  formatExplanationUserPrompt,
  type RealScanFinding,
} from "./finding-input";
import { checkExplanationGrounding, type GroundingCheckResult } from "./grounding-checker";
import { getProvider } from "./ai-pipeline";
import { executeWithRateLimitAndFallback } from "./rate-limiter";
import { getCachedAiOutput, saveCachedAiOutput } from "./ai-cache";
import { detectProvider, type DetectedProvider } from "./ai-provider-detector";
import {
  ExplanationOutputSchema,
  type ExplanationOutput,
  GROQ_EXPLANATION_JSON_SCHEMA,
} from "./stage-schemas";

export { ExplanationOutputSchema, type ExplanationOutput };

export const EXPLANATION_PROMPT_VERSION = "4.0";
export const EXPLANATION_BASE_MAX_TOKENS = 1500;
export const EXPLANATION_RETRY_MAX_TOKENS = 2500;

export class ExplanationValidationError extends Error {
  isValidationError = true;
  rawResponse?: string | undefined;
  zodIssues?: z.ZodIssue[] | undefined;

  constructor(message: string, rawResponse?: string, zodIssues?: z.ZodIssue[]) {
    super(message);
    this.name = "ExplanationValidationError";
    this.rawResponse = rawResponse;
    this.zodIssues = zodIssues;
  }
}

/**
 * Strips code fences and isolates the first JSON object block.
 */
export function extractFirstJson(text: string): string {
  let clean = text.trim();
  if (clean.startsWith("```json")) {
    clean = clean
      .replace(/^```json\s*/i, "")
      .replace(/\s*```$/, "")
      .trim();
  } else if (clean.startsWith("```")) {
    clean = clean
      .replace(/^```\s*/i, "")
      .replace(/\s*```$/, "")
      .trim();
  }

  const firstBrace = clean.indexOf("{");
  const lastBrace = clean.lastIndexOf("}");
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    return clean.slice(firstBrace, lastBrace + 1);
  }
  return clean;
}

/**
 * Gemini-specific ResponseSchema definition with likely_false_positive and confidence_note at FRONT.
 */
export const GEMINI_EXPLANATION_SCHEMA: ResponseSchema = {
  type: SchemaType.OBJECT,
  properties: {
    likely_false_positive: {
      type: SchemaType.OBJECT,
      properties: {
        value: { type: SchemaType.BOOLEAN },
        reason: { type: SchemaType.STRING },
      },
      required: ["value", "reason"],
    },
    confidence_note: { type: SchemaType.STRING },
    what_it_is: {
      type: SchemaType.OBJECT,
      properties: {
        technical: { type: SchemaType.STRING },
        simplified: { type: SchemaType.STRING },
      },
      required: ["technical", "simplified"],
    },
    why_it_happened: {
      type: SchemaType.OBJECT,
      properties: {
        technical: { type: SchemaType.STRING },
        simplified: { type: SchemaType.STRING },
      },
      required: ["technical", "simplified"],
    },
    how_fix_works: {
      type: SchemaType.OBJECT,
      properties: {
        technical: { type: SchemaType.STRING },
        simplified: { type: SchemaType.STRING },
      },
      required: ["technical", "simplified"],
    },
    attack_idea: { type: SchemaType.STRING },
    key_takeaway: { type: SchemaType.STRING },
  },
  required: [
    "likely_false_positive",
    "confidence_note",
    "what_it_is",
    "why_it_happened",
    "how_fix_works",
    "attack_idea",
    "key_takeaway",
  ],
};

export interface GenerateRealExplanationParams {
  finding: RealScanFinding;
  fileContent: string;
  primaryKey: string;
  backupKey?: string | undefined;
  userId?: string | undefined;
  findingId?: string | undefined;
}

export interface RealExplanationResult {
  output: ExplanationOutput;
  modelUsed: string;
  provider: DetectedProvider;
  groundingResult: GroundingCheckResult;
  snippetWithLineNumbers: string;
}

/**
 * Generates a real, verified security explanation for a scan finding.
 * Throws explicit errors if snippet verification fails, provider fails, or validation fails.
 * Never outputs placeholder or fallback content.
 */
export async function generateRealExplanation(
  params: GenerateRealExplanationParams,
): Promise<RealExplanationResult> {
  const { finding, fileContent, primaryKey, backupKey, userId, findingId } = params;

  // 1. Extract ±10 lines snippet and verify against scanner matched_text
  const snippet = extractAndVerifySnippet(
    fileContent,
    finding.line_start,
    finding.matched_text,
    10,
  );

  // 2. Build prompt input parameters (sends "not provided" for missing CWE/class)
  const inputData = buildPromptInputData(finding, snippet.snippetWithLineNumbers);

  // 3. Check persistent Supabase cache first if userId & findingId are present
  if (userId && findingId) {
    const cached = await getCachedAiOutput<ExplanationOutput>(
      userId,
      findingId,
      "explanation",
      EXPLANATION_PROMPT_VERSION,
    );
    if (cached) {
      const parsedCached = ExplanationOutputSchema.safeParse(cached.output);
      if (parsedCached.success) {
        const groundingResult = checkExplanationGrounding(
          parsedCached.data,
          snippet.snippetWithLineNumbers,
          finding.file_path,
        );
        return {
          output: parsedCached.data,
          modelUsed: cached.modelId,
          provider: (cached.provider as DetectedProvider) || "gemini",
          groundingResult,
          snippetWithLineNumbers: snippet.snippetWithLineNumbers,
        };
      }
    }
  }

  const userPrompt = formatExplanationUserPrompt(inputData);

  // 4. Execute single model call with rate limiting, retries, and backup key fallback
  const { result, providerUsed } = await executeWithRateLimitAndFallback<{
    output: ExplanationOutput;
    modelUsed: string;
  }>({
    primaryKey,
    backupKey,
    execute: async (keyToUse) => {
      const provider = getProvider(keyToUse);
      const isGemini = keyToUse.startsWith("AQ.") || keyToUse.startsWith("AIza");
      const isGroq = keyToUse.startsWith("gsk_");
      const providerName = detectProvider(keyToUse);

      let maxTokens = EXPLANATION_BASE_MAX_TOKENS;

      // 4a. Initial Call
      let res = await provider.generateChatCompletion(
        [
          { role: "system", content: EXPLANATION_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        "explanation_generation",
        {
          temperature: 0.2,
          maxTokens,
          responseFormatJson: true,
          ...(isGemini
            ? {
                responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
              }
            : isGroq
              ? {
                  responseSchema: GROQ_EXPLANATION_JSON_SCHEMA,
                }
              : {}),
        },
      );

      // Diagnostic logging (strictly excludes API key and full prompt)
      const resMeta = res as any;
      console.log("[explanation-diagnostics]", {
        provider: providerName,
        model: res.modelUsed,
        finish_reason: resMeta.finishReason ?? "unknown",
        completion_tokens: resMeta.completionTokens ?? "unknown",
        max_tokens_sent: maxTokens,
        raw_response_length: res.content.length,
      });

      // 4b. If finish_reason indicates token limit truncation, retry once with higher limit
      if (resMeta.finishReason === "length" || resMeta.finishReason === "MAX_TOKENS") {
        console.warn(
          `[explanation-diagnostics] Truncation detected on model ${res.modelUsed} (finish_reason = length). Retrying once with ${EXPLANATION_RETRY_MAX_TOKENS} tokens...`,
        );
        maxTokens = EXPLANATION_RETRY_MAX_TOKENS;
        res = await provider.generateChatCompletion(
          [
            { role: "system", content: EXPLANATION_SYSTEM_PROMPT },
            { role: "user", content: userPrompt },
          ],
          "explanation_generation",
          {
            temperature: 0.2,
            maxTokens,
            responseFormatJson: true,
            ...(isGemini
              ? {
                  responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
                }
              : isGroq
                ? {
                    responseSchema: GROQ_EXPLANATION_JSON_SCHEMA,
                  }
                : {}),
          },
        );

        const retryMeta = res as any;
        console.log("[explanation-diagnostics-retry-length]", {
          provider: providerName,
          model: res.modelUsed,
          finish_reason: retryMeta.finishReason ?? "unknown",
          completion_tokens: retryMeta.completionTokens ?? "unknown",
          max_tokens_sent: maxTokens,
          raw_response_length: res.content.length,
        });
      }

      // 4c. Extract JSON and parse
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(extractFirstJson(res.content));
      } catch (jsonErr) {
        console.warn("[explanation-service] Initial JSON parse failed, retrying once...");
        const retryRes = await provider.generateChatCompletion(
          [
            { role: "system", content: EXPLANATION_SYSTEM_PROMPT },
            { role: "user", content: userPrompt },
            {
              role: "user",
              content:
                "Your previous response was not valid JSON. Return ONLY the JSON object matching the schema with no extra text or fences.",
            },
          ],
          "explanation_generation",
          {
            temperature: 0.1,
            maxTokens,
            responseFormatJson: true,
            ...(isGemini
              ? {
                  responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
                }
              : isGroq
                ? {
                    responseSchema: GROQ_EXPLANATION_JSON_SCHEMA,
                  }
                : {}),
          },
        );
        parsedJson = JSON.parse(extractFirstJson(retryRes.content));
      }

      // 4d. First-pass validation check
      const parseResult = ExplanationOutputSchema.safeParse(parsedJson);
      if (parseResult.success) {
        return {
          output: parseResult.data,
          modelUsed: res.modelUsed,
        };
      }

      // 4e. Specific retry listing missing or invalid fields
      const missingOrInvalid = parseResult.error.issues
        .map((issue) => {
          const path = issue.path.join(".");
          return path ? `"${path}": ${issue.message}` : issue.message;
        })
        .join("; ");

      console.warn(
        `[explanation-service] Schema validation failed. Missing/invalid: ${missingOrInvalid}. Retrying with specific correction prompt...`,
      );

      const fixRes = await provider.generateChatCompletion(
        [
          { role: "system", content: EXPLANATION_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
          {
            role: "user",
            content: `Your previous response was incomplete or did not match the required schema. Missing or invalid fields: ${missingOrInvalid}. Return ONLY the COMPLETE valid JSON object with ALL required fields.`,
          },
        ],
        "explanation_generation",
        {
          temperature: 0.1,
          maxTokens: Math.max(maxTokens, EXPLANATION_RETRY_MAX_TOKENS),
          responseFormatJson: true,
          ...(isGemini
            ? {
                responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
              }
            : isGroq
              ? {
                  responseSchema: GROQ_EXPLANATION_JSON_SCHEMA,
                }
              : {}),
        },
      );

      const secondParsed = JSON.parse(extractFirstJson(fixRes.content));
      const secondObj = secondParsed as any;

      // 4f. Final failure handling per Requirement 6:
      // If retry still lacks likely_false_positive -> store as null (not assessed in UI; do NOT default to false or invent reason)
      // If confidence_note is missing -> treat as "" (confident)
      // Allow these two cases ONLY; any other missing field remains a hard error
      if (secondObj && typeof secondObj === "object") {
        if (secondObj.confidence_note === undefined) {
          secondObj.confidence_note = "";
        }
        if (secondObj.likely_false_positive === undefined) {
          secondObj.likely_false_positive = null;
        }
      }

      const secondCheck = ExplanationOutputSchema.safeParse(secondObj);

      if (!secondCheck.success) {
        const finalMissing = secondCheck.error.issues
          .map((i) => i.path.join(".") || "root")
          .join(", ");
        const fixMeta = fixRes as any;
        const isTruncated =
          fixMeta.finishReason === "length" || fixMeta.finishReason === "MAX_TOKENS";
        const errDetail = isTruncated
          ? `Output truncated by model token limit (${fixRes.modelUsed}). Incomplete fields: ${finalMissing}`
          : `Missing or invalid required fields (${finalMissing}) from model ${fixRes.modelUsed}`;

        throw new ExplanationValidationError(
          `AI explanation generation failed: ${errDetail}`,
          fixRes.content,
          secondCheck.error.issues,
        );
      }

      return {
        output: secondCheck.data,
        modelUsed: fixRes.modelUsed || res.modelUsed,
      };
    },
  });

  // 5. Post-generation Grounding Check
  const groundingResult = checkExplanationGrounding(
    result.output,
    snippet.snippetWithLineNumbers,
    finding.file_path,
  );

  // 6. Persist to Supabase AI cache
  if (userId && findingId) {
    await saveCachedAiOutput({
      userId,
      findingId,
      task: "explanation",
      provider: providerUsed,
      modelId: result.modelUsed,
      output: result.output,
      promptVersion: EXPLANATION_PROMPT_VERSION,
    });
  }

  return {
    output: result.output,
    modelUsed: result.modelUsed,
    provider: providerUsed,
    groundingResult,
    snippetWithLineNumbers: snippet.snippetWithLineNumbers,
  };
}
