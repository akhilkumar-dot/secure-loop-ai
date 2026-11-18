/**
 * src/lib/explanation-service.ts
 *
 * Implements Steps 2, 3, 4, 5 of AI Explanation Generation:
 * - One LLM call per finding producing both technical and simplified explanations.
 * - Temperature 0.2 - 0.3.
 * - Strict adherence to spec system prompt and user prompt templates.
 * - Native JSON schema mode for Gemini; defensive JSON parsing for Groq / OpenRouter / OpenAI.
 * - Provider detection, rate limiting, exponential backoff, and backup key fallback.
 * - Zod schema validation with single retry on validation error; throws typed error on second failure.
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
import type { DetectedProvider } from "./ai-provider-detector";

export const EXPLANATION_PROMPT_VERSION = "3.0";

export const ExplanationOutputSchema = z.object({
  what_it_is: z.object({
    technical: z.string().min(1, "Technical what_it_is cannot be empty"),
    simplified: z.string().min(1, "Simplified what_it_is cannot be empty"),
  }),
  why_it_happened: z.object({
    technical: z.string().min(1, "Technical why_it_happened cannot be empty"),
    simplified: z.string().min(1, "Simplified why_it_happened cannot be empty"),
  }),
  how_fix_works: z.object({
    technical: z.string().min(1, "Technical how_fix_works cannot be empty"),
    simplified: z.string().min(1, "Simplified how_fix_works cannot be empty"),
  }),
  attack_idea: z.string().min(1, "attack_idea cannot be empty"),
  key_takeaway: z.string().min(1, "key_takeaway cannot be empty"),
  likely_false_positive: z.object({
    value: z.boolean(),
    reason: z.string(),
  }),
  confidence_note: z.string(),
});

export type ExplanationOutput = z.infer<typeof ExplanationOutputSchema>;

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
 * Gemini-specific ResponseSchema definition matching the spec JSON.
 */
export const GEMINI_EXPLANATION_SCHEMA: ResponseSchema = {
  type: SchemaType.OBJECT,
  properties: {
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
    likely_false_positive: {
      type: SchemaType.OBJECT,
      properties: {
        value: { type: SchemaType.BOOLEAN },
        reason: { type: SchemaType.STRING },
      },
      required: ["value", "reason"],
    },
    confidence_note: { type: SchemaType.STRING },
  },
  required: [
    "what_it_is",
    "why_it_happened",
    "how_fix_works",
    "attack_idea",
    "key_takeaway",
    "likely_false_positive",
    "confidence_note",
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

      const res = await provider.generateChatCompletion(
        [
          { role: "system", content: EXPLANATION_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        "explanation_generation",
        {
          temperature: 0.2,
          responseFormatJson: true,
          ...(isGemini
            ? {
                responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
              }
            : {}),
        },
      );

      const jsonString = extractFirstJson(res.content);
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(jsonString);
      } catch (jsonErr) {
        // Attempt follow-up retry for valid JSON
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
            responseFormatJson: true,
            ...(isGemini
              ? {
                  responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
                }
              : {}),
          },
        );
        parsedJson = JSON.parse(extractFirstJson(retryRes.content));
      }

      const parseResult = ExplanationOutputSchema.safeParse(parsedJson);
      if (parseResult.success) {
        return {
          output: parseResult.data,
          modelUsed: res.modelUsed,
        };
      }

      // Retry once if schema validation failed
      console.warn(
        "[explanation-service] Schema validation failed, retrying with schema correction prompt...",
      );
      const fixRes = await provider.generateChatCompletion(
        [
          { role: "system", content: EXPLANATION_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
          {
            role: "user",
            content: `Your previous response did not match the required schema: ${JSON.stringify(
              parseResult.error.issues,
            )}. Return ONLY valid JSON with exactly the required fields.`,
          },
        ],
        "explanation_generation",
        {
          temperature: 0.1,
          responseFormatJson: true,
          ...(isGemini
            ? {
                responseSchema: GEMINI_EXPLANATION_SCHEMA as unknown as Record<string, unknown>,
              }
            : {}),
        },
      );

      const secondParsed = JSON.parse(extractFirstJson(fixRes.content));
      const secondCheck = ExplanationOutputSchema.safeParse(secondParsed);

      if (!secondCheck.success) {
        throw new ExplanationValidationError(
          `Explanation output failed Zod schema validation after retry: ${secondCheck.error.message}`,
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
