/**
 * Google Gemini Provider
 * Uses @google/generative-ai SDK.
 *
 * Primary model: gemini-2.5-flash (latest fast model with thinking)
 * Fallbacks:     gemini-1.5-flash → gemini-1.5-flash-8b
 *
 * Model names are configurable via env:
 *   GEMINI_MODEL_PRIMARY   (default: gemini-2.5-flash)
 *   GEMINI_MODEL_FALLBACKS (comma-separated, default: gemini-1.5-flash,gemini-1.5-flash-8b)
 *
 * Compatible with the same generateChatCompletion interface as OpenAIProvider / OpenRouterProvider.
 */
import { GoogleGenerativeAI, type ResponseSchema } from "@google/generative-ai";
import { redactKeys } from "./ai-provider-detector";
import type { StageName } from "./stage-schemas";

export type { StageName };

export class GeminiProviderExhaustedError extends Error {
  isExhausted = true;
  constructor(errors: Record<string, string>) {
    super(`All Gemini models failed. Details: ${JSON.stringify(errors, null, 2)}`);
    this.name = "GeminiProviderExhaustedError";
  }
}

function resolveModels(): string[] {
  const envPrimary =
    (typeof process !== "undefined" && process.env?.["GEMINI_MODEL_PRIMARY"]) ||
    (typeof import.meta !== "undefined" && (import.meta as any).env?.["VITE_GEMINI_MODEL_PRIMARY"]);
  const primary = envPrimary || "gemini-1.5-flash";

  const envFallbacks =
    (typeof process !== "undefined" && process.env?.["GEMINI_MODEL_FALLBACKS"]) ||
    (typeof import.meta !== "undefined" &&
      (import.meta as any).env?.["VITE_GEMINI_MODEL_FALLBACKS"]);
  const fallbacksEnv = envFallbacks || "gemini-2.0-flash,gemini-1.5-flash-8b";

  return [
    primary,
    ...fallbacksEnv
      .split(",")
      .map((m: string) => m.trim())
      .filter(Boolean),
  ];
}

const STAGE_MODELS: Record<StageName, string[]> = {
  explanation_generation: resolveModels(),
  patch_generation: resolveModels(),
  triage: resolveModels(),
  vulnerability_validation: resolveModels(),
  default: resolveModels(),
};

export class GeminiProvider {
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = (apiKey || "").trim();
    if (!this.apiKey) {
      throw new Error(
        "Gemini API key is required. Please enter your API key in the Pipeline Configuration above the scan.",
      );
    }
  }

  async generateChatCompletion(
    messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
    stage: StageName = "default",
    options: {
      temperature?: number;
      responseFormatJson?: boolean;
      responseSchema?: ResponseSchema | Record<string, unknown>;
    } = {},
  ): Promise<{ content: string; modelUsed: string }> {
    const models = STAGE_MODELS[stage] ?? STAGE_MODELS.default;
    const errors: Record<string, string> = {};

    const systemMsg = messages.find((m) => m.role === "system");
    const nonSystem = messages.filter((m) => m.role !== "system");
    const combinedPrompt = nonSystem.map((m) => m.content).join("\n\n");

    for (const modelName of models) {
      // Allow up to 2 attempts per model for transient errors
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const genAI = new GoogleGenerativeAI(this.apiKey);
          const model = genAI.getGenerativeModel({
            model: modelName,
            ...(systemMsg ? { systemInstruction: systemMsg.content } : {}),
            generationConfig: {
              temperature: options.temperature ?? 0.2,
              ...(options.responseFormatJson ? { responseMimeType: "application/json" } : {}),
              ...(options.responseSchema
                ? { responseSchema: options.responseSchema as unknown as ResponseSchema }
                : {}),
            },
          });

          const result = await model.generateContent(combinedPrompt);
          let content = result.response.text();

          // Strip markdown fences if present
          if (options.responseFormatJson) {
            content = content.trim();
            if (content.startsWith("```json")) {
              content = content
                .replace(/^```json\s*/i, "")
                .replace(/\s*```$/, "")
                .trim();
            } else if (content.startsWith("```")) {
              content = content
                .replace(/^```\s*/i, "")
                .replace(/\s*```$/, "")
                .trim();
            }
          }

          console.log(`[Gemini Success] Served by model: ${modelName}`);
          return { content, modelUsed: modelName };
        } catch (err: any) {
          const rawMsg = err?.message || String(err);
          const msg = redactKeys(rawMsg, [this.apiKey]);
          console.warn(`[Gemini Attempt ${attempt + 1}] Model ${modelName} failed: ${msg}`);
          errors[`${modelName}_attempt_${attempt + 1}`] = msg;

          const isTransient =
            msg.includes("429") ||
            msg.includes("RESOURCE_EXHAUSTED") ||
            msg.includes("503") ||
            msg.includes("500") ||
            msg.includes("Service Unavailable") ||
            msg.includes("quota");

          if (isTransient && attempt === 0) {
            // Wait 1.5s before retry
            await new Promise((r) => setTimeout(r, 1500));
            continue;
          }
          break;
        }
      }
    }

    throw new GeminiProviderExhaustedError(errors);
  }
}
