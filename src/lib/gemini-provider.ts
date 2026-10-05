/**
 * Google Gemini Provider
 * Uses @google/generative-ai SDK with gemini-2.0-flash (primary) and gemini-1.5-flash (fallback).
 * Compatible with the same generateChatCompletion interface as OpenAIProvider / OpenRouterProvider.
 */
import { GoogleGenerativeAI } from "@google/generative-ai";

export class GeminiProviderExhaustedError extends Error {
  isExhausted = true;
  constructor(errors: Record<string, string>) {
    super(`All Gemini models failed. Details: ${JSON.stringify(errors, null, 2)}`);
    this.name = "GeminiProviderExhaustedError";
  }
}

export type StageName = "explanation_generation" | "patch_generation" | "default";

const STAGE_MODELS: Record<StageName, string[]> = {
  explanation_generation: ["gemini-3.8-flash", "gemini-3.1-flash-lite", "gemini-flash-lite-latest"],
  patch_generation:       ["gemini-3.8-flash", "gemini-3.1-flash-lite", "gemini-flash-lite-latest"],
  default:                ["gemini-3.8-flash", "gemini-3.1-flash-lite", "gemini-flash-lite-latest"],
};

export class GeminiProvider {
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey =
      apiKey ||
      (typeof process !== "undefined" && (process as any).env?.["GEMINI_API_KEY"]) ||
      (import.meta as any).env?.VITE_GEMINI_API_KEY ||
      "";
  }

  async generateChatCompletion(
    messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
    stage: StageName = "default",
    options: { temperature?: number; responseFormatJson?: boolean } = {},
  ): Promise<{ content: string; modelUsed: string }> {
    const models = STAGE_MODELS[stage] ?? STAGE_MODELS.default;
    const errors: Record<string, string> = {};

    // Merge all messages into a single prompt for Gemini
    const combinedPrompt = messages.map((m) => m.content).join("\n\n");

    for (const modelName of models) {
      // Allow up to 2 attempts per model for transient errors
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const genAI = new GoogleGenerativeAI(this.apiKey);
          const model = genAI.getGenerativeModel({
            model: modelName,
            generationConfig: {
              temperature: options.temperature ?? 0.2,
              ...(options.responseFormatJson ? { responseMimeType: "application/json" } : {}),
            },
          });

          const result = await model.generateContent(combinedPrompt);
          let content = result.response.text();

          // Strip markdown fences if present
          if (options.responseFormatJson) {
            content = content.trim();
            if (content.startsWith("```json")) {
              content = content.replace(/^```json\s*/i, "").replace(/\s*```$/, "").trim();
            } else if (content.startsWith("```")) {
              content = content.replace(/^```\s*/i, "").replace(/\s*```$/, "").trim();
            }
          }

          console.log(`[Gemini Success] Served by model: ${modelName}`);
          return { content, modelUsed: modelName };
        } catch (err: any) {
          const msg = err?.message || String(err);
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
