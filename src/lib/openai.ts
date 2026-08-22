/**
 * OpenAI Provider Implementation
 * Uses OpenAI API (https://api.openai.com/v1/chat/completions) with multi-model fallback.
 */

export class OpenAIProvidersExhaustedError extends Error {
  isExhausted = true;
  constructor(stage: string, errors: Record<string, string>) {
    super(
      `All OpenAI models for stage '${stage}' failed. Details: ${JSON.stringify(
        errors,
        null,
        2,
      )}`,
    );
    this.name = "OpenAIProvidersExhaustedError";
  }
}

export type StageName = "explanation_generation" | "patch_generation" | "default";

export interface OpenAIConfig {
  apiKey?: string;
  stageModels?: Record<StageName, string[]>;
  maxAttempts?: number;
}

export const DEFAULT_OPENAI_STAGE_MODELS: Record<StageName, string[]> = {
  patch_generation: [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
  ],
  explanation_generation: [
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-4-turbo",
  ],
  default: [
    "gpt-4o-mini",
    "gpt-4o",
  ],
};

export class OpenAIProvider {
  private apiKey: string;
  private stageModels: Record<StageName, string[]>;
  private maxAttempts: number;

  constructor(config: OpenAIConfig = {}) {
    this.apiKey =
      config.apiKey ||
      (typeof process !== "undefined" && (process as any).env?.["OPENAI_API_KEY"]) ||
      (import.meta as any).env?.VITE_OPENAI_API_KEY ||
      "";
    this.stageModels = config.stageModels || DEFAULT_OPENAI_STAGE_MODELS;
    this.maxAttempts = config.maxAttempts || 4;
  }

  async generateChatCompletion(
    messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
    stage: StageName = "default",
    options: { temperature?: number; responseFormatJson?: boolean } = {},
  ): Promise<{ content: string; modelUsed: string }> {
    const models = this.stageModels[stage] || this.stageModels.default;
    const errorsRecorded: Record<string, string> = {};

    let attemptsLeft = Math.min(this.maxAttempts, models.length);

    for (const model of models) {
      if (attemptsLeft <= 0) break;
      attemptsLeft--;

      try {
        const body: any = {
          model,
          messages: messages.map((m) => ({
            role: m.role,
            content: m.content,
          })),
          temperature: options.temperature ?? 0.2,
        };

        if (options.responseFormatJson) {
          body.response_format = { type: "json_object" };
        }

        const res = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const status = res.status;
          const text = await res.text();
          if (status === 429 || status === 402 || status >= 500) {
            console.warn(
              `[OpenAI Fallback] Model ${model} returned HTTP ${status}: ${text}. Falling back to next candidate model...`,
            );
            errorsRecorded[model] = `HTTP ${status}: ${text}`;
            continue;
          }
          throw new Error(`OpenAI HTTP ${status}: ${text}`);
        }

        const data = await res.json();
        const content = data.choices?.[0]?.message?.content ?? "";

        console.log(`[OpenAI Success] Served by model: ${model}`);
        return { content, modelUsed: model };
      } catch (err: any) {
        errorsRecorded[model] = err.message || String(err);
        if (
          err.message?.includes("429") ||
          err.message?.includes("402") ||
          err.message?.includes("50")
        ) {
          continue;
        }
      }
    }

    throw new OpenAIProvidersExhaustedError(stage, errorsRecorded);
  }
}
