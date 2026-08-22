/**
 * Cohere AI Provider Implementation
 * Uses Cohere v2 chat completions API (https://api.cohere.com/v2/chat) with multi-model fallback.
 */

export class CohereProvidersExhaustedError extends Error {
  isExhausted = true;
  constructor(stage: string, errors: Record<string, string>) {
    super(
      `All Cohere models for stage '${stage}' failed. Details: ${JSON.stringify(
        errors,
        null,
        2,
      )}`,
    );
    this.name = "CohereProvidersExhaustedError";
  }
}

export type StageName = "explanation_generation" | "patch_generation" | "default";

export interface CohereConfig {
  apiKey?: string;
  stageModels?: Record<StageName, string[]>;
  maxAttempts?: number;
}

export const DEFAULT_COHERE_STAGE_MODELS: Record<StageName, string[]> = {
  patch_generation: [
    "command-r-plus",
    "command-r-plus-08-2024",
    "command-r",
    "command-r-08-2024",
    "command-nightly",
  ],
  explanation_generation: [
    "command-r-plus",
    "command-r-plus-08-2024",
    "command-r",
    "command-r-08-2024",
    "command-nightly",
  ],
  default: [
    "command-r-plus",
    "command-r",
    "command-nightly",
  ],
};

export class CohereProvider {
  private apiKey: string;
  private stageModels: Record<StageName, string[]>;
  private maxAttempts: number;

  constructor(config: CohereConfig = {}) {
    this.apiKey =
      config.apiKey ||
      (typeof process !== "undefined" && (process as any).env?.["COHERE_API_KEY"]) ||
      (import.meta as any).env?.VITE_COHERE_API_KEY ||
      "";
    this.stageModels = config.stageModels || DEFAULT_COHERE_STAGE_MODELS;
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

        const res = await fetch("https://api.cohere.com/v2/chat", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "Content-Type": "application/json",
            "X-Client-Name": "SecureLoop-AI",
          },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const status = res.status;
          const text = await res.text();
          if (status === 429 || status === 402 || status >= 500) {
            console.warn(
              `[Cohere Fallback] Model ${model} returned HTTP ${status}: ${text}. Falling back to next candidate model...`,
            );
            errorsRecorded[model] = `HTTP ${status}: ${text}`;
            continue;
          }
          throw new Error(`Cohere HTTP ${status}: ${text}`);
        }

        const data = await res.json();
        let content = "";
        if (data.message?.content) {
          if (Array.isArray(data.message.content)) {
            content = data.message.content
              .filter((c: any) => c.type === "text")
              .map((c: any) => c.text)
              .join("");
          } else if (typeof data.message.content === "string") {
            content = data.message.content;
          }
        } else if (data.text) {
          content = data.text;
        }

        console.log(`[Cohere Success] Served by model: ${model}`);
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

    throw new CohereProvidersExhaustedError(stage, errorsRecorded);
  }
}
