/**
 * OpenRouter OpenAI-Compatible Provider Implementation
 * Provides multi-model fallbacks for explanation_generation and patch_generation stages.
 */

export class AllProvidersExhaustedError extends Error {
  isExhausted = true;
  constructor(stage: string, errors: Record<string, string>) {
    super(
      `All OpenRouter models for stage '${stage}' failed. Details: ${JSON.stringify(
        errors,
        null,
        2,
      )}`,
    );
    this.name = "AllProvidersExhaustedError";
  }
}

export type StageName = "explanation_generation" | "patch_generation" | "default";

export interface OpenRouterConfig {
  apiKey?: string;
  stageModels?: Record<StageName, string[]>;
  referer?: string;
  title?: string;
  maxAttempts?: number;
}

export const DEFAULT_STAGE_MODELS: Record<StageName, string[]> = {
  patch_generation: [
    "mistralai/codestral-2508",
    "qwen/qwen3-coder",
    "deepseek/deepseek-r1",
  ],
  explanation_generation: [
    "meta-llama/llama-3.3-70b-instruct",
    "openai/gpt-oss-1",
    "mistralai/codestral-2508",
    "qwen/qwen3-coder",
    "deepseek/deepseek-r1",
  ],
  default: [
    "meta-llama/llama-3.3-70b-instruct",
    "mistralai/codestral-2508",
  ],
};

export class OpenRouterProvider {
  private apiKey: string;
  private stageModels: Record<StageName, string[]>;
  private referer: string;
  private title: string;
  private maxAttempts: number;

  constructor(config: OpenRouterConfig = {}) {
    this.apiKey =
      config.apiKey ||
      (typeof process !== "undefined" && (process as any).env?.["OPENROUTER_API_KEY"]) ||
      (import.meta as any).env?.VITE_OPENROUTER_API_KEY ||
      "";
    this.stageModels = config.stageModels || DEFAULT_STAGE_MODELS;
    this.referer = config.referer || "https://secureloop.ai";
    this.title = config.title || "SecureLoop AI";
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
          messages,
          temperature: options.temperature ?? 0.2,
        };

        if (options.responseFormatJson) {
          body.response_format = { type: "json_object" };
        }

        const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "HTTP-Referer": this.referer,
            "X-Title": this.title,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const status = res.status;
          const text = await res.text();
          // Fallback on 429 (rate limit), 402 (payment/quota required), or 5xx
          if (status === 429 || status === 402 || status >= 500) {
            console.warn(
              `[OpenRouter Fallback] Model ${model} returned HTTP ${status}: ${text}. Falling back to next candidate model...`,
            );
            errorsRecorded[model] = `HTTP ${status}: ${text}`;
            continue;
          }
          throw new Error(`OpenRouter HTTP ${status}: ${text}`);
        }

        const data = await res.json();
        const content = data.choices?.[0]?.message?.content ?? "";
        console.log(`[OpenRouter Success] Served by model: ${model}`);
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

    throw new AllProvidersExhaustedError(stage, errorsRecorded);
  }
}
