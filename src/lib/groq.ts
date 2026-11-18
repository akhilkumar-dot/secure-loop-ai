/**
 * Groq AI Provider Implementation
 * Uses Groq OpenAI-compatible Chat Completions API (https://api.groq.com/openai/v1/chat/completions)
 * Supports browser CORS and multi-model fallback.
 */
import { redactKeys } from "./ai-provider-detector";

export class GroqProvidersExhaustedError extends Error {
  isExhausted = true;
  constructor(stage: string, errors: Record<string, string>) {
    super(
      `All Groq models for stage '${stage}' failed. Details: ${JSON.stringify(errors, null, 2)}`,
    );
    this.name = "GroqProvidersExhaustedError";
  }
}

export type StageName = "explanation_generation" | "patch_generation" | "default";

export interface GroqConfig {
  apiKey?: string;
  stageModels?: Record<StageName, string[]>;
  maxAttempts?: number;
}

export const DEFAULT_GROQ_STAGE_MODELS: Record<StageName, string[]> = {
  patch_generation: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
  explanation_generation: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
  default: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
};

export class GroqProvider {
  private apiKey: string;
  private stageModels: Record<StageName, string[]>;
  private maxAttempts: number;

  constructor(config: GroqConfig = {}) {
    this.apiKey = (config.apiKey || "").trim();
    this.stageModels = config.stageModels || DEFAULT_GROQ_STAGE_MODELS;
    this.maxAttempts = config.maxAttempts || 3;
  }

  async generateChatCompletion(
    messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
    stage: StageName = "default",
    options: {
      temperature?: number;
      responseFormatJson?: boolean;
      responseSchema?: Record<string, unknown>;
    } = {},
  ): Promise<{ content: string; modelUsed: string }> {
    if (!this.apiKey) {
      throw new Error(
        "Groq API key is missing. Please enter your API key in the Pipeline Configuration.",
      );
    }
    const models = this.stageModels[stage] || this.stageModels.default;
    const errorsRecorded: Record<string, string> = {};

    let attemptsLeft = Math.min(this.maxAttempts, models.length);

    for (const model of models) {
      if (attemptsLeft <= 0) break;
      attemptsLeft--;

      try {
        const body: Record<string, any> = {
          model,
          messages: messages.map((m) => ({
            role: m.role,
            content: m.content,
          })),
          temperature: options.temperature ?? 0.2,
        };

        if (options.responseFormatJson) {
          body["response_format"] = { type: "json_object" };
        }

        const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const status = res.status;
          const rawText = await res.text();
          const sanitizedText = redactKeys(rawText, [this.apiKey]);
          if (status === 429 || status === 402 || status >= 500) {
            errorsRecorded[model] = `HTTP ${status}: ${sanitizedText}`;
            continue;
          }
          throw new Error(`Groq HTTP ${status}: ${sanitizedText}`);
        }

        const data = await res.json();
        const content = data.choices?.[0]?.message?.content ?? "";
        return { content, modelUsed: model };
      } catch (err: any) {
        errorsRecorded[model] = redactKeys(err?.message || String(err), [this.apiKey]);
      }
    }

    throw new GroqProvidersExhaustedError(stage, errorsRecorded);
  }
}
