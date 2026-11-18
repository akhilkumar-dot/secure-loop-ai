/**
 * src/lib/groq.ts
 *
 * Groq AI Provider Implementation with Dynamic Live Model Discovery:
 * - Never uses hardcoded or retired model IDs.
 * - Queries GET https://api.groq.com/openai/v1/models for live models.
 * - Filters out audio, moderation, embeddings, and non-JSON models (e.g. allam-2-7b).
 * - Caches live model list in sessionStorage for the browser session.
 * - Prioritizes preferred models: ["openai/gpt-oss-120b", "qwen/qwen3.6-27b", "openai/gpt-oss-20b"].
 * - Employs strict JSON Schema Structured Outputs per stage for openai/gpt-oss-120b and openai/gpt-oss-20b.
 * - Never shares one global response schema across stages.
 * - If a model returns json_validate_failed, attempts to recover and validate failed_generation.
 * - Accurate truthful error classification (distinguishes 401/403 key rejection, 404/400 retired, 429 quota).
 * - Zero dummy, mock, or fallback text anywhere.
 */

import { redactKeys } from "./ai-provider-detector";
import {
  getStageJsonSchema,
  GROQ_EXPLANATION_JSON_SCHEMA,
  GROQ_PATCH_JSON_SCHEMA,
  type StageName,
} from "./stage-schemas";

export const GROQ_MODELS_CACHE_KEY = "sl_groq_live_models_v2";

/**
 * Priority order for active Groq models in 2026.
 * All requests dynamically check that the model actually exists in the user's live list.
 */
export const GROQ_PREFERRED_MODELS: readonly string[] = [
  "openai/gpt-oss-120b",
  "qwen/qwen3.6-27b",
  "openai/gpt-oss-20b",
];

// Re-export for backwards compatibility
export const GROQ_STRUCTURED_EXPLANATION_SCHEMA = GROQ_EXPLANATION_JSON_SCHEMA;
export const GROQ_STRUCTURED_PATCH_SCHEMA = GROQ_PATCH_JSON_SCHEMA;

export class GroqProvidersExhaustedError extends Error {
  isExhausted = true;
  constructor(stage: string, errors: Record<string, string>) {
    super(
      `All Groq models for stage '${stage}' failed. Details: ${JSON.stringify(errors, null, 2)}`,
    );
    this.name = "GroqProvidersExhaustedError";
  }
}

export type { StageName };

export interface GroqConfig {
  apiKey?: string;
  maxAttempts?: number;
}

export interface ChatCompletionResult {
  content: string;
  modelUsed: string;
  finishReason?: string | undefined;
  completionTokens?: number | undefined;
  maxTokensSent?: number | undefined;
  rawLength?: number | undefined;
}

/**
 * Strips code fences and isolates the first JSON object or array block.
 */
function extractJsonSnippet(text: string): string {
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
 * Excludes audio models, embeddings, guardrail models, and non-JSON models like allam-2-7b.
 */
export function filterChatModels(rawModelIds: string[]): string[] {
  return rawModelIds.filter((id) => {
    if (!id || typeof id !== "string") return false;
    const lower = id.toLowerCase();
    if (
      lower.includes("whisper") ||
      lower.includes("prompt-guard") ||
      lower.includes("embedding") ||
      lower.includes("distil-whisper") ||
      lower.includes("allam") ||
      lower.includes("guard")
    ) {
      return false;
    }
    return true;
  });
}

/**
 * Fetches live models directly from Groq API with user's own API key.
 * Caches in sessionStorage for the tab session.
 * Excludes audio models, embeddings, guardrail models, and non-JSON models like allam-2-7b.
 */
export async function fetchLiveGroqModels(apiKey: string): Promise<string[]> {
  if (!apiKey) {
    throw new Error(
      "Groq API key is missing. Please enter your API key in the Pipeline Configuration.",
    );
  }

  // 1. Check sessionStorage cache
  if (typeof window !== "undefined" && window.sessionStorage) {
    try {
      const cached = window.sessionStorage.getItem(GROQ_MODELS_CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const filtered = filterChatModels(parsed as string[]);
          if (filtered.length > 0) {
            return filtered;
          }
        }
      }
    } catch {
      // Ignore cache parse failures
    }
  }

  // 2. Fetch live model list from Groq
  const res = await fetch("https://api.groq.com/openai/v1/models", {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    const status = res.status;
    const raw = await res.text();
    const sanitized = redactKeys(raw, [apiKey]);

    if (status === 401 || status === 403) {
      throw new Error("Your Groq API key was rejected.");
    }
    if (status === 429) {
      throw new Error(
        "Your Groq free quota or rate limit was reached. Wait and retry, or add a backup key.",
      );
    }
    throw new Error(`Failed to retrieve live Groq models (HTTP ${status}): ${sanitized}`);
  }

  const data = await res.json();
  const rawList: Array<{ id: string }> = Array.isArray(data?.data) ? data.data : [];

  // Exclude audio models, guardrail moderation models, embeddings, and non-JSON models (e.g. allam-2-7b)
  const chatModels = filterChatModels(rawList.map((m) => m.id));

  if (chatModels.length === 0) {
    throw new Error("No live chat models found for your Groq account.");
  }

  // 3. Cache in sessionStorage
  if (typeof window !== "undefined" && window.sessionStorage) {
    try {
      window.sessionStorage.setItem(GROQ_MODELS_CACHE_KEY, JSON.stringify(chatModels));
    } catch {
      // Ignore cache write failures
    }
  }

  return chatModels;
}

/**
 * Selects candidate models from the live model list using the priority list.
 * Never invents or outputs a model ID that is not present in the live list.
 */
export function resolveCandidateGroqModels(liveModels: string[]): {
  models: string[];
  chosenModel: string;
  isFallback: boolean;
} {
  const cleanLiveModels = filterChatModels(liveModels || []);
  if (!cleanLiveModels || cleanLiveModels.length === 0) {
    throw new Error("Live Groq model list is empty. Cannot select a model.");
  }

  const preferredInLive: string[] = [];
  for (const pref of GROQ_PREFERRED_MODELS) {
    if (cleanLiveModels.includes(pref)) {
      preferredInLive.push(pref);
    }
  }

  if (preferredInLive.length > 0) {
    const otherLive = cleanLiveModels.filter((m) => !preferredInLive.includes(m));
    return {
      models: [...preferredInLive, ...otherLive],
      chosenModel: preferredInLive[0]!,
      isFallback: false,
    };
  }

  // None of the preferred IDs are live; pick the first available chat model
  return {
    models: [...cleanLiveModels],
    chosenModel: cleanLiveModels[0]!,
    isFallback: true,
  };
}

export class GroqProvider {
  private apiKey: string;
  private maxAttempts: number;

  constructor(config: GroqConfig = {}) {
    this.apiKey = (config.apiKey || "").trim();
    this.maxAttempts = config.maxAttempts || 3;
  }

  async generateChatCompletion(
    messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
    stage: StageName = "default",
    options: {
      temperature?: number;
      maxTokens?: number;
      responseFormatJson?: boolean;
      responseSchema?: Record<string, unknown>;
      validateFn?: (parsed: unknown) => void;
    } = {},
  ): Promise<ChatCompletionResult> {
    if (!this.apiKey) {
      throw new Error(
        "Groq API key is missing. Please enter your API key in the Pipeline Configuration.",
      );
    }

    // 1. Fetch live models dynamically
    const liveModels = await fetchLiveGroqModels(this.apiKey);
    const {
      models: candidateModels,
      chosenModel,
      isFallback,
    } = resolveCandidateGroqModels(liveModels);

    if (isFallback) {
      console.info(
        `[Groq] None of the preferred models were active. Using live model: ${chosenModel}`,
      );
    }

    const errorsRecorded: Record<string, string> = {};
    let hadQuotaError = false;
    let attemptsLeft = Math.min(this.maxAttempts, candidateModels.length);

    for (const model of candidateModels) {
      if (attemptsLeft <= 0) break;
      attemptsLeft--;

      try {
        const isStructured = model === "openai/gpt-oss-120b" || model === "openai/gpt-oss-20b";
        const body: Record<string, any> = {
          model,
          messages: messages.map((m) => ({
            role: m.role,
            content: m.content,
          })),
          temperature: options.temperature ?? 0.2,
        };

        if (options.maxTokens) {
          body["max_tokens"] = options.maxTokens;
        }

        const stageSchema = options.responseSchema || getStageJsonSchema(stage);

        if (isStructured && options.responseFormatJson && stageSchema) {
          // Strict Structured Output Schema for openai/gpt-oss models targeting THIS STAGE ONLY
          body["response_format"] = {
            type: "json_schema",
            json_schema: {
              name: `${stage}_schema`,
              strict: true,
              schema: stageSchema,
            },
          };
        } else if (options.responseFormatJson) {
          // Standard JSON Mode for other models
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

          let errCode = "";
          let errMsg = "";
          let failedGen: string | undefined;
          try {
            const parsedErr = JSON.parse(rawText);
            errCode = parsedErr?.error?.code || "";
            errMsg = parsedErr?.error?.message || "";
            failedGen = parsedErr?.error?.failed_generation;
          } catch {
            errMsg = rawText;
          }

          // 401/403: API key rejected
          if (status === 401 || status === 403) {
            throw new Error("Your Groq API key was rejected.");
          }

          // 429: Rate limit or free quota reached
          if (status === 429) {
            hadQuotaError = true;
            const quotaMsg =
              "Your Groq free quota or rate limit was reached. Wait and retry, or add a backup key.";
            errorsRecorded[model] = quotaMsg;
            continue;
          }

          // 400 with json_validate_failed: try to recover failed_generation
          if (
            status === 400 &&
            (errCode === "json_validate_failed" || errMsg.includes("json_validate_failed")) &&
            failedGen
          ) {
            try {
              const snippet = extractJsonSnippet(failedGen);
              const candidate = JSON.parse(snippet);
              if (options.validateFn) {
                options.validateFn(candidate);
              }
              console.info(
                `[Groq] Successfully recovered valid stage output from failed_generation on model ${model}`,
              );
              return {
                content: snippet,
                modelUsed: model,
                finishReason: "stop",
                maxTokensSent: options.maxTokens,
                rawLength: snippet.length,
              };
            } catch (recoverErr: any) {
              const recMsg = recoverErr?.message || String(recoverErr);
              console.warn(
                `[Groq] Model ${model} returned json_validate_failed and failed_generation could not be validated: ${recMsg}`,
              );
              errorsRecorded[model] = `json_validate_failed: ${recMsg}`;
              continue;
            }
          }

          // 404/400: Model not found or decommissioned
          if (
            status === 404 ||
            (status === 400 &&
              (errCode === "model_decommissioned" ||
                errCode === "model_not_found" ||
                errMsg.toLowerCase().includes("decommissioned") ||
                errMsg.toLowerCase().includes("does not exist") ||
                errMsg.toLowerCase().includes("do not have access")))
          ) {
            const modelNotice = `Model ${model} is no longer available. The app will try the next live model.`;
            console.warn(`[Groq] ${modelNotice} (${errMsg})`);
            errorsRecorded[model] = modelNotice;
            continue;
          }

          // Other HTTP status
          errorsRecorded[model] = `HTTP ${status}: ${sanitizedText}`;
          continue;
        }

        const data = await res.json();
        const choice = data.choices?.[0];
        const content = choice?.message?.content ?? "";
        const finishReason = choice?.finish_reason;
        const completionTokens = data.usage?.completion_tokens;

        return {
          content,
          modelUsed: model,
          finishReason,
          completionTokens,
          maxTokensSent: options.maxTokens,
          rawLength: content.length,
        };
      } catch (err: any) {
        if (err?.message === "Your Groq API key was rejected.") {
          throw err;
        }
        errorsRecorded[model] = redactKeys(err?.message || String(err), [this.apiKey]);
      }
    }

    if (hadQuotaError) {
      throw new Error(
        "Your Groq free quota or rate limit was reached. Wait and retry, or add a backup key.",
      );
    }

    throw new GroqProvidersExhaustedError(stage, errorsRecorded);
  }
}
