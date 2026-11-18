/**
 * src/lib/groq.ts
 *
 * Groq AI Provider Implementation with Dynamic Live Model Discovery:
 * - Never uses hardcoded or retired model IDs.
 * - Queries GET https://api.groq.com/openai/v1/models for live models.
 * - Caches live model list in sessionStorage for the browser session.
 * - Prioritizes preferred models: ["openai/gpt-oss-120b", "qwen/qwen3.6-27b", "openai/gpt-oss-20b"].
 * - Employs strict JSON Schema Structured Outputs for openai/gpt-oss-120b and openai/gpt-oss-20b.
 * - Accurate truthful error classification (distinguishes 401/403 key rejection, 404/400 retired models, and 429 quota).
 */

import { redactKeys } from "./ai-provider-detector";

export const GROQ_MODELS_CACHE_KEY = "sl_groq_live_models";

/**
 * Priority list for Groq chat/explanation models.
 * Kept in this single configuration location, never scattered.
 */
export const GROQ_PREFERRED_MODELS: readonly string[] = [
  "openai/gpt-oss-120b",
  "qwen/qwen3.6-27b",
  "openai/gpt-oss-20b",
];

/**
 * Strict JSON schema matching the explanation schema for Groq's Structured Outputs.
 * Required by Groq's strict mode:
 * - additionalProperties: false on every object
 * - all defined properties must be listed in required
 */
export const GROQ_STRUCTURED_EXPLANATION_SCHEMA = {
  type: "object",
  properties: {
    what_it_is: {
      type: "object",
      properties: {
        technical: { type: "string" },
        simplified: { type: "string" },
      },
      required: ["technical", "simplified"],
      additionalProperties: false,
    },
    why_it_happened: {
      type: "object",
      properties: {
        technical: { type: "string" },
        simplified: { type: "string" },
      },
      required: ["technical", "simplified"],
      additionalProperties: false,
    },
    how_fix_works: {
      type: "object",
      properties: {
        technical: { type: "string" },
        simplified: { type: "string" },
      },
      required: ["technical", "simplified"],
      additionalProperties: false,
    },
    attack_idea: { type: "string" },
    key_takeaway: { type: "string" },
    likely_false_positive: {
      type: "object",
      properties: {
        value: { type: "boolean" },
        reason: { type: "string" },
      },
      required: ["value", "reason"],
      additionalProperties: false,
    },
    confidence_note: { type: "string" },
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
  additionalProperties: false,
};

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
  maxAttempts?: number;
}

/**
 * Fetches live models directly from Groq API with user's own API key.
 * Caches the result in sessionStorage for the browser tab session.
 */
export async function fetchLiveGroqModels(apiKey: string): Promise<string[]> {
  const trimmed = apiKey.trim();
  if (!trimmed) {
    throw new Error(
      "Groq API key is missing. Please enter your API key in the Pipeline Configuration.",
    );
  }

  // 1. Check browser sessionStorage cache
  if (typeof window !== "undefined" && window.sessionStorage) {
    try {
      const cached = window.sessionStorage.getItem(GROQ_MODELS_CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      }
    } catch {
      // Ignore cache read failures
    }
  }

  // 2. Fetch live model list from Groq
  const res = await fetch("https://api.groq.com/openai/v1/models", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${trimmed}`,
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    const status = res.status;
    const raw = await res.text();
    const sanitized = redactKeys(raw, [trimmed]);

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

  // Exclude audio models, guardrail moderation models, and embeddings
  const chatModels = rawList
    .map((m) => m.id)
    .filter((id) => {
      if (!id || typeof id !== "string") return false;
      const lower = id.toLowerCase();
      if (
        lower.includes("whisper") ||
        lower.includes("prompt-guard") ||
        lower.includes("embedding") ||
        lower.includes("distil-whisper")
      ) {
        return false;
      }
      return true;
    });

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
  if (!liveModels || liveModels.length === 0) {
    throw new Error("Live Groq model list is empty. Cannot select a model.");
  }

  const preferredInLive: string[] = [];
  for (const pref of GROQ_PREFERRED_MODELS) {
    if (liveModels.includes(pref)) {
      preferredInLive.push(pref);
    }
  }

  if (preferredInLive.length > 0) {
    const otherLive = liveModels.filter((m) => !preferredInLive.includes(m));
    return {
      models: [...preferredInLive, ...otherLive],
      chosenModel: preferredInLive[0]!,
      isFallback: false,
    };
  }

  // None of the preferred IDs are live; pick the first available chat model
  return {
    models: [...liveModels],
    chosenModel: liveModels[0]!,
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
      responseFormatJson?: boolean;
      responseSchema?: Record<string, unknown>;
    } = {},
  ): Promise<{ content: string; modelUsed: string }> {
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

        if (isStructured && options.responseFormatJson) {
          // Strict Structured Output Schema for openai/gpt-oss models
          body["response_format"] = {
            type: "json_schema",
            json_schema: {
              name: "security_explanation",
              strict: true,
              schema: GROQ_STRUCTURED_EXPLANATION_SCHEMA,
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
          try {
            const parsedErr = JSON.parse(rawText);
            errCode = parsedErr?.error?.code || "";
            errMsg = parsedErr?.error?.message || "";
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
        const content = data.choices?.[0]?.message?.content ?? "";
        return { content, modelUsed: model };
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
