/**
 * src/lib/custom-openai.ts
 *
 * Custom OpenAI-Compatible Provider Implementation (e.g. FreeLLMAPI, Ollama, LocalAI, vLLM).
 * - Sends requests ONLY to the user-entered Base URL (validated http/https, no credentials).
 * - Keys stay strictly in browser sessionStorage.
 * - Dynamic model discovery via GET {baseUrl}/models.
 * - Handles 401/403 with immediate non-retryable rejection.
 * - Reads retry-after and rate-limit headers on 429.
 * - JSON mode support with defensive schema parsing and finish_reason tracking.
 */

import { redactKeys, validateEndpointUrl } from "./ai-provider-detector";
import type { StageName } from "./stage-schemas";

export class AuthRejectedError extends Error {
  isAuthRejected = true;
  status: number;
  provider: string;

  constructor(message: string, status: number = 401, provider: string = "Custom Endpoint") {
    super(message);
    this.name = "AuthRejectedError";
    this.status = status;
    this.provider = provider;
  }
}

export class CustomOpenAIExhaustedError extends Error {
  isExhausted = true;
  constructor(stage: string, errors: Record<string, string>) {
    super(
      `All models for custom endpoint stage '${stage}' failed. Details: ${JSON.stringify(errors, null, 2)}`,
    );
    this.name = "CustomOpenAIExhaustedError";
  }
}

export interface CustomOpenAIConfig {
  apiKey?: string;
  baseUrl: string;
  defaultModel?: string;
  providerName?: string;
  maxAttempts?: number;
}

export interface CustomChatCompletionResult {
  content: string;
  modelUsed: string;
  finishReason?: string | undefined;
  completionTokens?: number | undefined;
  maxTokensSent?: number | undefined;
  rawLength?: number | undefined;
  retryAfterSec?: number | undefined;
}

/**
 * Fetches live models directly from the custom OpenAI endpoint: GET {baseUrl}/models.
 */
export async function fetchCustomEndpointModels(
  baseUrl: string,
  apiKey?: string,
): Promise<string[]> {
  const { isValid, error, normalizedUrl } = validateEndpointUrl(baseUrl);
  if (!isValid || !normalizedUrl) {
    throw new Error(error || "Invalid endpoint URL.");
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey.trim()}`;
  }

  const modelsUrl = `${normalizedUrl}/models`;
  const res = await fetch(modelsUrl, { headers });

  if (!res.ok) {
    const status = res.status;
    const raw = await res.text();
    const sanitized = redactKeys(raw, apiKey ? [apiKey] : []);

    if (status === 401 || status === 403) {
      throw new AuthRejectedError(
        `Custom endpoint rejected your API key (HTTP ${status}). Check that the key belongs to this endpoint.`,
        status,
        "Custom Endpoint",
      );
    }
    throw new Error(`Failed to retrieve models from ${modelsUrl} (HTTP ${status}): ${sanitized}`);
  }

  const data = await res.json();
  const rawList: Array<{ id: string }> = Array.isArray(data?.data)
    ? data.data
    : Array.isArray(data?.models)
      ? data.models
      : Array.isArray(data)
        ? data
        : [];

  const models = rawList
    .map((m) => (typeof m === "string" ? m : m?.id))
    .filter((id): id is string => typeof id === "string" && id.trim().length > 0);

  return models;
}

export class CustomOpenAIProvider {
  private apiKey: string;
  private baseUrl: string;
  private defaultModel: string;
  private providerName: string;
  private maxAttempts: number;

  constructor(config: CustomOpenAIConfig) {
    const { isValid, error, normalizedUrl } = validateEndpointUrl(config.baseUrl);
    if (!isValid || !normalizedUrl) {
      throw new Error(error || "Invalid custom endpoint Base URL.");
    }

    this.baseUrl = normalizedUrl;
    this.apiKey = (config.apiKey || "").trim();
    this.defaultModel = (config.defaultModel || "freellmapi/auto").trim();
    this.providerName = config.providerName || "FreeLLMAPI";
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
  ): Promise<CustomChatCompletionResult> {
    const candidateModels = [this.defaultModel];

    const errorsRecorded: Record<string, string> = {};
    let attemptsLeft = Math.min(this.maxAttempts, candidateModels.length);

    for (const model of candidateModels) {
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

        if (options.maxTokens) {
          body["max_tokens"] = options.maxTokens;
        }

        if (options.responseFormatJson) {
          body["response_format"] = { type: "json_object" };
        }

        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        if (this.apiKey) {
          headers["Authorization"] = `Bearer ${this.apiKey}`;
        }

        const completionsUrl = `${this.baseUrl}/chat/completions`;
        const res = await fetch(completionsUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const status = res.status;
          const rawText = await res.text();
          const sanitizedText = redactKeys(rawText, this.apiKey ? [this.apiKey] : []);

          // 401/403: Authentication rejected - non-retryable
          if (status === 401 || status === 403) {
            throw new AuthRejectedError(
              `${this.providerName} rejected your API key (HTTP ${status}). Check that the key belongs to ${this.providerName}.`,
              status,
              this.providerName,
            );
          }

          // 429: Rate limit or free quota reached
          if (status === 429) {
            const retryAfterHeader = res.headers.get("retry-after");
            let retryAfterSec: number | undefined;
            if (retryAfterHeader) {
              const parsedSec = parseInt(retryAfterHeader, 10);
              if (!isNaN(parsedSec)) retryAfterSec = parsedSec;
            }

            const quotaMsg = retryAfterSec
              ? `${this.providerName} rate limit reached. Retry after ${retryAfterSec}s.`
              : `${this.providerName} rate limit or free quota reached. Please wait and retry.`;
            errorsRecorded[model] = quotaMsg;
            continue;
          }

          errorsRecorded[model] = `HTTP ${status}: ${sanitizedText}`;
          continue;
        }

        const data = await res.json();
        const choice = data.choices?.[0];
        const content = choice?.message?.content ?? "";
        const finishReason = choice?.finish_reason;
        const completionTokens = data.usage?.completion_tokens;
        const actualModelUsed = data.model || model;

        return {
          content,
          modelUsed: actualModelUsed,
          finishReason,
          completionTokens,
          maxTokensSent: options.maxTokens,
          rawLength: content.length,
        };
      } catch (err: any) {
        if (err instanceof AuthRejectedError) {
          throw err;
        }
        errorsRecorded[model] = redactKeys(
          err?.message || String(err),
          this.apiKey ? [this.apiKey] : [],
        );
      }
    }

    throw new CustomOpenAIExhaustedError(stage, errorsRecorded);
  }
}
