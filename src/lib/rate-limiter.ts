/**
 * Client-Side Rate Limiter, Sequential Queue, and Retry with Backoff & Jitter
 *
 * Enforces per-provider rate limits so free-tier keys (e.g. Gemini 15 RPM, Groq 30 RPM)
 * do not hit 429 Quota Exceeded during scans.
 */
import { detectProvider, redactKeys, type DetectedProvider } from "./ai-provider-detector";

export interface RateLimitConfig {
  requestsPerMinute: number;
  minIntervalMs: number;
  baseBackoffMs: number;
  maxRetries: number;
}

export const PROVIDER_LIMITS: Record<DetectedProvider, RateLimitConfig> = {
  gemini: {
    requestsPerMinute: 14,
    minIntervalMs: 4200, // Safe buffer for 15 RPM limit (~4.2s per request)
    baseBackoffMs: 2000,
    maxRetries: 3,
  },
  groq: {
    requestsPerMinute: 25,
    minIntervalMs: 2400, // Safe buffer for 30 RPM limit (~2.4s per request)
    baseBackoffMs: 1500,
    maxRetries: 3,
  },
  openrouter: {
    requestsPerMinute: 15,
    minIntervalMs: 4000,
    baseBackoffMs: 2000,
    maxRetries: 3,
  },
  openai: {
    requestsPerMinute: 15,
    minIntervalMs: 4000,
    baseBackoffMs: 2000,
    maxRetries: 3,
  },
  cohere: {
    requestsPerMinute: 10,
    minIntervalMs: 6000,
    baseBackoffMs: 2500,
    maxRetries: 3,
  },
  unknown: {
    requestsPerMinute: 10,
    minIntervalMs: 5000,
    baseBackoffMs: 2000,
    maxRetries: 2,
  },
};

/**
 * Calculates exponential backoff with jitter:
 * delay = baseMs * 2^attempt ± 25% jitter
 */
export function calculateBackoff(
  attempt: number,
  baseMs: number = 2000,
  randomFn: () => number = Math.random,
): number {
  const exp = baseMs * Math.pow(2, attempt);
  const jitterRange = exp * 0.25; // ±25%
  const jitter = (randomFn() * 2 - 1) * jitterRange;
  return Math.max(500, Math.round(exp + jitter));
}

/**
 * Checks if an error message represents a rate limit / quota / transient error.
 */
export function isTransientError(errorText: string): boolean {
  const lower = (errorText || "").toLowerCase();
  return (
    lower.includes("429") ||
    lower.includes("quota") ||
    lower.includes("resource_exhausted") ||
    lower.includes("rate limit") ||
    lower.includes("too many requests") ||
    lower.includes("503") ||
    lower.includes("service unavailable") ||
    lower.includes("timeout") ||
    lower.includes("deadline exceeded")
  );
}

/**
 * Per-provider sequential request queue to ensure requests are never fired
 * faster than the configured minimum interval.
 */
class ProviderRequestQueue {
  private lastRequestEnd: Record<string, number> = {};
  private activeLocks: Record<string, Promise<void>> = {};

  async run<T>(
    provider: DetectedProvider,
    task: () => Promise<T>,
    sleepFn?: (ms: number) => Promise<void>,
  ): Promise<T> {
    const config = PROVIDER_LIMITS[provider] ?? PROVIDER_LIMITS.unknown;
    const key = provider;
    const sleep = sleepFn ?? ((ms) => new Promise((r) => setTimeout(r, ms)));

    // Chain onto the current active promise for this provider
    const previousLock = this.activeLocks[key] ?? Promise.resolve();

    let releaseLock!: () => void;
    this.activeLocks[key] = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    try {
      await previousLock;

      // Ensure minimum interval has elapsed since last request
      const now = Date.now();
      const elapsed = now - (this.lastRequestEnd[key] ?? 0);
      const waitTime = config.minIntervalMs - elapsed;
      if (waitTime > 0) {
        await sleep(waitTime);
      }

      const result = await task();
      return result;
    } finally {
      this.lastRequestEnd[key] = Date.now();
      releaseLock();
    }
  }

  /** Reset queues (useful in tests) */
  clear() {
    this.lastRequestEnd = {};
    this.activeLocks = {};
  }
}

export const providerQueue = new ProviderRequestQueue();

export class AiExecutionError extends Error {
  isAiError = true;
  provider: DetectedProvider;
  keyType: "primary" | "backup" | "both";
  originalDetails: string;

  constructor(
    message: string,
    provider: DetectedProvider,
    keyType: "primary" | "backup" | "both",
    originalDetails: string,
  ) {
    super(message);
    this.name = "AiExecutionError";
    this.provider = provider;
    this.keyType = keyType;
    this.originalDetails = originalDetails;
  }
}

export interface RetryCallbackInfo {
  attempt: number;
  delayMs: number;
  error: string;
  usingBackup: boolean;
  provider: DetectedProvider;
}

/**
 * Executes an AI call with:
 * 1. Rate limiter + sequential queue
 * 2. Exponential backoff and jitter on 429/quota/transient errors
 * 3. Fallback to backup key if primary key is exhausted
 * 4. Automatic key redaction in all error messages
 */
export async function executeWithRateLimitAndFallback<T>(params: {
  primaryKey: string;
  backupKey?: string | undefined;
  execute: (apiKey: string, provider: DetectedProvider) => Promise<T>;
  onRetry?: ((info: RetryCallbackInfo) => void) | undefined;
  sleepFn?: ((ms: number) => Promise<void>) | undefined;
}): Promise<{ result: T; keyUsed: "primary" | "backup"; providerUsed: DetectedProvider }> {
  const primaryKey = (params.primaryKey || "").trim();
  const backupKey = (params.backupKey || "").trim();
  const sleep = params.sleepFn ?? ((ms) => new Promise((r) => setTimeout(r, ms)));

  if (!primaryKey && !backupKey) {
    throw new AiExecutionError(
      "No AI API key provided. Please enter a valid key in the Pipeline Configuration.",
      "unknown",
      "primary",
      "No key provided",
    );
  }

  const allActiveKeys = [primaryKey, backupKey].filter(Boolean);

  // Helper to attempt with a specific key
  async function attemptWithKey(
    keyToUse: string,
    isBackup: boolean,
  ): Promise<{ result: T; provider: DetectedProvider }> {
    const provider = detectProvider(keyToUse);
    const config = PROVIDER_LIMITS[provider] ?? PROVIDER_LIMITS.unknown;
    let lastError = "";

    for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
      try {
        const result = await providerQueue.run(
          provider,
          () => params.execute(keyToUse, provider),
          params.sleepFn,
        );
        return { result, provider };
      } catch (err: any) {
        const rawMsg = err?.message || String(err);
        const sanitizedMsg = redactKeys(rawMsg, allActiveKeys);
        lastError = sanitizedMsg;

        const isTransient = isTransientError(sanitizedMsg);
        if (isTransient && attempt < config.maxRetries) {
          const delayMs = calculateBackoff(attempt, config.baseBackoffMs);
          params.onRetry?.({
            attempt: attempt + 1,
            delayMs,
            error: sanitizedMsg,
            usingBackup: isBackup,
            provider,
          });
          await sleep(delayMs);
          continue;
        }

        // If non-transient or final attempt, break out to key fallback or error
        break;
      }
    }

    throw new Error(lastError);
  }

  // 1. Try Primary Key
  let primaryError: string | null = null;
  if (primaryKey) {
    try {
      const { result, provider } = await attemptWithKey(primaryKey, false);
      return { result, keyUsed: "primary", providerUsed: provider };
    } catch (err: any) {
      primaryError = redactKeys(err?.message || String(err), allActiveKeys);
    }
  }

  // 2. Fallback to Backup Key if provided
  if (backupKey && backupKey !== primaryKey) {
    try {
      const { result, provider } = await attemptWithKey(backupKey, true);
      return { result, keyUsed: "backup", providerUsed: provider };
    } catch (backupErr: any) {
      const backupError = redactKeys(backupErr?.message || String(backupErr), allActiveKeys);
      throw new AiExecutionError(
        `Both primary and backup AI providers failed. Primary error: ${primaryError}. Backup error: ${backupError}`,
        detectProvider(backupKey),
        "both",
        backupError,
      );
    }
  }

  // If no backup key, throw primary failure
  throw new AiExecutionError(
    `AI generation failed: ${primaryError || "Unknown provider error"}. Please check your API key quota or try adding a backup key.`,
    detectProvider(primaryKey),
    "primary",
    primaryError || "Failed",
  );
}
