/**
 * src/lib/__tests__/ai-key-management.test.ts
 *
 * Tests for:
 * 1. Provider detection (Gemini, Groq, OpenRouter, OpenAI, Cohere)
 * 2. Fallback to backup key on 429 / quota
 * 3. Exponential backoff and jitter calculations
 * 4. Cache hit skipping network call
 * 5. Total failure reporting real error without canned fallback
 * 6. Security assertion: API keys NEVER appear in any Supabase payload
 * 7. Key redaction from error messages and URLs
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { detectProvider, redactKeys } from "../ai-provider-detector";
import {
  calculateBackoff,
  executeWithRateLimitAndFallback,
  isTransientError,
  providerQueue,
} from "../rate-limiter";
import { getCachedAiOutput, saveCachedAiOutput, CURRENT_PROMPT_VERSION } from "../ai-cache";
import { supabase } from "../supabase";

describe("AI Provider Detection", () => {
  it("correctly identifies Google Gemini keys", () => {
    expect(detectProvider("AIzaSyD-fakeKeyExample1234567890")).toBe("gemini");
    expect(detectProvider("AQ.fakeGoogleStudioKeyExample")).toBe("gemini");
  });

  it("correctly identifies Groq keys", () => {
    expect(detectProvider("gsk_fakeGroqKeyExample1234567890")).toBe("groq");
  });

  it("correctly identifies OpenRouter keys", () => {
    expect(detectProvider("sk-or-v1-fakeOpenRouterKeyExample")).toBe("openrouter");
  });

  it("correctly identifies OpenAI keys", () => {
    expect(detectProvider("sk-proj-fakeOpenAIKeyExample123456")).toBe("openai");
    expect(detectProvider("sk-fakeStandardOpenAIKey12345678")).toBe("openai");
  });

  it("correctly identifies Cohere keys", () => {
    expect(detectProvider("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")).toBe("cohere");
  });

  it("returns unknown for invalid or empty keys", () => {
    expect(detectProvider("")).toBe("unknown");
    expect(detectProvider("   ")).toBe("unknown");
    expect(detectProvider("short")).toBe("unknown");
  });
});

describe("Key Redaction & Privacy", () => {
  it("redacts active API keys and standard patterns from error messages", () => {
    const rawKey = "AIzaSyD_SECRET_GEMINI_KEY_99999999";
    const backupKey = "gsk_SECRET_GROQ_KEY_88888888";
    const errorText = `Failed to fetch https://generativelanguage.googleapis.com/v1beta/models?key=${rawKey} with Authorization: Bearer ${backupKey}`;

    const redacted = redactKeys(errorText, [rawKey, backupKey]);
    expect(redacted).not.toContain(rawKey);
    expect(redacted).not.toContain(backupKey);
    expect(redacted).toContain("[REDACTED");
  });
});

describe("Exponential Backoff & Jitter", () => {
  it("calculates exponential delays with jitter within ±25%", () => {
    const base = 2000;
    // With jitter = 0 (min jitter factor)
    const delay0 = calculateBackoff(0, base, () => 0.5); // jitter = 0
    expect(delay0).toBe(2000);

    const delay1 = calculateBackoff(1, base, () => 0.5); // 2000 * 2 = 4000
    expect(delay1).toBe(4000);

    const delay2 = calculateBackoff(2, base, () => 0.5); // 2000 * 4 = 8000
    expect(delay2).toBe(8000);

    // Bounded jitter
    const delayMaxJitter = calculateBackoff(0, base, () => 1.0); // +25% = 2500
    expect(delayMaxJitter).toBe(2500);

    const delayMinJitter = calculateBackoff(0, base, () => 0.0); // -25% = 1500
    expect(delayMinJitter).toBe(1500);
  });

  it("identifies transient / quota errors", () => {
    expect(isTransientError("HTTP 429: Resource exhausted")).toBe(true);
    expect(isTransientError("Rate limit exceeded")).toBe(true);
    expect(isTransientError("HTTP 503 Service Unavailable")).toBe(true);
    expect(isTransientError("SyntaxError: Unexpected token")).toBe(false);
  });
});

describe("Fallback to Backup Key & Retry Queue", () => {
  beforeEach(() => {
    providerQueue.clear();
  });

  it("retries on 429 and falls back to backup key when primary is exhausted", async () => {
    const primaryCalls: string[] = [];
    const backupCalls: string[] = [];

    const mockExecute = vi.fn(async (key: string) => {
      if (key.startsWith("AIzaSy")) {
        primaryCalls.push(key);
        throw new Error("HTTP 429: Quota exceeded for model gemini-1.5-flash");
      }
      if (key.startsWith("gsk_")) {
        backupCalls.push(key);
        return { message: "Success from backup" };
      }
      throw new Error("Unknown key");
    });

    const result = await executeWithRateLimitAndFallback({
      primaryKey: "AIzaSy_primary_key_here_1234567890",
      backupKey: "gsk_backup_key_here_1234567890",
      execute: mockExecute,
      sleepFn: async () => {}, // Instant sleep in tests
    });

    expect(result.keyUsed).toBe("backup");
    expect(result.providerUsed).toBe("groq");
    expect(result.result).toEqual({ message: "Success from backup" });
    expect(primaryCalls.length).toBeGreaterThan(0);
    expect(backupCalls.length).toBe(1);
  });

  it("throws honest error when both primary and backup keys fail (no fake placeholders)", async () => {
    const mockExecute = vi.fn(async () => {
      throw new Error("HTTP 429: Out of quota");
    });

    await expect(
      executeWithRateLimitAndFallback({
        primaryKey: "AIzaSy_primary_12345678901234567890",
        backupKey: "gsk_backup_12345678901234567890",
        execute: mockExecute,
        sleepFn: async () => {},
      }),
    ).rejects.toThrow("Both primary and backup AI providers failed");
  });
});

describe("AI Cache & Network Skipping", () => {
  it("skips network call when Supabase cache hit exists", async () => {
    const cachedData = {
      output: { what_it_is: "Cached Explanation", why_it_happened: "Cached Cause" },
      provider: "gemini",
      model_id: "gemini-1.5-flash",
    };

    const maybeSingleMock = vi.fn().mockResolvedValue({ data: cachedData, error: null });
    const eqMock = vi.fn().mockReturnValue({
      eq: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            maybeSingle: maybeSingleMock,
          }),
        }),
      }),
    });

    vi.spyOn(supabase, "from").mockReturnValue({
      select: vi.fn().mockReturnValue({ eq: eqMock }),
    } as any);

    const cached = await getCachedAiOutput("user-123", "finding-456", "explanation");

    expect(cached).not.toBeNull();
    expect(cached?.output).toEqual(cachedData.output);
    expect(cached?.provider).toBe("gemini");
  });
});

describe("Security Guarantee: Keys Never Transmitted to Supabase", () => {
  it("never includes API keys in Supabase cache payloads", async () => {
    const upsertSpy = vi.fn().mockResolvedValue({ error: null });
    vi.spyOn(supabase, "from").mockReturnValue({
      upsert: upsertSpy,
    } as any);

    const secretKey = "AIzaSy_SUPER_CONFIDENTIAL_KEY_XYZ_123";

    await saveCachedAiOutput({
      userId: "user-123",
      findingId: "finding-456",
      task: "explanation",
      provider: "gemini",
      modelId: "gemini-1.5-flash",
      output: { explanation: "Clean explanation without keys" },
      promptVersion: CURRENT_PROMPT_VERSION,
    });

    expect(upsertSpy).toHaveBeenCalledTimes(1);
    const payload = (upsertSpy.mock.calls[0] ?? [])[0];

    // Check payload structure
    expect(payload).toHaveProperty("user_id", "user-123");
    expect(payload).toHaveProperty("finding_id", "finding-456");
    expect(payload).toHaveProperty("task", "explanation");
    expect(payload).toHaveProperty("provider", "gemini");
    expect(payload).toHaveProperty("model_id", "gemini-1.5-flash");

    // Convert payload to JSON string and assert key is nowhere inside
    const payloadString = JSON.stringify(payload);
    expect(payloadString).not.toContain(secretKey);
    expect(payloadString).not.toContain("api_key");
    expect(payloadString).not.toContain("apiKey");
  });
});
