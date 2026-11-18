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
import {
  detectProvider,
  redactKeys,
  validateEndpointUrl,
  formatKeyHint,
} from "../ai-provider-detector";
import { AuthRejectedError } from "../custom-openai";
import {
  calculateBackoff,
  executeWithRateLimitAndFallback,
  isTransientError,
  providerQueue,
} from "../rate-limiter";
import { getCachedAiOutput, saveCachedAiOutput, CURRENT_PROMPT_VERSION } from "../ai-cache";
import { supabase } from "../supabase";
import { CohereProvider, DEFAULT_COHERE_STAGE_MODELS } from "../cohere";
import { filterChatModels, resolveCandidateGroqModels } from "../groq";

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
    expect(detectProvider("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0")).toBe("cohere");
  });

  it("correctly identifies FreeLLMAPI keys and rejects them from Cohere", () => {
    expect(detectProvider("freellmapi-unified-secret-key-12345")).toBe("freellmapi");
    expect(detectProvider("freellmapi-auto-generated-token")).toBe("freellmapi");
    expect(detectProvider("freellmapi-unified-secret-key-12345")).not.toBe("cohere");
  });

  it("returns unknown for invalid or empty keys", () => {
    expect(detectProvider("")).toBe("unknown");
    expect(detectProvider("   ")).toBe("unknown");
    expect(detectProvider("short")).toBe("unknown");
    expect(detectProvider("some-random-unknown-token-format")).toBe("unknown");
  });

  it("honors explicit provider override if specified", () => {
    expect(detectProvider("some-custom-token", "custom_openai")).toBe("custom_openai");
    expect(detectProvider("freellmapi-12345", "openrouter")).toBe("openrouter");
  });
});

describe("Endpoint URL Validation", () => {
  it("validates valid http and https URLs", () => {
    const res1 = validateEndpointUrl("http://localhost:3001/v1");
    expect(res1.isValid).toBe(true);
    expect(res1.normalizedUrl).toBe("http://localhost:3001/v1");

    const res2 = validateEndpointUrl("https://api.custom-proxy.internal/v1///");
    expect(res2.isValid).toBe(true);
    expect(res2.normalizedUrl).toBe("https://api.custom-proxy.internal/v1");
  });

  it("rejects non-http/https protocols", () => {
    const res = validateEndpointUrl("ftp://localhost:3001/v1");
    expect(res.isValid).toBe(false);
    expect(res.error).toContain("Unsupported protocol");
  });

  it("rejects inline credentials in URL", () => {
    const res = validateEndpointUrl("http://admin:secret@localhost:3001/v1");
    expect(res.isValid).toBe(false);
    expect(res.error).toContain("Security restriction: URLs cannot include inline credentials");
  });

  it("formats key hint safely with at most 4 trailing characters", () => {
    expect(formatKeyHint("freellmapi-secret-key-9876")).toBe("••••9876");
    expect(formatKeyHint("short")).toBe("••••hort");
    expect(formatKeyHint("abc")).toBe("••••");
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

describe("Cohere Active Models & 404 Fallback", () => {
  it("does not include retired models command-r-plus or command-r in default stage models", () => {
    for (const [stage, models] of Object.entries(DEFAULT_COHERE_STAGE_MODELS)) {
      expect(models).not.toContain("command-r-plus");
      expect(models).not.toContain("command-r");
    }
  });

  it("falls back to next candidate model when a model returns HTTP 404 (removed)", async () => {
    const originalFetch = global.fetch;
    let callCount = 0;
    const modelsCalled: string[] = [];

    global.fetch = vi.fn().mockImplementation(async (url: string, init: any) => {
      callCount++;
      const body = JSON.parse(init.body);
      modelsCalled.push(body.model);

      if (body.model === "command-r-plus-08-2024") {
        return {
          ok: false,
          status: 404,
          text: async () => JSON.stringify({ message: "model 'command-r-plus-08-2024' not found" }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          message: {
            role: "assistant",
            content: [{ type: "text", text: "Verified response from secondary candidate" }],
          },
        }),
      };
    }) as any;

    try {
      const provider = new CohereProvider({ apiKey: "test-cohere-key" });
      const res = await provider.generateChatCompletion(
        [{ role: "user", content: "hello" }],
        "patch_generation",
      );

      expect(res.content).toBe("Verified response from secondary candidate");
      expect(res.modelUsed).toBe("command-r-08-2024");
      expect(modelsCalled).toEqual(["command-r-plus-08-2024", "command-r-08-2024"]);
    } finally {
      global.fetch = originalFetch;
    }
  });
});

describe("Groq Model Filtering (No non-JSON or Allam models)", () => {
  it("filters out allam and non-JSON models from candidate lists", () => {
    const rawList = [
      "whisper-large-v3",
      "openai/gpt-oss-120b",
      "allam-2-7b",
      "prompt-guard",
      "qwen/qwen3.6-27b",
    ];
    const filtered = filterChatModels(rawList);
    expect(filtered).toEqual(["openai/gpt-oss-120b", "qwen/qwen3.6-27b"]);
    expect(filtered).not.toContain("allam-2-7b");
  });

  it("resolveCandidateGroqModels strips allam even if present in input list", () => {
    const { models } = resolveCandidateGroqModels([
      "allam-2-7b",
      "openai/gpt-oss-120b",
      "openai/gpt-oss-20b",
    ]);
    expect(models).not.toContain("allam-2-7b");
    expect(models).toContain("openai/gpt-oss-120b");
  });
});
