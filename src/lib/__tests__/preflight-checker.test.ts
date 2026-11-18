/**
 * src/lib/__tests__/preflight-checker.test.ts
 *
 * Tests for:
 * 1. Pre-flight API key check (fast 401/403 fail, provider rejection message)
 * 2. CustomOpenAIProvider & fetchCustomEndpointModels
 * 3. URL validation and key format handling in getProvider
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { preflightCheckProvider } from "../preflight-checker";
import {
  CustomOpenAIProvider,
  AuthRejectedError,
  fetchCustomEndpointModels,
} from "../custom-openai";
import { getProvider } from "../ai-pipeline";

describe("Pre-flight API Key & Provider Verification", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns error immediately when key is empty", async () => {
    const res = await preflightCheckProvider("");
    expect(res.ok).toBe(false);
    expect(res.errorMessage).toContain("No API key provided");
  });

  it("returns unknown error when key format is unrecognized and no override given", async () => {
    const res = await preflightCheckProvider("unrecognized-random-format-12345");
    expect(res.ok).toBe(false);
    expect(res.errorMessage).toContain("Choose the provider manually");
    expect(res.keyHint).toBe("••••2345");
  });

  it("identifies Groq 401 and reports honest provider rejection message", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ error: { message: "Invalid API Key" } }),
    } as any);

    const res = await preflightCheckProvider("gsk_fakeGroqKey1234567890abcdef");
    expect(res.ok).toBe(false);
    expect(res.isAuthError).toBe(true);
    expect(res.provider).toBe("groq");
    expect(res.errorMessage).toBe(
      "Groq rejected your API key (HTTP 401). Check that the key belongs to Groq.",
    );
    expect(res.keyHint).toBe("••••cdef");
  });

  it("identifies Gemini API_KEY_INVALID and reports honest rejection", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: async () =>
        JSON.stringify({
          error: {
            code: 400,
            message: "API key not valid. Please pass a valid API key.",
            status: "INVALID_ARGUMENT",
            details: [{ reason: "API_KEY_INVALID" }],
          },
        }),
    } as any);

    const res = await preflightCheckProvider("AIzaSyD_fakeGeminiKey1234567890");
    expect(res.ok).toBe(false);
    expect(res.isAuthError).toBe(true);
    expect(res.provider).toBe("gemini");
    expect(res.errorMessage).toContain("Google Gemini rejected your API key");
  });

  it("identifies OpenRouter 401 auth rejection", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ error: { message: "Unauthorized" } }),
    } as any);

    const res = await preflightCheckProvider("sk-or-v1-fakeOpenRouterKey12345");
    expect(res.ok).toBe(false);
    expect(res.isAuthError).toBe(true);
    expect(res.provider).toBe("openrouter");
    expect(res.errorMessage).toBe(
      "OpenRouter rejected your API key (HTTP 401). Check that the key belongs to OpenRouter.",
    );
  });

  it("identifies FreeLLMAPI endpoint 401 auth rejection", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "Unauthorized proxy access",
    } as any);

    const res = await preflightCheckProvider("freellmapi-unified-token-9999", {
      baseUrl: "http://localhost:3001/v1",
    });
    expect(res.ok).toBe(false);
    expect(res.isAuthError).toBe(true);
    expect(res.provider).toBe("freellmapi");
    expect(res.errorMessage).toContain("FreeLLMAPI rejected your API key (HTTP 401)");
  });

  it("rejects invalid custom endpoint URLs during preflight check", async () => {
    const res = await preflightCheckProvider("freellmapi-token-1234", {
      baseUrl: "ftp://localhost:3001",
    });
    expect(res.ok).toBe(false);
    expect(res.isAuthError).toBe(false);
    expect(res.errorMessage).toContain("Unsupported protocol");
  });

  it("returns ok: true when preflight authentication succeeds", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ data: [{ id: "openai/gpt-oss-120b" }] }),
    } as any);

    const res = await preflightCheckProvider("gsk_validGroqKey12345678");
    expect(res.ok).toBe(true);
    expect(res.isAuthError).toBe(false);
    expect(res.provider).toBe("groq");
  });
});

describe("CustomOpenAIProvider & fetchCustomEndpointModels", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("fetches live models from custom endpoint", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        data: [
          { id: "freellmapi/auto" },
          { id: "openai/gpt-oss-120b" },
          { id: "qwen/qwen3.6-27b" },
        ],
      }),
    } as any);

    const models = await fetchCustomEndpointModels(
      "http://localhost:3001/v1",
      "freellmapi-test-key",
    );
    expect(models).toEqual(["freellmapi/auto", "openai/gpt-oss-120b", "qwen/qwen3.6-27b"]);
  });

  it("throws AuthRejectedError when endpoint returns 401 on /models", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "Invalid proxy token",
    } as any);

    await expect(
      fetchCustomEndpointModels("http://localhost:3001/v1", "freellmapi-bad-key"),
    ).rejects.toThrow(AuthRejectedError);
  });

  it("executes chat completion and returns structured result with usage", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        id: "chatcmpl-123",
        model: "freellmapi/auto",
        choices: [
          {
            message: { role: "assistant", content: '{"diff":"@@ -1 +1 @@","explanation":"fixed"}' },
            finish_reason: "stop",
          },
        ],
        usage: { completion_tokens: 42, total_tokens: 120 },
      }),
    } as any);

    const provider = new CustomOpenAIProvider({
      apiKey: "freellmapi-unified-token",
      baseUrl: "http://localhost:3001/v1",
      defaultModel: "freellmapi/auto",
    });

    const res = await provider.generateChatCompletion([
      { role: "user", content: "Write a security patch" },
    ]);

    expect(res.content).toBe('{"diff":"@@ -1 +1 @@","explanation":"fixed"}');
    expect(res.modelUsed).toBe("freellmapi/auto");
    expect(res.finishReason).toBe("stop");
    expect(res.completionTokens).toBe(42);
  });

  it("throws AuthRejectedError on 401/403 during chat completion", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "Unauthorized endpoint call",
    } as any);

    const provider = new CustomOpenAIProvider({
      apiKey: "freellmapi-bad-key",
      baseUrl: "http://localhost:3001/v1",
      providerName: "FreeLLMAPI",
    });

    await expect(
      provider.generateChatCompletion([{ role: "user", content: "test" }]),
    ).rejects.toThrow(AuthRejectedError);
  });
});

describe("Pipeline getProvider Routing", () => {
  it("routes freellmapi- keys to CustomOpenAIProvider", () => {
    const provider = getProvider("freellmapi-token-xyz-12345");
    expect(provider).toBeInstanceOf(CustomOpenAIProvider);
  });

  it("routes explicit custom_openai override to CustomOpenAIProvider", () => {
    const provider = getProvider("some-custom-token-9999", {
      explicitProvider: "custom_openai",
    });
    expect(provider).toBeInstanceOf(CustomOpenAIProvider);
  });

  it("throws honest error for unknown key without defaulting to Cohere or Gemini", () => {
    expect(() => getProvider("unknown-token-style-abcdef")).toThrow(
      "Key format not recognized. Choose the provider manually from the dropdown.",
    );
  });
});
