import { OpenAIProvider, OpenAIProvidersExhaustedError } from "../openai";

/**
 * Self-contained test suite for OpenAIProvider fallback & rate limit resilience
 */
export async function runOpenAITests(): Promise<boolean> {
  const originalFetch = globalThis.fetch;
  let passed = true;

  console.log("▶ [Test 1] Testing 429 failover to secondary OpenAI model...");
  try {
    const provider = new OpenAIProvider({
      apiKey: "test-openai-key",
      stageModels: {
        patch_generation: ["gpt-4o", "gpt-4o-mini"],
        explanation_generation: [],
        default: [],
      },
    });

    let callCount = 0;
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      callCount++;
      const body = JSON.parse((init?.body as string) || "{}");

      if (body.model === "gpt-4o") {
        return new Response("Rate limit reached for gpt-4o", {
          status: 429,
          statusText: "Too Many Requests",
        });
      }

      if (body.model === "gpt-4o-mini") {
        return new Response(
          JSON.stringify({
            choices: [{ message: { content: "Patch completion from gpt-4o-mini" } }],
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      }

      return new Response("Not Found", { status: 404 });
    }) as typeof fetch;

    const result = await provider.generateChatCompletion(
      [{ role: "user", content: "Generate patch" }],
      "patch_generation",
    );

    if (callCount === 2 && result.modelUsed === "gpt-4o-mini") {
      console.log("  ✓ SUCCESS: Correctly failed over to secondary model upon receiving 429!");
    } else {
      console.error(`  ✖ FAIL: Expected gpt-4o-mini, got ${result.modelUsed}`);
      passed = false;
    }
  } catch (err: any) {
    console.error("  ✖ FAIL with exception:", err);
    passed = false;
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log("\n▶ [Test 2] Testing OpenAIProvidersExhaustedError when all models fail...");
  try {
    const provider = new OpenAIProvider({
      apiKey: "test-openai-key",
      stageModels: {
        patch_generation: ["gpt-4o", "gpt-4o-mini"],
        explanation_generation: [],
        default: [],
      },
    });

    globalThis.fetch = (async () => {
      return new Response("Quota Exceeded", { status: 402 });
    }) as typeof fetch;

    await provider.generateChatCompletion(
      [{ role: "user", content: "Test" }],
      "patch_generation",
    );
    console.error("  ✖ FAIL: Expected OpenAIProvidersExhaustedError, but no error was thrown.");
    passed = false;
  } catch (err: any) {
    if (err instanceof OpenAIProvidersExhaustedError || err?.name === "OpenAIProvidersExhaustedError") {
      console.log("  ✓ SUCCESS: Correctly raised OpenAIProvidersExhaustedError when all providers were exhausted!");
    } else {
      console.error("  ✖ FAIL: Caught unexpected error type:", err);
      passed = false;
    }
  } finally {
    globalThis.fetch = originalFetch;
  }

  return passed;
}

// Auto-run if executed directly
if (typeof process !== "undefined" && (process as any).argv?.[1]?.includes("openai.test.ts")) {
  runOpenAITests().then((ok) => {
    if (!ok) process.exit(1);
  });
}
