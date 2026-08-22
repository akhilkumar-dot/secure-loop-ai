import { OpenRouterProvider, AllProvidersExhaustedError } from "../openrouter";

/**
 * Self-contained test suite for OpenRouterProvider fallback & rate limit resilience
 */
export async function runOpenRouterTests(): Promise<boolean> {
  const originalFetch = globalThis.fetch;
  let passed = true;

  console.log("▶ [Test 1] Testing 429 failover to secondary model...");
  try {
    const provider = new OpenRouterProvider({
      apiKey: "test-openrouter-key",
      stageModels: {
        patch_generation: ["model-primary-429", "model-secondary-success"],
        explanation_generation: [],
        default: [],
      },
    });

    let callCount = 0;
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      callCount++;
      const body = JSON.parse((init?.body as string) || "{}");

      if (body.model === "model-primary-429") {
        return new Response("Rate limit reached for model-primary-429", {
          status: 429,
          statusText: "Too Many Requests",
        });
      }

      if (body.model === "model-secondary-success") {
        return new Response(
          JSON.stringify({
            choices: [{ message: { content: "Patch completion from secondary model" } }],
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

    if (callCount === 2 && result.modelUsed === "model-secondary-success") {
      console.log("  ✓ SUCCESS: Correctly failed over to secondary model upon receiving 429!");
    } else {
      console.error(`  ✖ FAIL: Expected model-secondary-success, got ${result.modelUsed}`);
      passed = false;
    }
  } catch (err: any) {
    console.error("  ✖ FAIL with exception:", err);
    passed = false;
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log("\n▶ [Test 2] Testing AllProvidersExhaustedError when all models fail...");
  try {
    const provider = new OpenRouterProvider({
      apiKey: "test-openrouter-key",
      stageModels: {
        patch_generation: ["model-1", "model-2"],
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
    console.error("  ✖ FAIL: Expected AllProvidersExhaustedError, but no error was thrown.");
    passed = false;
  } catch (err: any) {
    if (err instanceof AllProvidersExhaustedError || err?.name === "AllProvidersExhaustedError") {
      console.log("  ✓ SUCCESS: Correctly raised AllProvidersExhaustedError when all providers were exhausted!");
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
if (typeof process !== "undefined" && (process as any).argv?.[1]?.includes("openrouter.test.ts")) {
  runOpenRouterTests().then((ok) => {
    if (!ok) process.exit(1);
  });
}
