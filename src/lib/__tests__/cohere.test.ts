import { CohereProvider, CohereProvidersExhaustedError } from "../cohere";

async function runTests() {
  console.log("▶ Running CohereProvider unit tests...\n");

  const originalFetch = global.fetch;

  try {
    // Test 1: Fallback on 429
    console.log("▶ [Test 1] Testing 429 failover to secondary Cohere model...");
    let callCount = 0;
    global.fetch = (async (url: string, init: any) => {
      callCount++;
      const body = JSON.parse(init.body);
      if (body.model === "command-r-plus") {
        return {
          ok: false,
          status: 429,
          text: async () => "Rate limit exceeded for command-r-plus",
        };
      }
      return {
        ok: true,
        json: async () => ({
          message: {
            role: "assistant",
            content: [{ type: "text", text: "Test response from secondary model" }],
          },
        }),
      };
    }) as any;

    const provider = new CohereProvider({ apiKey: "test-cohere-key" });
    const res = await provider.generateChatCompletion(
      [{ role: "user", content: "hello" }],
      "patch_generation",
    );

    if (res.content === "Test response from secondary model" && res.modelUsed === "command-r-plus-08-2024") {
      console.log("  ✓ SUCCESS: Correctly failed over to secondary model upon receiving 429!\n");
    } else {
      throw new Error(`Unexpected result: ${JSON.stringify(res)}`);
    }

    // Test 2: All exhausted
    console.log("▶ [Test 2] Testing CohereProvidersExhaustedError when all models fail...");
    global.fetch = (async () => {
      return {
        ok: false,
        status: 402,
        text: async () => "Quota Exceeded",
      };
    }) as any;

    try {
      await provider.generateChatCompletion(
        [{ role: "user", content: "hello" }],
        "patch_generation",
      );
      throw new Error("Should have thrown CohereProvidersExhaustedError");
    } catch (err: any) {
      if (err instanceof CohereProvidersExhaustedError || err.isExhausted) {
        console.log("  ✓ SUCCESS: Correctly raised CohereProvidersExhaustedError when all models failed!\n");
      } else {
        throw err;
      }
    }

    console.log("🎉 ALL COHERE PROVIDER TESTS PASSED SUCCESSFULLY!");
  } finally {
    global.fetch = originalFetch;
  }
}

runTests().catch((e) => {
  console.error("❌ Test failed:", e);
  process.exit(1);
});
