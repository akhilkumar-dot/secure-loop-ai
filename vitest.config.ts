import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: "node",
    // Only include files that are proper vitest suites (exclude the old custom-runner files)
    include: [
      "src/**/__tests__/patch.test.ts",
      "src/**/__tests__/zip.test.ts",
      "src/**/__tests__/verify-real-runs.test.ts",
      "src/**/__tests__/sast.test.ts",
      "src/**/__tests__/score.test.ts",
      "src/**/__tests__/misconception.test.ts",
      "src/**/__tests__/quiz-bank.test.ts",
      "src/**/__tests__/spaced-repetition.test.ts",
      "src/**/__tests__/benchmark.test.ts",
      "src/**/__tests__/education-integrity.test.ts",
      "src/**/__tests__/tier-progression.test.ts",
      "src/**/__tests__/ai-key-management.test.ts",
      "src/**/__tests__/preflight-checker.test.ts",
      "src/**/__tests__/preflight-errors.test.ts",
      "src/**/__tests__/explanation-logic.test.ts",
      "src/**/__tests__/explanation-integration.test.ts",
      "src/**/__tests__/decision-actions.test.ts",
      "src/**/__tests__/ai-quiz-generator.test.ts",
    ],
    globals: true,
  },
});
