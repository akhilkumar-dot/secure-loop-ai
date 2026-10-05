import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: "node",
    // Only include files that are proper vitest suites (exclude the old custom-runner files)
    include: [
      "src/**/__tests__/patch.test.ts",
      "src/**/__tests__/sast.test.ts",
      "src/**/__tests__/score.test.ts",
    ],
    globals: true,
  },
});
