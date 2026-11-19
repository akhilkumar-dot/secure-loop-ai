/**
 * src/lib/__tests__/benchmark.test.ts
 *
 * Unit tests for Benchmark Runner (Review 3 Phase 3).
 * Verifies detection accuracy, false positive rate, patch validation rate,
 * and false-positive override handling.
 */

import { describe, it, expect } from "vitest";
import { runBenchmark, BENCHMARK_SAMPLES } from "../benchmark-runner";

describe("runBenchmark Suite", () => {
  it("includes all 25 samples across 4 vuln classes plus controls", () => {
    expect(BENCHMARK_SAMPLES).toHaveLength(25);
    const classes = new Set(BENCHMARK_SAMPLES.map((s) => s.vulnClass));
    expect(classes.has("sqli")).toBe(true);
    expect(classes.has("xss")).toBe(true);
    expect(classes.has("csrf")).toBe(true);
    expect(classes.has("insecure_deserialization")).toBe(true);
  });

  it("runs the full benchmark suite and produces valid metrics", () => {
    const summary = runBenchmark();

    expect(summary.totalSamples).toBe(25);
    expect(summary.vulnerableCount).toBe(18);
    expect(summary.safeControlCount).toBe(7);

    // Detection rate reflects honest SAST evaluation on open-source snippets
    expect(summary.detectionRate).toBeGreaterThanOrEqual(60);

    // False positive rate on safe controls (honest evaluation including secondary rule firings)
    expect(summary.falsePositiveRate).toBeGreaterThanOrEqual(0);
    expect(summary.falsePositiveRate).toBeLessThanOrEqual(60);

    // Patch validation success rate (deterministic validation including non-JS rejections)
    expect(summary.patchSuccessRate).toBeGreaterThanOrEqual(50);

    // Runtime should be recorded
    expect(summary.totalRuntimeMs).toBeGreaterThan(0);
    expect(summary.sampleResults).toHaveLength(25);
  });

  it("does not fire on the safe SQL control sample", () => {
    const summary = runBenchmark();
    const safeSqli = summary.sampleResults.find((s) => s.sampleId === "sqli-04");
    expect(safeSqli).toBeDefined();
    expect(safeSqli!.detected).toBe(false);
  });

  it("does not fire on the safe XSS textContent sample", () => {
    const summary = runBenchmark();
    const safeXss = summary.sampleResults.find((s) => s.sampleId === "xss-04");
    expect(safeXss).toBeDefined();
    expect(safeXss!.detected).toBe(false);
  });

  it("recomputes metrics when manual false positives are provided", () => {
    const initial = runBenchmark();
    const initialFP = initial.falsePositives;
    const initialTP = initial.truePositives;

    // Mark sample sqli-02 (which is detected) as manual false positive
    const updated = runBenchmark({ "sqli-02": true });
    expect(updated.falsePositives).toBe(initialFP + 1);
    expect(updated.truePositives).toBe(initialTP - 1);
  });
});
