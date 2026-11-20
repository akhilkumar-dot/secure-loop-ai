/**
 * src/lib/__tests__/benchmark.test.ts
 *
 * Unit tests for Benchmark Runner (Part B — 50 Samples Suite).
 * Verifies detection accuracy, false positive rate, patch validation rate,
 * Wilson confidence intervals, language scoping (JS/TS in-scope vs Java/Python),
 * and false-positive override handling.
 */

import { describe, it, expect } from "vitest";
import { runBenchmark, BENCHMARK_SAMPLES, computeWilsonScoreInterval } from "../benchmark-runner";

describe("runBenchmark Suite (50 Samples)", () => {
  it("includes all 50 samples across all 5 vuln classes (at least 6 vuln + 4 safe each)", () => {
    expect(BENCHMARK_SAMPLES).toHaveLength(50);
    const classes = ["sqli", "xss", "csrf", "insecure_deserialization", "other"];

    for (const c of classes) {
      const classSamples = BENCHMARK_SAMPLES.filter((s) => s.vulnClass === c);
      const vuln = classSamples.filter((s) => s.isVulnerable).length;
      const safe = classSamples.filter((s) => !s.isVulnerable).length;
      expect(vuln, `Class ${c} must have at least 6 vulnerable samples`).toBeGreaterThanOrEqual(6);
      expect(safe, `Class ${c} must have at least 4 safe control samples`).toBeGreaterThanOrEqual(4);
    }
  });

  it("runs the full benchmark suite and produces valid honest metrics with Wilson CIs", () => {
    const summary = runBenchmark();

    expect(summary.totalSamples).toBe(50);
    expect(summary.vulnerableCount).toBe(30);
    expect(summary.safeControlCount).toBe(20);

    // Detection rate (recall)
    expect(summary.detectionRate).toBeGreaterThanOrEqual(50);
    expect(summary.recallWilson.lower).toBeGreaterThanOrEqual(30);
    expect(summary.recallWilson.upper).toBeLessThanOrEqual(100);

    // False positive rate on safe controls
    expect(summary.falsePositiveRate).toBeGreaterThanOrEqual(0);
    expect(summary.falsePositiveRate).toBeLessThanOrEqual(60);
    expect(summary.fprWilson.lower).toBeGreaterThanOrEqual(0);
    expect(summary.fprWilson.upper).toBeLessThanOrEqual(100);

    // Patch validation success rate (primary: on detected samples)
    expect(summary.patchPassRateDetected).toBeGreaterThanOrEqual(50);
    expect(summary.patchSuccessRate).toBe(summary.patchPassRateDetected);

    // Confusion matrix
    expect(summary.confusionMatrix.tp + summary.confusionMatrix.fn).toBe(30);
    expect(summary.confusionMatrix.fp + summary.confusionMatrix.tn).toBe(20);

    // Scope separation (B5)
    expect(summary.inScope.totalSamples).toBe(44); // 44 JS/TS samples
    expect(summary.outOfScope.totalSamples).toBe(6); // 5 Java + 1 Python

    // Runtime should be recorded
    expect(summary.totalRuntimeMs).toBeGreaterThan(0);
    expect(summary.sampleResults).toHaveLength(50);
  });

  it("does not fire on the safe SQL control samples", () => {
    const summary = runBenchmark();
    const safeSqli4 = summary.sampleResults.find((s) => s.sampleId === "sqli-04");
    expect(safeSqli4).toBeDefined();
    expect(safeSqli4!.detected).toBe(false);

    const safeSqli8 = summary.sampleResults.find((s) => s.sampleId === "sqli-08");
    expect(safeSqli8).toBeDefined();
    expect(safeSqli8!.detected).toBe(false);
  });

  it("does not fire on the safe XSS textContent samples", () => {
    const summary = runBenchmark();
    const safeXss4 = summary.sampleResults.find((s) => s.sampleId === "xss-04");
    expect(safeXss4).toBeDefined();
    expect(safeXss4!.detected).toBe(false);

    const safeXss8 = summary.sampleResults.find((s) => s.sampleId === "xss-08");
    expect(safeXss8).toBeDefined();
    expect(safeXss8!.detected).toBe(false);
  });

  it("computes Wilson score confidence interval accurately", () => {
    // 0 out of 10
    const zero = computeWilsonScoreInterval(0, 10);
    expect(zero.point).toBe(0);
    expect(zero.lower).toBe(0);
    expect(zero.upper).toBeGreaterThan(0);

    // 10 out of 10
    const full = computeWilsonScoreInterval(10, 10);
    expect(full.point).toBe(100);
    expect(full.lower).toBeLessThan(100);
    expect(full.upper).toBe(100);

    // 8 out of 10 (80%)
    const partial = computeWilsonScoreInterval(8, 10);
    expect(partial.point).toBe(80);
    expect(partial.lower).toBeGreaterThan(45);
    expect(partial.upper).toBeLessThan(98);
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
