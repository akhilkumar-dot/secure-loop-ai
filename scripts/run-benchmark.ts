/**
 * scripts/run-benchmark.ts
 *
 * CLI command to run the full SecureLoop benchmark suite.
 * Run with: npm run benchmark
 */

import { runBenchmark } from "../src/lib/benchmark-runner";

console.log("====================================================");
console.log("       SecureLoop SAST & Validation Benchmark        ");
console.log("====================================================\n");

const summary = runBenchmark();

console.log("────────────────────────────────────────────────────");
console.log("Summary Metrics (Honest Evaluation):");
console.log("────────────────────────────────────────────────────");
console.log(`Total Samples:              ${summary.totalSamples} (Vulnerable: ${summary.vulnerableCount}, Safe Controls: ${summary.safeControlCount})`);
console.log(`Detection Rate (Recall):    ${summary.detectionRate}% (${summary.truePositives} / ${summary.vulnerableCount})`);
console.log(`False Positive Rate:        ${summary.falsePositiveRate}% (${summary.falsePositives} / ${summary.safeControlCount})`);
console.log(`Patch Validation Rate:      ${summary.patchSuccessRate}%`);
console.log(`Total Runtime:              ${summary.totalRuntimeMs}ms`);
console.log("────────────────────────────────────────────────────\n");

console.log("Sample Details:");
console.table(
  summary.sampleResults.map((r) => ({
    ID: r.sampleId,
    Class: r.vulnClass,
    CWE: r.cwe,
    Vulnerable: r.isVulnerable ? "YES" : "NO (control)",
    Detected: r.detected ? "YES" : "NO",
    "Rule Match": r.ruleMatched ? "YES" : "NO",
    "Patch Valid": r.patchValid === null ? "N/A" : r.patchValid ? "PASS" : "FAIL",
    "Time(ms)": r.runtimeMs,
  })),
);

console.log("\nComparison template available at: benchmark/comparison-template.csv");

