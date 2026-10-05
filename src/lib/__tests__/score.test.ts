/**
 * src/lib/__tests__/score.test.ts
 * Unit tests for computeScore.
 */
import { describe, it, expect } from "vitest";
import { computeScore } from "../score";

describe("computeScore", () => {
  it("returns 100 for all categories when no findings", () => {
    const score = computeScore([]);
    expect(score.overall).toBe(100);
    expect(score.sqli).toBe(100);
    expect(score.xss).toBe(100);
    expect(score.csrf).toBe(100);
    expect(score.deserialization).toBe(100);
    expect(score.other).toBe(100);
  });

  it("deducts from the correct category for sqli finding", () => {
    const findings = [
      { vulnerability_class: "sqli", severity: "critical", status: "open" },
    ];
    const score = computeScore(findings);
    expect(score.sqli).toBeLessThan(100);
    expect(score.xss).toBe(100); // unaffected
    expect(score.other).toBe(100); // unaffected
  });

  it("deducts from 'other' for command injection (CWE-78)", () => {
    const findings = [
      { vulnerability_class: "other", cwe: "CWE-78", severity: "critical", status: "open" },
    ];
    const score = computeScore(findings);
    expect(score.other).toBeLessThan(100);
    expect(score.sqli).toBe(100);
  });

  it("does NOT deduct for developer-accepted findings", () => {
    const findings = [
      { vulnerability_class: "sqli", severity: "critical", status: "accepted" },
    ];
    const score = computeScore(findings);
    expect(score.sqli).toBe(100);
    expect(score.overall).toBe(100);
  });

  it("floors category score at 0 (no negatives)", () => {
    const findings = Array.from({ length: 20 }, () => ({
      vulnerability_class: "sqli",
      severity: "critical",
      status: "open",
    }));
    const score = computeScore(findings);
    expect(score.sqli).toBe(0);
    expect(score.overall).toBeGreaterThanOrEqual(0);
  });

  it("routes CWE-79 to xss even when vulnerability_class is 'other'", () => {
    const findings = [
      { vulnerability_class: "other", cwe: "CWE-79", severity: "high", status: "open" },
    ];
    const score = computeScore(findings);
    // Should hit xss category via CWE routing
    expect(score.xss).toBeLessThan(100);
  });

  it("overall is average of 5 categories", () => {
    const findings = [
      { vulnerability_class: "sqli", severity: "critical", status: "open" }, // -25
    ];
    const score = computeScore(findings);
    const expected = Math.round((score.sqli + score.xss + score.csrf + score.deserialization + score.other) / 5);
    expect(score.overall).toBe(expected);
  });
});
