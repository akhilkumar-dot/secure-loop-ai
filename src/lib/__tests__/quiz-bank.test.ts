/**
 * src/lib/__tests__/quiz-bank.test.ts
 *
 * Verifies quiz bank integrity:
 * - Minimum 3 questions per vulnerability class per tier (36 total)
 * - Exactly one correct option per question (correctIndex matches misconceptionId: null)
 * - Every wrong option has a non-null misconceptionId
 * - Every misconceptionId is defined in MISCONCEPTION_LABELS
 * - No duplicate question IDs
 * - Every question has an authoritative non-empty source reference (OWASP, MITRE, vendor docs)
 */
import { describe, it, expect } from "vitest";
import { QUIZ_BANK, type VulnClass, type Tier } from "../quiz-bank";
import { MISCONCEPTION_LABELS } from "../misconception";

const REQUIRED_CLASSES: VulnClass[] = ["sqli", "xss", "csrf", "insecure_deserialization"];
const REQUIRED_TIERS: Tier[] = ["easy", "medium", "hard"];
const MIN_QUESTIONS_PER_TIER = 3;

describe("Quiz Bank Integrity", () => {
  it("contains at least the minimum required questions per class and tier", () => {
    for (const vc of REQUIRED_CLASSES) {
      for (const tier of REQUIRED_TIERS) {
        const questions = QUIZ_BANK.filter((q) => q.vulnClass === vc && q.tier === tier);
        expect(
          questions.length,
          `Expected at least ${MIN_QUESTIONS_PER_TIER} questions for ${vc} ${tier}, got ${questions.length}`,
        ).toBeGreaterThanOrEqual(MIN_QUESTIONS_PER_TIER);
      }
    }
  });

  it("has no duplicate question IDs", () => {
    const ids = QUIZ_BANK.map((q) => q.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("ensures every question has exactly 4 options and valid correctIndex (0..3)", () => {
    for (const q of QUIZ_BANK) {
      expect(q.options).toHaveLength(4);
      expect(q.correctIndex).toBeGreaterThanOrEqual(0);
      expect(q.correctIndex).toBeLessThan(4);
    }
  });

  it("ensures the correct option has misconceptionId === null and wrong options have a valid misconceptionId", () => {
    for (const q of QUIZ_BANK) {
      // Correct option
      const correctOpt = q.options[q.correctIndex];
      expect(
        correctOpt?.misconceptionId,
        `Question ${q.id}: correct option at index ${q.correctIndex} must have null misconceptionId`,
      ).toBeNull();

      // Wrong options
      q.options.forEach((opt, idx) => {
        if (idx !== q.correctIndex) {
          expect(
            opt.misconceptionId,
            `Question ${q.id}: wrong option at index ${idx} must not have null misconceptionId`,
          ).not.toBeNull();
          expect(
            typeof opt.misconceptionId,
            `Question ${q.id}: wrong option at index ${idx} must have string misconceptionId`,
          ).toBe("string");
          expect(
            opt.misconceptionId!.length,
            `Question ${q.id}: misconceptionId must not be empty`,
          ).toBeGreaterThan(0);
        }
      });
    }
  });

  it("ensures all misconception IDs are defined in MISCONCEPTION_LABELS", () => {
    for (const q of QUIZ_BANK) {
      q.options.forEach((opt, idx) => {
        if (opt.misconceptionId !== null) {
          expect(
            MISCONCEPTION_LABELS[opt.misconceptionId],
            `Question ${q.id}: misconceptionId "${opt.misconceptionId}" on option ${idx} is undefined in MISCONCEPTION_LABELS`,
          ).toBeDefined();
        }
      });
    }
  });

  it("ensures every question has an authoritative, non-empty source reference", () => {
    for (const q of QUIZ_BANK) {
      expect(q.source, `Question ${q.id} is missing a source reference`).toBeDefined();
      expect(typeof q.source, `Question ${q.id} source must be a non-empty string`).toBe("string");
      expect(q.source.trim().length, `Question ${q.id} source must not be blank`).toBeGreaterThan(
        10,
      );
    }
  });
});
