/**
 * src/lib/__tests__/spaced-repetition.test.ts
 *
 * Unit tests for computeNextMasteryState, getMasteryLevel, daysUntilReview.
 */
import { describe, it, expect } from "vitest";
import {
  computeNextMasteryState,
  getMasteryLevel,
  daysUntilReview,
  SM2_DEFAULTS,
  type MasteryState,
} from "../spaced-repetition";

const NOW = new Date("2026-01-01T12:00:00Z");

function state(overrides: Partial<MasteryState> = {}): MasteryState {
  return {
    attempts_count: 5,
    correct_count: 3,
    tier_reached: "easy",
    interval_days: 3,
    ease_factor: 2.5,
    last_reviewed_at: "2026-01-01T00:00:00Z",
    next_review_at: "2026-01-04T00:00:00Z",
    ...overrides,
  };
}

describe("computeNextMasteryState", () => {
  describe("first attempt (null state)", () => {
    it("correct first attempt starts interval at ease_factor × initial_interval", () => {
      const result = computeNextMasteryState(null, true, "easy", false, NOW);
      expect(result.attempts_count).toBe(1);
      expect(result.correct_count).toBe(1);
      // initial interval = 1; 1 * 2.5 = 2.5 → rounds to 3
      expect(result.interval_days).toBe(3);
      expect(result.ease_factor).toBeCloseTo(SM2_DEFAULTS.EASE_FACTOR_INITIAL + SM2_DEFAULTS.EASE_FACTOR_DELTA_RIGHT, 5);
    });

    it("wrong first attempt resets interval to 1 day", () => {
      const result = computeNextMasteryState(null, false, "easy", false, NOW);
      expect(result.interval_days).toBe(SM2_DEFAULTS.INTERVAL_WRONG_RESET);
      expect(result.correct_count).toBe(0);
      expect(result.ease_factor).toBeCloseTo(
        SM2_DEFAULTS.EASE_FACTOR_INITIAL - SM2_DEFAULTS.EASE_FACTOR_DELTA_WRONG,
        5,
      );
    });
  });

  describe("correct answer", () => {
    it("extends interval by ease_factor", () => {
      const s = state({ interval_days: 3, ease_factor: 2.5 });
      const result = computeNextMasteryState(s, true, "easy", false, NOW);
      // 3 * 2.5 = 7.5 → round = 8 (Math.round)
      expect(result.interval_days).toBe(8);
    });

    it("increases ease_factor slightly", () => {
      const s = state({ ease_factor: 2.5 });
      const result = computeNextMasteryState(s, true, "easy", false, NOW);
      expect(result.ease_factor).toBeCloseTo(2.5 + SM2_DEFAULTS.EASE_FACTOR_DELTA_RIGHT, 5);
    });

    it("caps interval at INTERVAL_MAX", () => {
      const s = state({ interval_days: SM2_DEFAULTS.INTERVAL_MAX, ease_factor: 3.0 });
      const result = computeNextMasteryState(s, true, "easy", false, NOW);
      expect(result.interval_days).toBe(SM2_DEFAULTS.INTERVAL_MAX);
    });

    it("sets next_review_at to now + interval_days", () => {
      const s = state({ interval_days: 3, ease_factor: 2.0 });
      const result = computeNextMasteryState(s, true, "easy", false, NOW);
      // 3 * 2.0 = 6 → next = 2026-01-07
      const expected = new Date("2026-01-07T12:00:00Z");
      expect(new Date(result.next_review_at).toDateString()).toBe(expected.toDateString());
    });
  });

  describe("wrong answer", () => {
    it("resets interval to 1 day", () => {
      const s = state({ interval_days: 10, ease_factor: 2.5 });
      const result = computeNextMasteryState(s, false, "easy", false, NOW);
      expect(result.interval_days).toBe(SM2_DEFAULTS.INTERVAL_WRONG_RESET);
    });

    it("decreases ease_factor by DELTA_WRONG", () => {
      const s = state({ ease_factor: 2.0 });
      const result = computeNextMasteryState(s, false, "easy", false, NOW);
      expect(result.ease_factor).toBeCloseTo(2.0 - SM2_DEFAULTS.EASE_FACTOR_DELTA_WRONG, 5);
    });

    it("does not let ease_factor fall below minimum", () => {
      const s = state({ ease_factor: SM2_DEFAULTS.EASE_FACTOR_MIN });
      const result = computeNextMasteryState(s, false, "easy", false, NOW);
      expect(result.ease_factor).toBeCloseTo(SM2_DEFAULTS.EASE_FACTOR_MIN, 5);
    });
  });

  describe("recurring misconception override", () => {
    it("resets interval to 1 day regardless of correct flag", () => {
      const s = state({ interval_days: 14, ease_factor: 2.5 });
      const resultCorrect = computeNextMasteryState(s, true, "easy", true, NOW);
      expect(resultCorrect.interval_days).toBe(SM2_DEFAULTS.RECURRING_MISCONCEPTION_RESET);
    });

    it("also decreases ease_factor", () => {
      const s = state({ ease_factor: 2.5 });
      const result = computeNextMasteryState(s, true, "easy", true, NOW);
      expect(result.ease_factor).toBeCloseTo(2.5 - SM2_DEFAULTS.EASE_FACTOR_DELTA_WRONG, 5);
    });
  });

  describe("tier_reached tracking", () => {
    it("promotes tier_reached when answering a higher tier", () => {
      const s = state({ tier_reached: "easy" });
      const result = computeNextMasteryState(s, true, "medium", false, NOW);
      expect(result.tier_reached).toBe("medium");
    });

    it("does not demote tier_reached when answering a lower tier", () => {
      const s = state({ tier_reached: "hard" });
      const result = computeNextMasteryState(s, true, "easy", false, NOW);
      expect(result.tier_reached).toBe("hard");
    });
  });

  describe("attempt counters", () => {
    it("increments attempts_count on every answer", () => {
      const s = state({ attempts_count: 10 });
      const result = computeNextMasteryState(s, false, "easy", false, NOW);
      expect(result.attempts_count).toBe(11);
    });

    it("only increments correct_count on correct answers", () => {
      const s = state({ correct_count: 7 });
      expect(computeNextMasteryState(s, true, "easy", false, NOW).correct_count).toBe(8);
      expect(computeNextMasteryState(s, false, "easy", false, NOW).correct_count).toBe(7);
    });
  });
});

describe("getMasteryLevel", () => {
  it("returns 'weak' when no attempts", () => {
    expect(getMasteryLevel(0, 0, "easy")).toBe("weak");
  });

  it("returns 'mastered' for hard tier with ≥75% accuracy", () => {
    expect(getMasteryLevel(8, 6, "hard")).toBe("mastered"); // 75%
    expect(getMasteryLevel(10, 8, "hard")).toBe("mastered"); // 80%
  });

  it("returns 'learning' for hard tier with <75% accuracy", () => {
    expect(getMasteryLevel(10, 7, "hard")).toBe("learning"); // 70%
  });

  it("returns 'learning' for medium tier regardless of accuracy ≥60%", () => {
    expect(getMasteryLevel(5, 3, "medium")).toBe("learning"); // 60%
  });

  it("returns 'learning' for easy tier with ≥60% accuracy", () => {
    expect(getMasteryLevel(5, 3, "easy")).toBe("learning"); // 60%
  });

  it("returns 'weak' for easy tier with <60% accuracy", () => {
    expect(getMasteryLevel(10, 5, "easy")).toBe("weak"); // 50%
  });
});

describe("daysUntilReview", () => {
  it("returns null when next_review_at is null", () => {
    expect(daysUntilReview(null, NOW)).toBeNull();
  });

  it("returns positive days for a future review", () => {
    const future = new Date(NOW);
    future.setDate(NOW.getDate() + 7);
    expect(daysUntilReview(future.toISOString(), NOW)).toBe(7);
  });

  it("returns 0 for a review due today", () => {
    expect(daysUntilReview(NOW.toISOString(), NOW)).toBe(0);
  });

  it("returns negative days for an overdue review", () => {
    const past = new Date(NOW);
    past.setDate(NOW.getDate() - 3);
    expect(daysUntilReview(past.toISOString(), NOW)).toBe(-3);
  });
});

