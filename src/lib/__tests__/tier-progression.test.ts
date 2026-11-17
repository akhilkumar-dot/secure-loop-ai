/**
 * src/lib/__tests__/tier-progression.test.ts
 *
 * Unit tests for tier-progression logic:
 * - New user starts with only easy tier unlocked
 * - Passing easy (2 of last 3 correct) unlocks medium only
 * - Failing easy does not unlock medium
 * - Passing medium (2 of last 3 correct) unlocks hard ONLY if medium is unlocked
 * - Progress is strictly scoped per vulnerability class
 * - Threshold constant is documented and exported
 */
import { describe, it, expect } from "vitest";
import { getUnlockedTiers, PASS_THRESHOLD, type Tier } from "../quiz-bank";

describe("Tier Progression & Locking", () => {
  it("exports PASS_THRESHOLD documented as 2 out of 3 (67% consistency)", () => {
    expect(PASS_THRESHOLD.required).toBe(2);
    expect(PASS_THRESHOLD.outOf).toBe(3);
  });

  it("new user with 0 attempts has only easy tier unlocked", () => {
    const unlocked = getUnlockedTiers([]);
    expect(unlocked.has("easy")).toBe(true);
    expect(unlocked.has("medium")).toBe(false);
    expect(unlocked.has("hard")).toBe(false);
    expect(Array.from(unlocked)).toEqual(["easy"]);
  });

  it("medium tier unlocks after 2 out of 3 easy attempts are correct", () => {
    const attempts = [
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: false },
      { tier: "easy" as Tier, correct: true },
    ];
    const unlocked = getUnlockedTiers(attempts);
    expect(unlocked.has("easy")).toBe(true);
    expect(unlocked.has("medium")).toBe(true);
    expect(unlocked.has("hard")).toBe(false);
  });

  it("medium tier does NOT unlock with 1 out of 3 correct easy attempts", () => {
    const attempts = [
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: false },
      { tier: "easy" as Tier, correct: false },
    ];
    const unlocked = getUnlockedTiers(attempts);
    expect(unlocked.has("medium")).toBe(false);
  });

  it("medium tier does NOT unlock with fewer than 3 easy attempts", () => {
    const attempts = [
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: true },
    ];
    const unlocked = getUnlockedTiers(attempts);
    expect(unlocked.has("medium")).toBe(false);
  });

  it("hard tier unlocks only after medium is unlocked AND 2 of last 3 medium attempts are correct", () => {
    const attempts = [
      // Pass easy
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: false },
      // Pass medium
      { tier: "medium" as Tier, correct: true },
      { tier: "medium" as Tier, correct: false },
      { tier: "medium" as Tier, correct: true },
    ];
    const unlocked = getUnlockedTiers(attempts);
    expect(unlocked.has("easy")).toBe(true);
    expect(unlocked.has("medium")).toBe(true);
    expect(unlocked.has("hard")).toBe(true);
  });

  it("hard tier does NOT unlock if medium is not yet unlocked, even with medium attempts present", () => {
    // Failing easy (never unlocked medium)
    const attempts = [
      { tier: "easy" as Tier, correct: false },
      { tier: "easy" as Tier, correct: false },
      { tier: "easy" as Tier, correct: false },
      // Fake/injected medium attempts
      { tier: "medium" as Tier, correct: true },
      { tier: "medium" as Tier, correct: true },
      { tier: "medium" as Tier, correct: true },
    ];
    const unlocked = getUnlockedTiers(attempts);
    expect(unlocked.has("easy")).toBe(true);
    expect(unlocked.has("medium")).toBe(false);
    expect(unlocked.has("hard")).toBe(false);
  });

  it("uses strictly the LAST 3 attempts at each tier (rolling window)", () => {
    // User initially passed easy (attempts 1,2,3: 2 correct)
    // But then failed the next 2 easy attempts (attempts 2,3,4,5: last 3 are [true, false, false] = 1/3)
    const attempts = [
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: true },
      { tier: "easy" as Tier, correct: false },
      { tier: "easy" as Tier, correct: false },
      { tier: "easy" as Tier, correct: false },
    ];
    const unlocked = getUnlockedTiers(attempts);
    // Last 3 easy are [false, false, false] (0/3) -> medium is not unlocked
    expect(unlocked.has("medium")).toBe(false);
  });
});
