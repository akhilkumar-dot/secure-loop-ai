/**
 * src/lib/spaced-repetition.ts
 *
 * SM-2–inspired spaced repetition scheduler for SecureLoop.
 *
 * Rules (intentionally simpler than full SM-2 to stay testable):
 *   - After a correct answer:  interval *= ease_factor (min 1 day)
 *   - After a wrong answer:    interval = 1 day, ease_factor -= 0.15 (floor 1.3)
 *   - After a recurring misconception is flagged: interval = 1 day (shortcut)
 *   - Intervals are capped at 60 days.
 *   - next_review_at = now() + interval_days
 *
 * This module is fully pure (no DB calls) — all persistence is done by the
 * calling code in mastery-db.ts.
 */

export interface MasteryState {
  attempts_count: number;
  correct_count: number;
  tier_reached: "easy" | "medium" | "hard";
  interval_days: number;
  ease_factor: number;
  last_reviewed_at: string | null;
  next_review_at: string | null;
}

export interface MasteryUpdate {
  attempts_count: number;
  correct_count: number;
  tier_reached: "easy" | "medium" | "hard";
  interval_days: number;
  ease_factor: number;
  last_reviewed_at: string;
  next_review_at: string;
}

export const SM2_DEFAULTS = {
  EASE_FACTOR_INITIAL: 2.5,
  EASE_FACTOR_MIN: 1.3,
  EASE_FACTOR_DELTA_WRONG: 0.15,  // subtracted on wrong
  EASE_FACTOR_DELTA_RIGHT: 0.05,  // added on correct (slight boost)
  INTERVAL_INITIAL: 1,            // days
  INTERVAL_MAX: 60,               // days cap
  INTERVAL_WRONG_RESET: 1,        // reset to 1 day on wrong
  RECURRING_MISCONCEPTION_RESET: 1, // reset to 1 day on recurring flag
} as const;

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

function addDays(from: Date, days: number): Date {
  const d = new Date(from);
  d.setDate(d.getDate() + days);
  return d;
}

/**
 * Compute the next mastery state after a quiz answer.
 *
 * @param current   Current DB row (or null = first attempt)
 * @param correct   Whether this answer was correct
 * @param tier      The tier this answer was for
 * @param hasRecurringMisconception  Whether a recurring misconception was detected this session
 * @param now       The timestamp to anchor intervals to (defaults to Date.now())
 */
export function computeNextMasteryState(
  current: MasteryState | null,
  correct: boolean,
  tier: "easy" | "medium" | "hard",
  hasRecurringMisconception = false,
  now = new Date(),
): MasteryUpdate {
  const prev: MasteryState = current ?? {
    attempts_count: 0,
    correct_count: 0,
    tier_reached: "easy",
    interval_days: SM2_DEFAULTS.INTERVAL_INITIAL,
    ease_factor: SM2_DEFAULTS.EASE_FACTOR_INITIAL,
    last_reviewed_at: null,
    next_review_at: null,
  };

  const newAttempts = prev.attempts_count + 1;
  const newCorrect = prev.correct_count + (correct ? 1 : 0);

  // Tier reached is the max tier this user has ever attempted
  const tierOrder: Record<"easy" | "medium" | "hard", number> = { easy: 0, medium: 1, hard: 2 };
  const newTierReached =
    tierOrder[tier] > tierOrder[prev.tier_reached] ? tier : prev.tier_reached;

  let newEaseFactor: number;
  let newIntervalDays: number;

  if (hasRecurringMisconception) {
    // Recurring misconception: aggressively shorten the interval
    newIntervalDays = SM2_DEFAULTS.RECURRING_MISCONCEPTION_RESET;
    newEaseFactor = clamp(
      prev.ease_factor - SM2_DEFAULTS.EASE_FACTOR_DELTA_WRONG,
      SM2_DEFAULTS.EASE_FACTOR_MIN,
      5.0,
    );
  } else if (correct) {
    // Correct: extend interval by ease factor
    newIntervalDays = clamp(
      Math.round(prev.interval_days * prev.ease_factor),
      1,
      SM2_DEFAULTS.INTERVAL_MAX,
    );
    // Slight ease factor boost for correct answers (bounded at 5.0)
    newEaseFactor = clamp(
      prev.ease_factor + SM2_DEFAULTS.EASE_FACTOR_DELTA_RIGHT,
      SM2_DEFAULTS.EASE_FACTOR_MIN,
      5.0,
    );
  } else {
    // Wrong: reset interval, reduce ease factor
    newIntervalDays = SM2_DEFAULTS.INTERVAL_WRONG_RESET;
    newEaseFactor = clamp(
      prev.ease_factor - SM2_DEFAULTS.EASE_FACTOR_DELTA_WRONG,
      SM2_DEFAULTS.EASE_FACTOR_MIN,
      5.0,
    );
  }

  const nextReview = addDays(now, newIntervalDays);

  return {
    attempts_count: newAttempts,
    correct_count: newCorrect,
    tier_reached: newTierReached,
    interval_days: newIntervalDays,
    ease_factor: newEaseFactor,
    last_reviewed_at: now.toISOString(),
    next_review_at: nextReview.toISOString(),
  };
}

/**
 * Compute mastery level label from accuracy + tier_reached.
 * Used for the per-class progress display.
 */
export function getMasteryLevel(
  attempts: number,
  correct: number,
  tierReached: "easy" | "medium" | "hard",
): "mastered" | "learning" | "weak" {
  if (attempts === 0) return "weak";
  const accuracy = correct / attempts;
  if (tierReached === "hard" && accuracy >= 0.75) return "mastered";
  if (accuracy >= 0.6 || tierReached === "medium") return "learning";
  return "weak";
}

/**
 * Returns the number of days until next review (negative = overdue).
 * Returns null if next_review_at is not set.
 */
export function daysUntilReview(nextReviewAt: string | null, now = new Date()): number | null {
  if (!nextReviewAt) return null;
  const next = new Date(nextReviewAt);
  const diffMs = next.getTime() - now.getTime();
  return Math.round(diffMs / (1000 * 60 * 60 * 24));
}

