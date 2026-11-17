/**
 * src/lib/mastery-db.ts
 *
 * Database layer for mastery_profiles — persists SM-2 state after every quiz answer.
 * Separated from spaced-repetition.ts (pure logic) to keep that module testable.
 */

import { supabase } from "@/lib/supabase";
import { computeNextMasteryState, type MasteryState } from "@/lib/spaced-repetition";
import type { VulnClass, Tier } from "@/lib/quiz-bank";

export interface MasteryProfileRow {
  id: string;
  user_id: string;
  vuln_class: VulnClass;
  attempts_count: number;
  correct_count: number;
  tier_reached: Tier;
  interval_days: number;
  ease_factor: number;
  last_reviewed_at: string | null;
  next_review_at: string | null;
}

/**
 * Load the mastery profile for a user+vulnClass, or null if not yet created.
 */
export async function getMasteryProfile(
  userId: string,
  vulnClass: VulnClass,
): Promise<MasteryProfileRow | null> {
  const { data, error } = await supabase
    .from("mastery_profiles")
    .select("*")
    .eq("user_id", userId)
    .eq("vuln_class", vulnClass)
    .maybeSingle();

  if (error) {
    console.error("[mastery] Failed to load mastery profile:", error);
    return null;
  }
  return data as MasteryProfileRow | null;
}

/**
 * Load all mastery profiles for a user (for the mastery view).
 */
export async function getAllMasteryProfiles(userId: string): Promise<MasteryProfileRow[]> {
  const { data, error } = await supabase
    .from("mastery_profiles")
    .select("*")
    .eq("user_id", userId)
    .order("vuln_class");

  if (error) {
    console.error("[mastery] Failed to load all mastery profiles:", error);
    return [];
  }
  return (data ?? []) as MasteryProfileRow[];
}

/**
 * Update the mastery profile after a quiz answer.
 * Creates the row if it doesn't exist (upsert on user_id + vuln_class).
 */
export async function updateMasteryAfterAnswer(
  userId: string,
  vulnClass: VulnClass,
  tier: Tier,
  correct: boolean,
  hasRecurringMisconception = false,
): Promise<void> {
  const current = await getMasteryProfile(userId, vulnClass);

  const currentState: MasteryState | null = current
    ? {
        attempts_count: current.attempts_count,
        correct_count: current.correct_count,
        tier_reached: current.tier_reached,
        interval_days: current.interval_days,
        ease_factor: current.ease_factor,
        last_reviewed_at: current.last_reviewed_at,
        next_review_at: current.next_review_at,
      }
    : null;

  const nextState = computeNextMasteryState(currentState, correct, tier, hasRecurringMisconception);

  const { error } = await supabase.from("mastery_profiles").upsert(
    {
      user_id: userId,
      vuln_class: vulnClass,
      ...nextState,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id,vuln_class" },
  );

  if (error) {
    console.error("[mastery] Failed to upsert mastery profile:", error);
  }
}

/**
 * Fetch mastery profiles that are due for review (next_review_at ≤ now).
 */
export async function getDueForReview(userId: string): Promise<MasteryProfileRow[]> {
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from("mastery_profiles")
    .select("*")
    .eq("user_id", userId)
    .lte("next_review_at", now)
    .order("next_review_at", { ascending: true });

  if (error) {
    console.error("[mastery] Failed to load due reviews:", error);
    return [];
  }
  return (data ?? []) as MasteryProfileRow[];
}
