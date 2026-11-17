/**
 * src/lib/tier-progression.ts
 *
 * Server-side tier progression enforcement.
 *
 * Rules (enforced here, never trusted from client):
 *  - Easy is always unlocked.
 *  - Medium unlocks when the user gets ≥2/3 of their last 3 easy attempts correct (per vuln class).
 *  - Hard unlocks when the user gets ≥2/3 of their last 3 medium attempts correct (per vuln class).
 *
 * This module has NO side effects — it only reads from Supabase.
 * The quiz submission path in the finding route calls checkTierAllowed() before
 * inserting an education_check row.
 */

import { supabase } from "@/lib/supabase";
import { getUnlockedTiers, PASS_THRESHOLD } from "@/lib/quiz-bank";
import type { Tier, VulnClass } from "@/lib/quiz-bank";

export interface TierStatus {
  unlockedTiers: Tier[];
  currentBestTier: Tier;
  easyPassRate: number | null; // 0-1; null if < outOf attempts
  mediumPassRate: number | null;
}

/**
 * Fetch the user's attempt history for a vuln class and compute which tiers
 * are unlocked.  Returns the unlocked set + a human-readable status object.
 */
export async function getTierStatus(userId: string, vulnClass: VulnClass): Promise<TierStatus> {
  const { data, error } = await supabase
    .from("education_checks")
    .select("tier, correct, answered_at")
    .eq("user_id", userId)
    .eq("vuln_class", vulnClass)
    .order("answered_at", { ascending: true });

  if (error || !data) {
    // On error, default to easy-only (safe fallback)
    return {
      unlockedTiers: ["easy"],
      currentBestTier: "easy",
      easyPassRate: null,
      mediumPassRate: null,
    };
  }

  const attempts = data as Array<{ tier: string; correct: boolean }>;
  const typedAttempts = attempts.map((a) => ({
    tier: a.tier as Tier,
    correct: a.correct,
  }));

  const unlocked = getUnlockedTiers(typedAttempts);

  // Compute pass rates for display
  const easyAttempts = typedAttempts.filter((a) => a.tier === "easy");
  const lastEasy = easyAttempts.slice(-PASS_THRESHOLD.outOf);
  const easyPassRate =
    lastEasy.length >= PASS_THRESHOLD.outOf
      ? lastEasy.filter((a) => a.correct).length / PASS_THRESHOLD.outOf
      : null;

  const mediumAttempts = typedAttempts.filter((a) => a.tier === "medium");
  const lastMedium = mediumAttempts.slice(-PASS_THRESHOLD.outOf);
  const mediumPassRate =
    lastMedium.length >= PASS_THRESHOLD.outOf
      ? lastMedium.filter((a) => a.correct).length / PASS_THRESHOLD.outOf
      : null;

  const currentBestTier: Tier = unlocked.has("hard")
    ? "hard"
    : unlocked.has("medium")
      ? "medium"
      : "easy";

  return {
    unlockedTiers: Array.from(unlocked) as Tier[],
    currentBestTier,
    easyPassRate,
    mediumPassRate,
  };
}

/**
 * Returns true if the user is allowed to attempt the requested tier.
 * This is the server-side gate — always call this before accepting a quiz answer.
 * Verifies both via backend RPC (when available) and direct DB history checks.
 */
export async function checkTierAllowed(
  userId: string,
  vulnClass: VulnClass,
  requestedTier: Tier,
): Promise<boolean> {
  if (requestedTier === "easy") return true; // always allowed

  // 1. Try server RPC gate first
  try {
    const { data: rpcAllowed, error: rpcErr } = await supabase.rpc("rpc_check_tier_unlocked", {
      p_vuln_class: vulnClass,
      p_tier: requestedTier,
    });
    if (!rpcErr && typeof rpcAllowed === "boolean") {
      return rpcAllowed;
    }
  } catch {
    // Fall back to database query if RPC is unavailable
  }

  // 2. Query attempts and evaluate logic
  const { unlockedTiers } = await getTierStatus(userId, vulnClass);
  return unlockedTiers.includes(requestedTier);
}
