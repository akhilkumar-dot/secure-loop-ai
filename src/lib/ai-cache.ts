/**
 * Supabase AI Cache Layer
 *
 * Caches model outputs (explanations, patches) in Supabase keyed by:
 * (user_id, finding_id, prompt_version, task).
 *
 * Security Guarantee:
 * - Stores ONLY output, provider name, and model ID.
 * - NEVER accepts, stores, or transmits API keys.
 * - Protected by Supabase Row Level Security (auth.uid() = user_id).
 */
import { supabase } from "./supabase";

export const CURRENT_PROMPT_VERSION = "2.1";

export interface CachedAiOutput<T = unknown> {
  output: T;
  provider: string;
  modelId: string;
}

/**
 * Retrieve cached model output from Supabase if previously computed.
 */
export async function getCachedAiOutput<T>(
  userId: string,
  findingId: string,
  task: "explanation" | "patch",
  promptVersion: string = CURRENT_PROMPT_VERSION,
): Promise<CachedAiOutput<T> | null> {
  if (!userId || !findingId) return null;

  try {
    const { data, error } = await supabase
      .from("ai_cache")
      .select("output, provider, model_id")
      .eq("user_id", userId)
      .eq("finding_id", findingId)
      .eq("task", task)
      .eq("prompt_version", promptVersion)
      .maybeSingle();

    if (error || !data) return null;

    return {
      output: data.output as T,
      provider: data.provider,
      modelId: data.model_id,
    };
  } catch {
    return null;
  }
}

/**
 * Persist model output into Supabase cache.
 */
export async function saveCachedAiOutput<T>(params: {
  userId: string;
  findingId: string;
  task: "explanation" | "patch";
  provider: string;
  modelId: string;
  output: T;
  promptVersion?: string;
}): Promise<void> {
  if (!params.userId || !params.findingId) return;

  try {
    await supabase.from("ai_cache").upsert(
      {
        user_id: params.userId,
        finding_id: params.findingId,
        task: params.task,
        provider: params.provider,
        model_id: params.modelId,
        output: params.output as any,
        prompt_version: params.promptVersion ?? CURRENT_PROMPT_VERSION,
        created_at: new Date().toISOString(),
      },
      {
        onConflict: "user_id,finding_id,prompt_version,task",
      },
    );
  } catch (err) {
    console.warn("[ai-cache] Failed to persist output to cache:", err);
  }
}
