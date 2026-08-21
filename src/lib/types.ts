/**
 * Shared domain types for SecureLoop.
 * These are the canonical type definitions used across the UI, components,
 * and Supabase integrations. Importing from here (not demo-data.ts)
 * ensures no production code depends on mock/seed data files.
 */

export type Severity = "critical" | "high" | "medium" | "low";

export type VulnClass = "sqli" | "xss" | "csrf" | "insecure_deserialization";

export type FindingStatus =
  | "open"
  | "explained"
  | "patched"
  | "validated"
  | "accepted"
  | "rejected";

/**
 * A single line in a unified diff view.
 */
export interface DiffLine {
  /** "add" = +line, "del" = -line, "ctx" = context, "hunk" = @@ header */
  type: "add" | "del" | "ctx" | "hunk";
  code: string;
}

/**
 * Parse a raw unified diff string into DiffLine[] for DiffView rendering.
 */
export function parseDiff(rawDiff: string): DiffLine[] {
  return rawDiff.split("\n").map((line) => {
    if (line.startsWith("+")) return { type: "add", code: line };
    if (line.startsWith("-")) return { type: "del", code: line };
    if (line.startsWith("@@")) return { type: "hunk", code: line };
    return { type: "ctx", code: line };
  });
}
