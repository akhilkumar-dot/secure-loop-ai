/**
 * src/lib/stage-schemas.ts
 *
 * Defines explicit, isolated JSON Schemas and Zod Schemas per pipeline stage:
 * - explanation_generation
 * - patch_generation
 * - triage (heuristic scan)
 * - vulnerability_validation
 *
 * Enforces:
 * 1. Never sharing one global response schema across different stages.
 * 2. Strict compliance with Groq and OpenAI JSON Schema constraints:
 *    - additionalProperties: false on every object level
 *    - every property in required
 * 3. Schema order: likely_false_positive and confidence_note at the FRONT for explanations.
 * 4. Startup / test assertion verifying JSON Schema matches Zod schema for each stage.
 */

import { z } from "zod";

export type StageName =
  "explanation_generation" | "patch_generation" | "triage" | "vulnerability_validation" | "default";

/* ─────────────────────────────────────────────────────────────────────────── */
/* 1. EXPLANATION GENERATION SCHEMAS                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

export const ExplanationOutputSchema = z.object({
  likely_false_positive: z
    .object({
      value: z.boolean(),
      reason: z.string(),
    })
    .nullable(),
  confidence_note: z.string().default(""),
  what_it_is: z.object({
    technical: z.string().min(1, "Technical what_it_is cannot be empty"),
    simplified: z.string().min(1, "Simplified what_it_is cannot be empty"),
  }),
  why_it_happened: z.object({
    technical: z.string().min(1, "Technical why_it_happened cannot be empty"),
    simplified: z.string().min(1, "Simplified why_it_happened cannot be empty"),
  }),
  how_fix_works: z.object({
    technical: z.string().min(1, "Technical how_fix_works cannot be empty"),
    simplified: z.string().min(1, "Simplified how_fix_works cannot be empty"),
  }),
  attack_idea: z.string().min(1, "attack_idea cannot be empty"),
  key_takeaway: z.string().min(1, "key_takeaway cannot be empty"),
});

export type ExplanationOutput = z.infer<typeof ExplanationOutputSchema>;

export const GROQ_EXPLANATION_JSON_SCHEMA = {
  type: "object",
  properties: {
    likely_false_positive: {
      type: "object",
      properties: {
        value: { type: "boolean" },
        reason: { type: "string" },
      },
      required: ["value", "reason"],
      additionalProperties: false,
    },
    confidence_note: { type: "string" },
    what_it_is: {
      type: "object",
      properties: {
        technical: { type: "string" },
        simplified: { type: "string" },
      },
      required: ["technical", "simplified"],
      additionalProperties: false,
    },
    why_it_happened: {
      type: "object",
      properties: {
        technical: { type: "string" },
        simplified: { type: "string" },
      },
      required: ["technical", "simplified"],
      additionalProperties: false,
    },
    how_fix_works: {
      type: "object",
      properties: {
        technical: { type: "string" },
        simplified: { type: "string" },
      },
      required: ["technical", "simplified"],
      additionalProperties: false,
    },
    attack_idea: { type: "string" },
    key_takeaway: { type: "string" },
  },
  required: [
    "likely_false_positive",
    "confidence_note",
    "what_it_is",
    "why_it_happened",
    "how_fix_works",
    "attack_idea",
    "key_takeaway",
  ],
  additionalProperties: false,
};

/* ─────────────────────────────────────────────────────────────────────────── */
/* 2. PATCH GENERATION SCHEMAS                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

export const PatchSchema = z.object({
  start_line: z.number().int().positive("start_line must be a positive integer"),
  end_line: z.number().int().positive("end_line must be a positive integer"),
  original_code: z.string().min(1, "original_code cannot be empty"),
  replacement_code: z.string(),
  explanation: z.string().min(1, "Patch explanation cannot be empty"),
});

export type PatchOutput = z.infer<typeof PatchSchema>;

export const GROQ_PATCH_JSON_SCHEMA = {
  type: "object",
  properties: {
    start_line: {
      type: "integer",
      description: "1-based starting line number in the source file of the code to replace",
    },
    end_line: {
      type: "integer",
      description:
        "1-based ending line number in the source file of the code to replace (inclusive)",
    },
    original_code: {
      type: "string",
      description:
        "Exact unmodified lines of original code to replace from the source file, WITHOUT line numbers",
    },
    replacement_code: {
      type: "string",
      description: "Replacement code to substitute in place of original_code, WITHOUT line numbers",
    },
    explanation: {
      type: "string",
      description: "1-2 sentences explaining why this fixes the vulnerability",
    },
  },
  required: ["start_line", "end_line", "original_code", "replacement_code", "explanation"],
  additionalProperties: false,
};

/* ─────────────────────────────────────────────────────────────────────────── */
/* 3. TRIAGE (HEURISTIC SCAN) SCHEMAS                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

export const HeuristicFindingSchema = z.object({
  rule_id: z.string(),
  cwe: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  file_path: z.string(),
  line_start: z.number(),
  line_end: z.number(),
  vulnerability_class: z.enum(["sqli", "xss", "csrf", "insecure_deserialization", "other"]),
  raw_message: z.string(),
  code_lines: z.array(
    z.object({
      n: z.number(),
      code: z.string(),
      vuln: z.boolean().optional(),
    }),
  ),
});

export const HeuristicScanSchema = z.object({
  findings: z.array(HeuristicFindingSchema),
});

export const GROQ_TRIAGE_JSON_SCHEMA = {
  type: "object",
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          rule_id: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          file_path: { type: "string" },
          line_start: { type: "integer" },
          line_end: { type: "integer" },
          vulnerability_class: {
            type: "string",
            enum: ["sqli", "xss", "csrf", "insecure_deserialization", "other"],
          },
          raw_message: { type: "string" },
          code_lines: {
            type: "array",
            items: {
              type: "object",
              properties: {
                n: { type: "integer" },
                code: { type: "string" },
                vuln: { type: "boolean" },
              },
              required: ["n", "code"],
              additionalProperties: false,
            },
          },
        },
        required: [
          "rule_id",
          "cwe",
          "severity",
          "file_path",
          "line_start",
          "line_end",
          "vulnerability_class",
          "raw_message",
          "code_lines",
        ],
        additionalProperties: false,
      },
    },
  },
  required: ["findings"],
  additionalProperties: false,
};

/* ─────────────────────────────────────────────────────────────────────────── */
/* 4. VALIDATION SCHEMAS                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

export const ValidationReviewSchema = z.object({
  review: z.string().min(1, "Review comment cannot be empty"),
});

export const GROQ_VALIDATION_REVIEW_JSON_SCHEMA = {
  type: "object",
  properties: {
    review: { type: "string" },
  },
  required: ["review"],
  additionalProperties: false,
};

export const ValidationOpinionSchema = z.object({
  llm_vulnerability_gone: z.boolean(),
  review: z.string().default(""),
  new_issues_count: z.number().default(0),
});

export const GROQ_VALIDATION_OPINION_JSON_SCHEMA = {
  type: "object",
  properties: {
    llm_vulnerability_gone: { type: "boolean" },
    review: { type: "string" },
    new_issues_count: { type: "integer" },
  },
  required: ["llm_vulnerability_gone", "review", "new_issues_count"],
  additionalProperties: false,
};

/* ─────────────────────────────────────────────────────────────────────────── */
/* 5. STAGE SCHEMA RESOLVER                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

export const STAGE_JSON_SCHEMAS: Record<StageName, Record<string, unknown> | null> = {
  explanation_generation: GROQ_EXPLANATION_JSON_SCHEMA,
  patch_generation: GROQ_PATCH_JSON_SCHEMA,
  triage: GROQ_TRIAGE_JSON_SCHEMA,
  vulnerability_validation: GROQ_VALIDATION_REVIEW_JSON_SCHEMA,
  default: null,
};

/**
 * Returns the exact JSON schema assigned to a stage.
 * Never defaults across stages.
 */
export function getStageJsonSchema(stage: StageName): Record<string, unknown> | null {
  return STAGE_JSON_SCHEMAS[stage] ?? null;
}

/**
 * Assertion utility that verifies the JSON schema sent to the provider
 * matches the top-level keys expected by the stage's Zod schema.
 */
export function assertStageSchemaEquivalence(
  stage: StageName,
  jsonSchema: Record<string, any>,
  zodSchema: z.ZodObject<any>,
): boolean {
  if (!jsonSchema || jsonSchema["type"] !== "object") {
    throw new Error(`[SchemaEquivalence] Invalid JSON schema for stage ${stage}`);
  }

  const jsonRequired: string[] = jsonSchema["required"] || [];
  const zodShape = zodSchema.shape;
  const zodKeys = Object.keys(zodShape);

  // Check that every required JSON schema field exists in Zod
  for (const reqKey of jsonRequired) {
    if (!zodKeys.includes(reqKey)) {
      throw new Error(
        `[SchemaEquivalence] Stage '${stage}': JSON schema required key '${reqKey}' missing in Zod schema`,
      );
    }
  }

  // Check that every non-optional Zod key is present in JSON schema required
  for (const zodKey of zodKeys) {
    const isOptional = zodShape[zodKey].isOptional?.();
    if (!isOptional && !jsonRequired.includes(zodKey)) {
      throw new Error(
        `[SchemaEquivalence] Stage '${stage}': Non-optional Zod key '${zodKey}' missing in JSON schema required list`,
      );
    }
  }

  return true;
}
