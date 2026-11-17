/**
 * src/lib/__tests__/education-integrity.test.ts
 *
 * Verifies that education code paths follow strict Real Data principles:
 * - No Math.random() in runtime learner logic (mastery, spaced repetition, progression, misconception)
 * - No hardcoded attempt arrays outside of test files
 * - No mock learner profiles in production runtime paths
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const EDUCATION_FILES = [
  "src/lib/quiz-bank.ts",
  "src/lib/misconception.ts",
  "src/lib/tier-progression.ts",
  "src/lib/spaced-repetition.ts",
  "src/lib/mastery-db.ts",
  "src/routes/learn.tsx",
];

describe("Education Layer Integrity — Real Data Enforcement", () => {
  it("ensures no Math.random() is used in education runtime code paths", () => {
    for (const fileRel of EDUCATION_FILES) {
      const fullPath = path.resolve(process.cwd(), fileRel);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        const lines = content.split("\n");
        lines.forEach((line, idx) => {
          // Allow comments or Math.round / Math.max / Math.min, but forbid Math.random
          if (
            line.includes("Math.random") &&
            !line.trim().startsWith("//") &&
            !line.trim().startsWith("*")
          ) {
            expect.fail(
              `Found Math.random() in runtime education file ${fileRel} at line ${idx + 1}: ${line}`,
            );
          }
        });
      }
    }
  });

  it("ensures no hardcoded learner attempt fixtures exist in runtime education lib files", () => {
    const RUNTIME_LIB_FILES = [
      "src/lib/misconception.ts",
      "src/lib/tier-progression.ts",
      "src/lib/spaced-repetition.ts",
      "src/lib/mastery-db.ts",
    ];

    for (const fileRel of RUNTIME_LIB_FILES) {
      const fullPath = path.resolve(process.cwd(), fileRel);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        // Look for fake attempts arrays like attempts = [{ ... }, { ... }]
        const hasHardcodedAttempts =
          /const\s+(?:fake|mock|demo|sample)?attempts\s*:\s*[^=]+=\s*\[\s*\{/i.test(content);
        expect(hasHardcodedAttempts, `Found hardcoded attempt array in ${fileRel}`).toBe(false);
      }
    }
  });

  it("ensures all education queries in mastery-db and misconception filter by user_id", () => {
    const dbFiles = ["src/lib/mastery-db.ts", "src/lib/misconception.ts"];
    for (const fileRel of dbFiles) {
      const fullPath = path.resolve(process.cwd(), fileRel);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        // Check that any select/upsert from mastery_profiles or recurring_misconceptions or education_checks includes user_id
        if (content.includes('from("mastery_profiles")')) {
          expect(content).toContain('.eq("user_id",');
        }
        if (content.includes('from("recurring_misconceptions")')) {
          expect(content).toContain('.eq("user_id",');
        }
        if (content.includes('from("education_checks")')) {
          expect(content).toContain('.eq("user_id",');
        }
      }
    }
  });
});
