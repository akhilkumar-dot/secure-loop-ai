/**
 * src/lib/__tests__/patch.test.ts
 *
 * Unit tests for applyUnifiedDiff.
 * Tests:
 *   - Good patch (parameterized query) accepted
 *   - Non-applying diff rejected with clear error
 *   - Drift tolerance: hunk applies even when offset by a few lines
 *   - Empty diff rejected
 *   - Multi-hunk patch applied correctly
 */
import { describe, it, expect } from "vitest";
import { applyUnifiedDiff } from "../patch";

// ── Fixtures ───────────────────────────────────────────────────────────────

const VULN_JS = `const express = require('express');
const db = require('./db');
const router = express.Router();

router.get('/user', async (req, res) => {
  const id = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + id + "'";
  const result = await db.query(query);
  res.json(result);
});

module.exports = router;
`;

const GOOD_PATCH = `--- a/routes/user.js
+++ b/routes/user.js
@@ -5,5 +5,5 @@
 router.get('/user', async (req, res) => {
   const id = req.query.id;
-  const query = "SELECT * FROM users WHERE id = '" + id + "'";
-  const result = await db.query(query);
+  const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
   res.json(result);
 });
`;

const BAD_PATCH_WRONG_CONTEXT = `--- a/routes/user.js
+++ b/routes/user.js
@@ -5,5 +5,5 @@
 router.get('/nonexistent', async (req, res) => {
   const id = req.query.id;
-  const query = "SELECT * FROM users WHERE id = '" + id + "'";
+  const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
   res.json(result);
 });
`;

const PLACEHOLDER_DIFF = "// Patch generation failed — see scan log";

// ── Tests ──────────────────────────────────────────────────────────────────

describe("applyUnifiedDiff", () => {
  it("applies a clean parameterized-query patch (good patch)", () => {
    const result = applyUnifiedDiff(VULN_JS, GOOD_PATCH);
    expect(result.ok).toBe(true);
    expect(result.patched).toBeDefined();
    // The fixed line should contain the parameterized form
    expect(result.patched).toContain('db.query("SELECT * FROM users WHERE id = $1", [id])');
    // The vulnerable concatenation should be gone
    expect(result.patched).not.toContain("+ id +");
  });

  it("rejects a patch whose context does not match the file (non-applying diff)", () => {
    const result = applyUnifiedDiff(VULN_JS, BAD_PATCH_WRONG_CONTEXT);
    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error!.length).toBeGreaterThan(0);
  });

  it("rejects an empty/placeholder diff", () => {
    const r1 = applyUnifiedDiff(VULN_JS, "");
    expect(r1.ok).toBe(false);

    const r2 = applyUnifiedDiff(VULN_JS, PLACEHOLDER_DIFF);
    expect(r2.ok).toBe(false);
    expect(r2.error).toContain("placeholder");
  });

  it("applies a patch with small line-offset drift (tolerance)", () => {
    // Add 3 extra comment lines before the vulnerable line
    const modifiedFile = VULN_JS.replace(
      "router.get('/user'",
      "// comment 1\n// comment 2\n// comment 3\nrouter.get('/user'",
    );
    const result = applyUnifiedDiff(modifiedFile, GOOD_PATCH);
    // With drift tolerance of ±5, this should still apply
    expect(result.ok).toBe(true);
  });

  it("correctly applies a multi-hunk patch", () => {
    const original = `const a = 1;
const b = 2;
const c = 3;
const d = 4;
const e = 5;
const f = 6;
const g = 7;
const h = 8;
`;

    const multiHunk = `--- a/test.js
+++ b/test.js
@@ -1,2 +1,2 @@
-const a = 1;
+const a = 100;
 const b = 2;
@@ -7,2 +7,2 @@
 const g = 7;
-const h = 8;
+const h = 800;
`;

    const result = applyUnifiedDiff(original, multiHunk);
    expect(result.ok).toBe(true);
    expect(result.patched).toContain("const a = 100;");
    expect(result.patched).toContain("const h = 800;");
    expect(result.patched).toContain("const b = 2;");
  });
});
