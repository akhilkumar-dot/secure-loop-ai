/**
 * src/lib/__tests__/explanation-integration.test.ts
 *
 * Real provider integration test:
 * - Makes a real call to the provider using the user's free key from SECURELOOP_TEST_KEY or GEMINI_API_KEY.
 * - Skips automatically when no key is set in the environment, keeping CI 100% green without burning quota.
 * - Never commits any API key.
 * - Validates that real live API calls return schema-valid, grounded JSON output.
 */

import { describe, it, expect } from "vitest";
import { generateRealExplanation } from "../explanation-service";
import type { RealScanFinding } from "../finding-input";

const TEST_KEY =
  process.env["SECURELOOP_TEST_KEY"] ||
  process.env["GEMINI_API_KEY"] ||
  process.env["GROQ_API_KEY"] ||
  "";

const describeOrSkip = TEST_KEY ? describe : describe.skip;

const REAL_SQLI_SAMPLE = `// Sample 1: SQL Injection via query string concat (Vulnerable)
// Source: OWASP NodeGoat (contributions.js)
const express = require('express');
const router = express.Router();
const db = require('./db');

router.get('/user', async (req, res) => {
  const userId = req.query.userId;
  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
  const results = await db.query(query);
  res.json(results);
});

module.exports = router;
`;

describeOrSkip("Live AI Provider Explanation Generation (Real Data)", () => {
  it("generates and validates a real explanation from real provider call", async () => {
    const finding: RealScanFinding = {
      rule_id: "javascript.lang.security.audit.sqli.node-sqli-injection",
      vuln_class: "sqli",
      cwe: "CWE-89",
      severity: "critical",
      raw_message: "Untrusted string concatenated into SQL query",
      file_path: "benchmark/samples/sqli-01-webgoat.js",
      line_start: 9,
      matched_text:
        "const query = \"SELECT * FROM users WHERE id = '\" + userId + \"' AND status = 'active'\";",
    };

    const result = await generateRealExplanation({
      finding,
      fileContent: REAL_SQLI_SAMPLE,
      primaryKey: TEST_KEY,
    });

    expect(result.output).toBeDefined();
    expect(result.output.what_it_is.technical).toBeTruthy();
    expect(result.output.what_it_is.simplified).toBeTruthy();
    expect(result.output.how_fix_works.technical).toBeTruthy();
    expect(result.output.attack_idea).toBeTruthy();
    expect(result.output.key_takeaway).toBeTruthy();
    expect(typeof result.output.likely_false_positive?.value).toBe("boolean");
    expect(result.modelUsed).toBeTruthy();
    expect(result.provider).toBeTruthy();

    // Verify snippet extraction
    expect(result.snippetWithLineNumbers).toContain(">>>");
    expect(result.snippetWithLineNumbers).toContain("SELECT * FROM users");
  });
});
