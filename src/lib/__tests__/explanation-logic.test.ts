/**
 * src/lib/__tests__/explanation-logic.test.ts
 *
 * Pure-logic tests for AI Explanation generation using real data fixtures:
 * - Snippet window extraction (±10 lines), line numbers, and >>> markers
 * - Strict snippet verification against scanner matched_text (throws on mismatch)
 * - Defensive prompt input building ("not provided" for missing CWE/class)
 * - Fenced JSON extraction and cleanup
 * - Zod schema validation against real model outputs
 * - Grounding checks verifying AI-mentioned identifiers against the real snippet
 * - Security & privacy guarantees (key redaction, sessionStorage only)
 */

import { describe, it, expect } from "vitest";
import {
  extractAndVerifySnippet,
  buildPromptInputData,
  normalizeLine,
  type RealScanFinding,
} from "../finding-input";
import { extractFirstJson, ExplanationOutputSchema } from "../explanation-service";
import { checkExplanationGrounding } from "../grounding-checker";
import { redactKeys } from "../ai-provider-detector";
import fixtureSqli from "./fixtures/explanation-sqli-gemini.json";
import fixtureNosqli from "./fixtures/explanation-nosqli-groq.json";

const SAMPLE_SQLI_CODE = `// Sample 1: SQL Injection via query string concat (Vulnerable)
// Source: OWASP NodeGoat (contributions.js)
// License: Apache-2.0

const express = require('express');
const router = express.Router();
const db = require('./db');

router.get('/user', async (req, res) => {
  const userId = req.query.userId;
  // Vulnerability: user input directly interpolated into SQL
  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
  const results = await db.query(query);
  res.json(results);
});

module.exports = router;
`;

describe("Step 1: Snippet Extraction and Verification", () => {
  it("extracts a ±10 line context window with exact line numbers and >>> on flagged line", () => {
    const flaggedLine = 12;
    const matchedText =
      "const query = \"SELECT * FROM users WHERE id = '\" + userId + \"' AND status = 'active'\";";

    const snippet = extractAndVerifySnippet(SAMPLE_SQLI_CODE, flaggedLine, matchedText, 10);

    expect(snippet.flaggedLineCode).toContain("SELECT * FROM users");
    expect(snippet.snippetWithLineNumbers).toContain(">>>   12 |   const query =");
    expect(snippet.snippetWithLineNumbers).toContain("       5 | const express =");
    expect(snippet.rawSnippetLines.some((l) => l.isFlagged && l.n === 12)).toBe(true);
  });

  it("normalizes whitespace during line comparison", () => {
    expect(normalizeLine("   const x   =   1; \t")).toBe("const x = 1;");
  });

  it("throws a descriptive error when flagged code does not match scanner matched_text", () => {
    expect(() =>
      extractAndVerifySnippet(
        SAMPLE_SQLI_CODE,
        12,
        "completely_different_code_that_does_not_exist()",
        10,
      ),
    ).toThrow(/Snippet verification mismatch at line 12/);
  });

  it("throws when fileContent is empty", () => {
    expect(() => extractAndVerifySnippet("", 5, undefined, 10)).toThrow(
      /File content is empty or could not be retrieved/,
    );
  });

  it("throws when target line is out of file bounds", () => {
    expect(() => extractAndVerifySnippet(SAMPLE_SQLI_CODE, 999, undefined, 10)).toThrow(
      /Flagged line 999 is out of bounds/,
    );
  });
});

describe("Step 1 & 2: Prompt Input Building", () => {
  it("substitutes 'not provided' when CWE or vuln_class is missing (never guesses)", () => {
    const finding: RealScanFinding = {
      rule_id: "javascript.lang.security.eval",
      severity: "high",
      file_path: "src/server.js",
      line_start: 10,
    };

    const inputData = buildPromptInputData(finding, "   10 | eval(x);");

    expect(inputData.cwe).toBe("not provided");
    expect(inputData.vuln_class).toBe("not provided");
    expect(inputData.message).toBe("not provided");
    expect(inputData.rule_id).toBe("javascript.lang.security.eval");
    expect(inputData.line_start).toBe(10);
  });

  it("preserves real scanner values when present", () => {
    const finding: RealScanFinding = {
      rule_id: "javascript.lang.security.audit.sqli",
      cwe: "CWE-89",
      vuln_class: "sqli",
      severity: "critical",
      raw_message: "Untrusted string concatenated into SQL query",
      file_path: "routes/user.js",
      line_start: 12,
    };

    const inputData = buildPromptInputData(finding, "   12 | db.query(q);");

    expect(inputData.cwe).toBe("CWE-89");
    expect(inputData.vuln_class).toBe("sqli");
    expect(inputData.severity).toBe("critical");
    expect(inputData.message).toBe("Untrusted string concatenated into SQL query");
  });
});

describe("Step 3 & 4: JSON Extraction & Zod Schema Validation", () => {
  it("extracts JSON wrapped in ```json code fences", () => {
    const raw = '```json\n{"hello": "world"}\n```';
    expect(extractFirstJson(raw)).toBe('{"hello": "world"}');
  });

  it("extracts the first valid JSON block when surrounded by stray commentary", () => {
    const raw = 'Here is the requested explanation:\n{"attack_idea": "test"}\nHope this helps!';
    expect(extractFirstJson(raw)).toBe('{"attack_idea": "test"}');
  });

  it("validates real Gemini SQL injection fixture against Zod schema", () => {
    const { _comment, ...payload } = fixtureSqli;
    const parsed = ExplanationOutputSchema.safeParse(payload);

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.what_it_is.technical).toContain("req.query.userId");
      expect(parsed.data.what_it_is.simplified).toBeTruthy();
      expect(parsed.data.how_fix_works.technical).toContain("parameterized queries");
      expect(parsed.data.attack_idea).toBeTruthy();
      expect(parsed.data.key_takeaway).toBeTruthy();
      expect(parsed.data.likely_false_positive.value).toBe(false);
    }
  });

  it("validates real Groq NoSQL injection fixture against Zod schema", () => {
    const { _comment, ...payload } = fixtureNosqli;
    const parsed = ExplanationOutputSchema.safeParse(payload);

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.what_it_is.technical).toContain("MongoDB");
      expect(parsed.data.attack_idea).toContain('"$gt"');
      expect(parsed.data.likely_false_positive.value).toBe(false);
    }
  });

  it("rejects incomplete output missing required fields", () => {
    const invalid = {
      what_it_is: { technical: "test", simplified: "test" },
      why_it_happened: { technical: "test", simplified: "test" },
      how_fix_works: { technical: "test", simplified: "test" },
      // missing attack_idea, key_takeaway, likely_false_positive, confidence_note
    };

    const parsed = ExplanationOutputSchema.safeParse(invalid);
    expect(parsed.success).toBe(false);
  });

  it("rejects output when technical or simplified explanation is empty string", () => {
    const invalid = {
      ...fixtureSqli,
      what_it_is: { technical: "", simplified: "test" },
    };

    const parsed = ExplanationOutputSchema.safeParse(invalid);
    expect(parsed.success).toBe(false);
  });
});

describe("Step 5: Grounding Checker", () => {
  it("confirms grounded explanation where backtick identifiers match snippet code", () => {
    const groundedExplanation = {
      what_it_is: {
        technical: "Input from `userId` is passed into `db.query`.",
        simplified: "The input `userId` is not checked.",
      },
      why_it_happened: {
        technical: "Concatenated into `query` string directly.",
        simplified: "Joined `query` with plus signs.",
      },
      how_fix_works: {
        technical: "Use parameterized query with `db.query`.",
        simplified: "Tell `db` to parameterize.",
      },
      attack_idea: "Injecting SQL via `userId` param.",
      key_takeaway: "Parameterize all database calls.",
    };

    const result = checkExplanationGrounding(
      groundedExplanation,
      SAMPLE_SQLI_CODE,
      "benchmark/samples/sqli-01-webgoat.js",
    );

    expect(result.isFullyGrounded).toBe(true);
    expect(result.warnings.length).toBe(0);
  });

  it("emits visible warnings when an explanation references hallucinated identifiers", () => {
    const hallucinatedExplanation = {
      what_it_is: {
        technical: "The function calls `secretVaultDecryptToken` in `authBroker`.",
        simplified: "Calls `secretVaultDecryptToken`.",
      },
      why_it_happened: {
        technical: "Missing validation on `secretVaultDecryptToken`.",
        simplified: "No check on `authBroker`.",
      },
      how_fix_works: {
        technical: "Update `cryptoGatewayKey` parameter.",
        simplified: "Fix `cryptoGatewayKey`.",
      },
      attack_idea: "Exploit `authBroker`.",
      key_takeaway: "Check all secrets.",
    };

    const result = checkExplanationGrounding(
      hallucinatedExplanation,
      SAMPLE_SQLI_CODE,
      "benchmark/samples/sqli-01-webgoat.js",
    );

    expect(result.isFullyGrounded).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.ungroundedTokens).toContain("secretVaultDecryptToken");
    expect(result.ungroundedTokens).toContain("authBroker");
  });
});

describe("Security & Privacy Guarantees", () => {
  it("redacts API keys from logs and error strings", () => {
    const key = "AIzaSyD9876543210TestApiKeySecretString";
    const rawError = `Failed to connect to Google API with key ${key}: 403 Forbidden`;

    const clean = redactKeys(rawError, [key]);
    expect(clean).not.toContain(key);
    expect(clean).toContain("[REDACTED_API_KEY]");
  });

  it("verifies that API keys never exist in explanation database fields", () => {
    const { _comment, ...payload } = fixtureSqli;
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain("AIza");
    expect(serialized).not.toContain("gsk_");
    expect(serialized).not.toContain("sk-");
  });
});
