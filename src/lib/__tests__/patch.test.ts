/**
 * src/lib/__tests__/patch.test.ts
 *
 * Unit tests for patch generation, original-code matching, unified-diff construction,
 * syntax checking, and deterministic validation.
 *
 * Uses REAL files and findings from repository scans as labeled fixtures:
 * 1. skills/unslop/scripts/story.mjs:211 (CWE-79, commit 620163eedb3529d9cd23a3994ed8d287d06f760d)
 * 2. benchmark/samples/xss-01-innerhtml.js:9 (CWE-79, OWASP Juice Shop)
 * 3. benchmark/samples/path-01-traversal.js:5 (CWE-22, OWASP Benchmark)
 * 4. benchmark/samples/sqli-01-webgoat.js:12 (CWE-89, OWASP NodeGoat)
 * 5. benchmark/samples/cmd-01-exec-injection.js:12 (CWE-78, OWASP NodeGoat)
 * 6. benchmark/samples/cred-01-hardcoded-secret.js:11 (CWE-798, OWASP Benchmark)
 */
import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import {
  applyUnifiedDiff,
  hasLineNumberPrefixes,
  verifyOriginalCode,
  generateUnifiedDiff,
  isXssInnerHtmlToTextContent,
  checkSyntax,
} from "../patch";
import { scanFile } from "../sast";
import { validatePatch } from "../ai-pipeline";

// ── Real Fixture Data ───────────────────────────────────────────────────────

/** Real snippet from skills/unslop/scripts/story.mjs (commit 620163eedb3529d9cd23a3994ed8d287d06f760d, line 211) */
const STORY_MJS_CONTENT = `// skills/unslop/scripts/story.mjs - commit 620163eedb3529d9cd23a3994ed8d287d06f760d
export function createBox(className, style, html) {
  const node = document.createElement("div");
  node.className = className;
  Object.assign(node.style, style);
  if (html) node.innerHTML = html;
  document.body.appendChild(node);
  return node;
}
`;

// ── Tests ──────────────────────────────────────────────────────────────────

describe("Line-Number Prefix Detection", () => {
  it("rejects real malformed AI response from story.mjs:211 that included line numbers", () => {
    // Exact output that broke finding 7cf102c2-2e35-43b0-af3d-76d333034133:
    const malformedOriginal = `208:     node.className = className;\n209:     Object.assign(node.style, style);\n210:     if (html) node.innerHTML = html;`;
    const malformedReplacement = `208:     node.className = className;\n209:     Object.assign(node.style, style);\n210:     if (html) node.textContent = html;`;

    expect(hasLineNumberPrefixes(malformedOriginal)).toBe(true);
    expect(hasLineNumberPrefixes(malformedReplacement)).toBe(true);
  });

  it("detects pipe-separated and space-separated line prefixes", () => {
    expect(hasLineNumberPrefixes("211 |   if (html) node.innerHTML = html;")).toBe(true);
    expect(hasLineNumberPrefixes(" 211:  const a = 1;")).toBe(true);
  });

  it("accepts clean plain code without line-number prefixes", () => {
    const cleanOriginal = `    node.className = className;\n    Object.assign(node.style, style);\n    if (html) node.innerHTML = html;`;
    const cleanReplacement = `    if (html) node.textContent = html;`;

    expect(hasLineNumberPrefixes(cleanOriginal)).toBe(false);
    expect(hasLineNumberPrefixes(cleanReplacement)).toBe(false);
  });
});

describe("verifyOriginalCode against Real Source Files", () => {
  it("verifies matching lines in story.mjs fixture", () => {
    // Lines 6..6: '  if (html) node.innerHTML = html;'
    const result = verifyOriginalCode(
      STORY_MJS_CONTENT,
      6,
      6,
      "  if (html) node.innerHTML = html;",
    );
    expect(result.ok).toBe(true);
  });

  it("rejects when line numbers are off-by-one (e.g. line 5 instead of line 6)", () => {
    const result = verifyOriginalCode(
      STORY_MJS_CONTENT,
      5,
      5,
      "  if (html) node.innerHTML = html;",
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("Content mismatch at line 5");
    expect(result.expectedLines).toBeDefined();
  });

  it("rejects when model provides wrong number of lines", () => {
    const result = verifyOriginalCode(STORY_MJS_CONTENT, 6, 6, "  line1\n  line2");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("Line count mismatch");
  });

  it("rejects out-of-bounds start or end lines", () => {
    expect(verifyOriginalCode(STORY_MJS_CONTENT, 0, 5, "x").ok).toBe(false);
    expect(verifyOriginalCode(STORY_MJS_CONTENT, 1, 999, "x").ok).toBe(false);
  });

  it("verifies real benchmark file: benchmark/samples/xss-01-innerhtml.js line 9", () => {
    const filePath = path.resolve(process.cwd(), "benchmark/samples/xss-01-innerhtml.js");
    const fileContent = fs.readFileSync(filePath, "utf8");
    const expectedLine = '  container.innerHTML = "<h3>Results for: " + query + "</h3>" + data;';

    const result = verifyOriginalCode(fileContent, 9, 9, expectedLine);
    expect(result.ok).toBe(true);
  });
});

describe("Programmatic generateUnifiedDiff on Real Findings", () => {
  it("Fixture 1: story.mjs:211 (CWE-79) - generates clean diff with correct hunk counts that applies deterministically", () => {
    const diff = generateUnifiedDiff({
      filePath: "skills/unslop/scripts/story.mjs",
      fileContent: STORY_MJS_CONTENT,
      startLine: 6,
      endLine: 6,
      replacementCode: "  if (html) node.textContent = html;",
    });

    // Valid header format
    expect(diff).toContain("--- a/skills/unslop/scripts/story.mjs");
    expect(diff).toContain("+++ b/skills/unslop/scripts/story.mjs");
    expect(diff).toMatch(/^@@ -\d+,\d+ \+\d+,\d+ @@/m);

    // No line number prefixes in diff
    expect(diff).not.toMatch(/208:/);
    expect(diff).not.toMatch(/210:/);

    // Apply check
    const applyResult = applyUnifiedDiff(STORY_MJS_CONTENT, diff);
    expect(applyResult.ok).toBe(true);
    expect(applyResult.patched).toContain("node.textContent = html;");
    expect(applyResult.patched).not.toContain("node.innerHTML = html;");
  });

  it("Fixture 2: benchmark/samples/xss-01-innerhtml.js (CWE-79, OWASP Juice Shop)", async () => {
    const filePath = "benchmark/samples/xss-01-innerhtml.js";
    const fileContent = fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8");

    // Scan original: rule fires
    const beforeScan = scanFile(filePath, fileContent);
    expect(beforeScan.some((f) => f.rule_id.includes("innerHTML"))).toBe(true);

    const diff = generateUnifiedDiff({
      filePath,
      fileContent,
      startLine: 9,
      endLine: 9,
      replacementCode: '  container.textContent = "Results for: " + query + data;',
    });

    const applyResult = applyUnifiedDiff(fileContent, diff);
    expect(applyResult.ok).toBe(true);

    // Re-scan: rule no longer fires
    const afterScan = scanFile(filePath, applyResult.patched!);
    expect(afterScan.some((f) => f.rule_id.includes("innerHTML"))).toBe(false);

    // Syntax check passes
    const syntaxOk = await checkSyntax(applyResult.patched!, filePath);
    expect(syntaxOk).toBe(true);
  });

  it("Fixture 3: benchmark/samples/path-01-traversal.js (CWE-22, OWASP Benchmark)", async () => {
    const filePath = "benchmark/samples/path-01-traversal.js";
    const fileContent = fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8");

    // Pure logic test: verify original code match
    const verify = verifyOriginalCode(
      fileContent,
      5,
      5,
      '  const filePath = path.join(__dirname, "public", req.query.file);',
    );
    expect(verify.ok).toBe(true);

    const diff = generateUnifiedDiff({
      filePath,
      fileContent,
      startLine: 5,
      endLine: 5,
      replacementCode:
        "  const safe = path.basename(req.query.file);\n  const filePath = path.resolve(__dirname, 'public', safe);",
    });

    const applyResult = applyUnifiedDiff(fileContent, diff);
    expect(applyResult.ok).toBe(true);
    expect(applyResult.patched).toContain("path.basename");

    const syntaxOk = await checkSyntax(applyResult.patched!, filePath);
    expect(syntaxOk).toBe(true);
  });

  it("Fixture 4: benchmark/samples/sqli-01-webgoat.js (CWE-89, OWASP NodeGoat)", async () => {
    const filePath = "benchmark/samples/sqli-01-webgoat.js";
    const fileContent = fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8");

    // Pure logic test: verify original code match
    const verify = verifyOriginalCode(
      fileContent,
      12,
      12,
      "  const query = \"SELECT * FROM users WHERE id = '\" + userId + \"' AND status = 'active'\";",
    );
    expect(verify.ok).toBe(true);

    const diff = generateUnifiedDiff({
      filePath,
      fileContent,
      startLine: 12,
      endLine: 12,
      replacementCode:
        "  const query = \"SELECT * FROM users WHERE id = ? AND status = 'active'\";",
    });

    const applyResult = applyUnifiedDiff(fileContent, diff);
    expect(applyResult.ok).toBe(true);
    expect(applyResult.patched).toContain("SELECT * FROM users WHERE id = ?");

    const syntaxOk = await checkSyntax(applyResult.patched!, filePath);
    expect(syntaxOk).toBe(true);
  });

  it("Fixture 5: benchmark/samples/cmd-01-exec-injection.js (CWE-78, OWASP NodeGoat)", async () => {
    const filePath = "benchmark/samples/cmd-01-exec-injection.js";
    const fileContent = fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8");

    const beforeScan = scanFile(filePath, fileContent);
    expect(beforeScan.some((f) => f.rule_id.includes("child-process-injection"))).toBe(true);

    const diff = generateUnifiedDiff({
      filePath,
      fileContent,
      startLine: 12,
      endLine: 12,
      replacementCode:
        '  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, "");\n  exec("convert " + safe + " output.png", (err, stdout) => {',
    });

    const applyResult = applyUnifiedDiff(fileContent, diff);
    expect(applyResult.ok).toBe(true);

    const syntaxOk = await checkSyntax(applyResult.patched!, filePath);
    expect(syntaxOk).toBe(true);
  });

  it("Fixture 6: benchmark/samples/cred-01-hardcoded-secret.js (CWE-798, OWASP Benchmark)", async () => {
    const filePath = "benchmark/samples/cred-01-hardcoded-secret.js";
    const fileContent = fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8");

    const beforeScan = scanFile(filePath, fileContent);
    expect(beforeScan.some((f) => f.rule_id.includes("hardcoded-credentials"))).toBe(true);

    const diff = generateUnifiedDiff({
      filePath,
      fileContent,
      startLine: 11,
      endLine: 11,
      replacementCode: "  password: process.env.DB_PASSWORD,",
    });

    const applyResult = applyUnifiedDiff(fileContent, diff);
    expect(applyResult.ok).toBe(true);

    const afterScan = scanFile(filePath, applyResult.patched!);
    expect(afterScan.some((f) => f.rule_id.includes("hardcoded-credentials"))).toBe(false);

    const syntaxOk = await checkSyntax(applyResult.patched!, filePath);
    expect(syntaxOk).toBe(true);
  });
});

describe("XSS Behavior Note Detection", () => {
  it("detects when innerHTML is replaced by textContent", () => {
    expect(
      isXssInnerHtmlToTextContent(
        "if (html) node.innerHTML = html;",
        "if (html) node.textContent = html;",
      ),
    ).toBe(true);
  });

  it("does not trigger when replacement still uses innerHTML or DOMPurify", () => {
    expect(
      isXssInnerHtmlToTextContent(
        "node.innerHTML = html;",
        "node.innerHTML = DOMPurify.sanitize(html);",
      ),
    ).toBe(false);
  });
});

describe("Deterministic Validator: Untested Status on Failed Diff Apply", () => {
  it("reports 'not tested (patch did not apply)' in logs and null status when diff does not apply", async () => {
    const finding = {
      file_path: "benchmark/samples/xss-01-innerhtml.js",
      rule_id: "javascript.browser.security.innerHTML-assignment.innerHTML-assignment",
      line_start: 9,
      source: "sast",
    };

    const invalidDiff = "// Invalid patch: Original code mismatch: Content mismatch at line 9";
    const fileContent = fs.readFileSync(path.resolve(process.cwd(), finding.file_path), "utf8");

    const validation = await validatePatch(finding, invalidDiff, fileContent);

    expect(validation.diff_applies).toBe(false);
    expect(validation.failed_check).toBe("diff_does_not_apply");
    expect(validation.verdict).toBe("rejected");
    expect(validation.vulnerability_gone).toBeNull();
    expect(validation.syntax_ok).toBeNull();

    // Verify logs explicitly contain 'not tested (patch did not apply)'
    const logStr = validation.logs.join("\n");
    expect(logStr).toContain("not tested (patch did not apply)");
  });
});
