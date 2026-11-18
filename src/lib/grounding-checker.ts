/**
 * src/lib/grounding-checker.ts
 *
 * Implements Step 5: Grounding Check
 * Verifies that file names, function names, and variable names mentioned in the AI explanation
 * actually appear in the inspected code snippet or file path.
 *
 * Returns visible warning messages if an ungrounded identifier is found.
 */

const COMMON_LANGUAGE_KEYWORDS = new Set([
  "function",
  "const",
  "let",
  "var",
  "if",
  "else",
  "for",
  "while",
  "do",
  "return",
  "import",
  "export",
  "from",
  "default",
  "class",
  "extends",
  "new",
  "this",
  "super",
  "try",
  "catch",
  "finally",
  "throw",
  "async",
  "await",
  "yield",
  "typeof",
  "instanceof",
  "in",
  "of",
  "void",
  "delete",
  "switch",
  "case",
  "break",
  "continue",
  "true",
  "false",
  "null",
  "undefined",
  "string",
  "number",
  "boolean",
  "object",
  "array",
  "any",
  "unknown",
  "never",
  "interface",
  "type",
  "enum",
  "public",
  "private",
  "protected",
  "static",
]);

const COMMON_SECURITY_TERMS = new Set([
  "sql",
  "sqli",
  "xss",
  "csrf",
  "ssrf",
  "html",
  "http",
  "https",
  "get",
  "post",
  "put",
  "delete",
  "json",
  "ast",
  "dom",
  "waf",
  "url",
  "uri",
  "jwt",
  "api",
  "cwe",
  "owasp",
  "semgrep",
  "regex",
  "sink",
  "source",
  "sanitizer",
  "middleware",
  "cookie",
  "session",
  "header",
  "cors",
  "csp",
  "sha",
  "md5",
  "eval",
]);

export interface GroundingCheckResult {
  isFullyGrounded: boolean;
  warnings: string[];
  ungroundedTokens: string[];
}

/**
 * Checks that variable names, function names, and file names mentioned in backticks
 * or explicit code quotes appear in the real code snippet or file path.
 */
export function checkExplanationGrounding(
  explanation: {
    what_it_is: { technical: string; simplified: string };
    why_it_happened: { technical: string; simplified: string };
    how_fix_works: { technical: string; simplified: string };
    attack_idea: string;
    key_takeaway: string;
  },
  snippetCode: string,
  filePath: string,
): GroundingCheckResult {
  const combinedExplanationText = [
    explanation.what_it_is.technical,
    explanation.what_it_is.simplified,
    explanation.why_it_happened.technical,
    explanation.why_it_happened.simplified,
    explanation.how_fix_works.technical,
    explanation.how_fix_works.simplified,
    explanation.attack_idea,
    explanation.key_takeaway,
  ].join(" ");

  // Extract tokens wrapped in backticks: `identifier`
  const backtickMatches = Array.from(combinedExplanationText.matchAll(/`([^`]+)`/g))
    .map((m) => m[1]?.trim() ?? "")
    .filter(Boolean);

  const cleanSnippet = snippetCode.toLowerCase();
  const cleanFilePath = filePath.toLowerCase();
  const ungroundedTokens: string[] = [];
  const warnings: string[] = [];

  for (const token of backtickMatches) {
    // Strip trailing parenthesis e.g. "func()" -> "func"
    const normalized = token.replace(/\(\)$/, "").trim();
    if (!normalized || normalized.length < 2) continue;

    // Check if it's a common keyword or security acronym
    const lower = normalized.toLowerCase();
    if (COMMON_LANGUAGE_KEYWORDS.has(lower) || COMMON_SECURITY_TERMS.has(lower)) {
      continue;
    }

    // Check if it looks like an identifier or path
    const isIdentifier = /^[a-zA-Z_$][a-zA-Z0-9_$.-]*$/.test(normalized);
    if (!isIdentifier) continue;

    // Check if token or member property exists in the code snippet or file path
    const tokenExistsInSnippet = cleanSnippet.includes(lower);
    const tokenExistsInPath = cleanFilePath.includes(lower);

    // If it's a property access (e.g. "req.body" or "user.name"), check parts
    let partExists = false;
    if (normalized.includes(".")) {
      const parts = lower.split(".");
      partExists = parts.some((p) => p.length > 2 && cleanSnippet.includes(p));
    }

    if (!tokenExistsInSnippet && !tokenExistsInPath && !partExists) {
      ungroundedTokens.push(token);
      warnings.push(
        `Explanation mentions '${token}', but this identifier does not appear in the inspected code snippet or file path.`,
      );
    }
  }

  return {
    isFullyGrounded: warnings.length === 0,
    warnings,
    ungroundedTokens,
  };
}
