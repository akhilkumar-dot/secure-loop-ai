/**
 * src/lib/finding-input.ts
 *
 * Implements Step 1 of AI Explanation Generation:
 * - Builds explanation inputs from real Semgrep / SAST scan data.
 * - Extracts ±10 lines of context around the flagged line from real repository files.
 * - Formats line numbers and marks the flagged line with ">>>".
 * - Rigorously verifies that the flagged line in the snippet matches the code Semgrep reported.
 * - Sets "not provided" for missing CWE or vulnerability class (never infers).
 */

export interface RealScanFinding {
  rule_id: string;
  vuln_class?: string | undefined;
  cwe?: string | undefined;
  severity: string;
  raw_message?: string | undefined;
  message?: string | undefined;
  file_path: string;
  line_start?: number | undefined;
  matched_text?: string | undefined;
}

export interface ExtractedSnippet {
  snippetWithLineNumbers: string;
  rawSnippetLines: Array<{ n: number; code: string; isFlagged: boolean }>;
  flaggedLineCode: string;
}

/**
 * Normalizes code line for comparison (removes leading/trailing whitespace).
 */
export function normalizeLine(line: string): string {
  return (line || "").trim().replace(/\s+/g, " ");
}

/**
 * Checks if actual line code matches expected matched_text,
 * taking into account potential credential masking (e.g. quotes replaced by '***' or wildcard ***).
 */
export function checkSnippetMatch(actualLineCode: string, expectedMatchedText: string): boolean {
  const normActual = normalizeLine(actualLineCode);
  const normExpected = normalizeLine(expectedMatchedText);

  // 1. Direct equality or substring match
  if (
    normActual === normExpected ||
    normActual.includes(normExpected) ||
    normExpected.includes(normActual)
  ) {
    return true;
  }

  // 2. If expected text was masked/redacted with '***', check against masked actual line
  if (normExpected.includes("***")) {
    // Check quote masking like in sast.ts: replace string literal contents >= 3 chars with ***
    const maskedActual = normActual.replace(/(['"`])[^'"`]{3,}[^'"`]*\1/g, "$1***$1");
    if (
      maskedActual === normExpected ||
      maskedActual.includes(normExpected) ||
      normExpected.includes(maskedActual)
    ) {
      return true;
    }

    // 3. General wildcard match where *** (or \*{3,}) matches any characters
    const escapedExpected = normExpected.replace(/[-[\]{}()+?.,\\^$|#\s]/g, "\\$&");
    const wildcardPattern = escapedExpected.replace(/\\\*\\\*\\\*+/g, ".*");
    try {
      const reg = new RegExp(`^${wildcardPattern}$`);
      if (reg.test(normActual)) return true;
      const subReg = new RegExp(wildcardPattern);
      if (subReg.test(normActual)) return true;
    } catch {
      // Ignore regex compile error and fallback
    }
  }

  return false;
}

/**
 * Extracts a ~10 line context window either side of the flagged line from real file content.
 * Verifies that the code on the flagged line matches what the scanner matched.
 * Throws a clear descriptive error if the snippet cannot be verified against the scan.
 */
export function extractAndVerifySnippet(
  fileContent: string,
  lineStart: number | undefined,
  expectedMatchedText?: string | undefined,
  contextLines: number = 10,
): ExtractedSnippet {
  if (typeof fileContent !== "string" || fileContent.length === 0) {
    throw new Error(
      "File content is empty or could not be retrieved from the repository at the scanned commit.",
    );
  }

  const lines = fileContent.split(/\r?\n/);
  const totalLines = lines.length;

  const targetLine = lineStart ?? 1;
  if (targetLine < 1 || targetLine > totalLines) {
    throw new Error(
      `Flagged line ${targetLine} is out of bounds for file with ${totalLines} line(s). Scan data may be corrupted.`,
    );
  }

  const zeroIndex = targetLine - 1;
  const actualLineCode = lines[zeroIndex] ?? "";

  // Verification against scanner reported matched_text (including redacted secrets)
  if (expectedMatchedText && expectedMatchedText.trim().length > 0) {
    const matches = checkSnippetMatch(actualLineCode, expectedMatchedText);

    if (!matches) {
      const normActual = normalizeLine(actualLineCode);
      const normExpected = normalizeLine(expectedMatchedText);
      throw new Error(
        `Snippet verification mismatch at line ${targetLine}. File content on line is ${JSON.stringify(
          normActual,
        )}, but scanner reported matching code ${JSON.stringify(normExpected)}. Stopping to prevent ungrounded AI explanation.`,
      );
    }
  }

  const startIdx = Math.max(0, zeroIndex - contextLines);
  const endIdx = Math.min(totalLines - 1, zeroIndex + contextLines);

  const rawSnippetLines: Array<{ n: number; code: string; isFlagged: boolean }> = [];
  const formattedLines: string[] = [];

  for (let i = startIdx; i <= endIdx; i++) {
    const lineNum = i + 1;
    const code = lines[i] ?? "";
    const isFlagged = i === zeroIndex;

    rawSnippetLines.push({ n: lineNum, code, isFlagged });

    const marker = isFlagged ? ">>>" : "   ";
    const lineNumStr = String(lineNum).padStart(4, " ");
    formattedLines.push(`${marker} ${lineNumStr} | ${code}`);
  }

  return {
    snippetWithLineNumbers: formattedLines.join("\n"),
    rawSnippetLines,
    flaggedLineCode: actualLineCode,
  };
}

export interface PromptInputData {
  rule_id: string;
  vuln_class: string;
  cwe: string;
  severity: string;
  message: string;
  file_path: string;
  line_start: number;
  snippet_with_line_numbers: string;
}

/**
 * Builds the exact prompt variables required for Step 2.
 * If CWE or vuln_class is missing, explicitly sends "not provided" (does not infer).
 */
export function buildPromptInputData(
  finding: RealScanFinding,
  snippetWithLineNumbers: string,
): PromptInputData {
  const lineStart = finding.line_start ?? 1;

  const cwe = (finding.cwe || "").trim();
  const vulnClass = (finding.vuln_class || "").trim();
  const rawMsg = (finding.raw_message || finding.message || "").trim();

  return {
    rule_id: finding.rule_id || "not provided",
    vuln_class: vulnClass ? vulnClass : "not provided",
    cwe: cwe ? cwe : "not provided",
    severity: finding.severity || "not provided",
    message: rawMsg ? rawMsg : "not provided",
    file_path: finding.file_path,
    line_start: lineStart,
    snippet_with_line_numbers: snippetWithLineNumbers,
  };
}

export const EXPLANATION_SYSTEM_PROMPT = `You are a secure-code-review tutor for beginner developers. You explain one static-analysis finding at a time.

Rules:
- Use ONLY the code, rule and CWE provided. Refer to real variable and function names from the snippet. Never invent files, line numbers, libraries or APIs.
- Be technically accurate. Base advice on established guidance (OWASP Cheat Sheet Series, MITRE CWE). If you are unsure, say so in "confidence_note" instead of guessing.
- If the code looks safe or the rule appears to be a false positive, say that in "likely_false_positive" and explain why.
- Do not give a working exploit or attack payload. Describe the attack idea in words only.
- Return ONLY a JSON object matching the schema. No markdown, no code fences, no extra text.`;

export function formatExplanationUserPrompt(data: PromptInputData): string {
  return `Finding:
- Rule: ${data.rule_id}
- Vulnerability class: ${data.vuln_class}   (CWE: ${data.cwe})
- Severity: ${data.severity}
- Scanner message: ${data.message}
- File: ${data.file_path}, flagged line: ${data.line_start}

Code (flagged line marked with >>>):
${data.snippet_with_line_numbers}

Return JSON with exactly these keys:
{
  "likely_false_positive": {"value": true|false, "reason": "..."},
  "confidence_note":   "empty string if confident",
  "what_it_is":        {"technical": "...", "simplified": "..."},
  "why_it_happened":   {"technical": "...", "simplified": "..."},
  "how_fix_works":     {"technical": "...", "simplified": "..."},
  "attack_idea":       "one or two sentences, in words only",
  "key_takeaway":      "one sentence a student can remember"
}

Style: "technical" is for a developer (precise, 2-4 sentences). "simplified" is for a beginner (plain words, an everyday analogy is fine, 2-3 sentences, no jargon without explaining it).`;
}
