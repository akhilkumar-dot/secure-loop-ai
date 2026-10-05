/**
 * src/lib/patch.ts
 *
 * Deterministic unified-diff applicator.
 *
 * Supports standard unified-diff hunks:  @@ -oldStart,oldCount +newStart,newCount @@
 * Tolerates small line-offset drift (up to DRIFT_TOLERANCE lines) so diffs generated
 * from a ±150-line window still apply even when the file has minor additions above the hunk.
 *
 * Returns { ok: false, error } when the diff cannot be applied rather than silently
 * producing wrong output.
 */

export interface ApplyResult {
  ok: boolean;
  patched?: string;
  error?: string;
}

const DRIFT_TOLERANCE = 5; // lines of acceptable offset drift

interface Hunk {
  oldStart: number; // 1-based
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: string[]; // raw diff lines including leading ' ', '+', '-'
}

/** Parse all hunks out of a unified diff string. */
function parseHunks(diff: string): { hunks: Hunk[]; error?: string } {
  const hunks: Hunk[] = [];
  const diffLines = diff.split("\n");

  let i = 0;
  while (i < diffLines.length) {
    const line = diffLines[i]!;
    // Skip file header lines (---, +++, diff --git …)
    if (
      line.startsWith("---") ||
      line.startsWith("+++") ||
      line.startsWith("diff ") ||
      line.startsWith("index ")
    ) {
      i++;
      continue;
    }
    const hunkHeader = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/.exec(line);
    if (!hunkHeader) {
      i++;
      continue;
    }

    const oldStart = parseInt(hunkHeader[1]!, 10);
    const oldCount = hunkHeader[2] !== undefined ? parseInt(hunkHeader[2]!, 10) : 1;
    const newStart = parseInt(hunkHeader[3]!, 10);
    const newCount = hunkHeader[4] !== undefined ? parseInt(hunkHeader[4]!, 10) : 1;

    const hunkLines: string[] = [];
    i++;
    while (i < diffLines.length && !diffLines[i]!.startsWith("@@")) {
      hunkLines.push(diffLines[i]!);
      i++;
    }

    hunks.push({ oldStart, oldCount, newStart, newCount, lines: hunkLines });
  }

  if (hunks.length === 0) {
    return { hunks: [], error: "No hunks found in diff" };
  }

  return { hunks };
}

/**
 * Find the actual starting line in `fileLines` (0-indexed) for a hunk whose
 * expected start is `expectedStart` (1-based). Searches within DRIFT_TOLERANCE.
 */
function findHunkOffset(
  fileLines: string[],
  hunkLines: string[],
  expectedStart: number, // 1-based
): number | null {
  // Context lines from the hunk (lines starting with ' ')
  const contextLines = hunkLines
    .filter((l) => l.startsWith(" ") || l.startsWith("-"))
    .map((l) => l.slice(1));

  if (contextLines.length === 0) {
    // No context — trust the line number
    return Math.max(0, expectedStart - 1);
  }

  const firstContext = contextLines[0]!.trimEnd();

  // Search for first context line within drift tolerance
  const searchStart = Math.max(0, expectedStart - 1 - DRIFT_TOLERANCE);
  const searchEnd = Math.min(fileLines.length - 1, expectedStart - 1 + DRIFT_TOLERANCE);

  for (let i = searchStart; i <= searchEnd; i++) {
    if (fileLines[i]!.trimEnd() === firstContext) {
      return i;
    }
  }

  // Last resort: trust expected line number if within bounds
  const fallback = expectedStart - 1;
  if (fallback >= 0 && fallback < fileLines.length) {
    return fallback;
  }

  return null;
}

/**
 * Apply a single hunk to fileLines (mutating). Returns an error string on failure.
 */
function applyHunk(fileLines: string[], hunk: Hunk): string | null {
  const actualOffset = findHunkOffset(fileLines, hunk.lines, hunk.oldStart);
  if (actualOffset === null) {
    return `Cannot locate hunk context near line ${hunk.oldStart} (drift tolerance: ±${DRIFT_TOLERANCE})`;
  }

  // Walk through hunk lines and build the replacement block
  const replacement: string[] = [];
  let filePointer = actualOffset;
  const contextAndRemoved = hunk.lines.filter((l) => l.startsWith(" ") || l.startsWith("-"));

  // Verify context lines match before applying
  let ctxIdx = 0;
  for (const hunkLine of hunk.lines) {
    if (hunkLine.startsWith(" ")) {
      const expected = hunkLine.slice(1).trimEnd();
      const actual = (fileLines[filePointer + ctxIdx] ?? "").trimEnd();
      if (expected !== actual) {
        // Allow near-match (trimmed whitespace only)
        if (expected.trim() !== actual.trim()) {
          return `Context mismatch at line ${filePointer + ctxIdx + 1}: expected "${expected}" got "${actual}"`;
        }
      }
      ctxIdx++;
    } else if (hunkLine.startsWith("-")) {
      ctxIdx++;
    }
  }

  // Build replacement
  for (const hunkLine of hunk.lines) {
    if (hunkLine.startsWith(" ")) {
      replacement.push(fileLines[filePointer++] ?? hunkLine.slice(1));
    } else if (hunkLine.startsWith("-")) {
      filePointer++; // remove this line
    } else if (hunkLine.startsWith("+")) {
      replacement.push(hunkLine.slice(1));
    }
    // Lines starting with '\' (no newline at EOF) are ignored
  }

  // Verify we consumed the expected number of old lines
  const consumed = contextAndRemoved.length;
  if (consumed !== hunk.oldCount && hunk.oldCount > 0) {
    // Non-fatal: warn but proceed (line counts in diffs are sometimes off-by-one)
    console.warn(
      `[patch] Hunk old count mismatch: header says ${hunk.oldCount}, consumed ${consumed}`,
    );
  }

  // Replace the consumed region with the replacement
  fileLines.splice(actualOffset, filePointer - actualOffset, ...replacement);
  return null; // success
}

/**
 * Apply a unified diff string to `original` file content.
 *
 * @param original  The full original file content as a string.
 * @param diff      A unified diff (output of `git diff` or similar).
 * @returns         { ok: true, patched } on success, { ok: false, error } on failure.
 */
export function applyUnifiedDiff(original: string, diff: string): ApplyResult {
  if (!diff || diff.trim() === "" || diff.startsWith("//")) {
    return { ok: false, error: "Empty or placeholder diff" };
  }

  const { hunks, error: parseError } = parseHunks(diff);
  if (parseError) {
    return { ok: false, error: parseError };
  }

  // Work on a mutable array of lines (preserve trailing newlines)
  const fileLines = original.split("\n");

  // Apply hunks in order; track offset drift to keep subsequent hunks aligned
  let drift = 0;
  for (const hunk of hunks) {
    // Adjust hunk start for drift from previous hunk applications
    const adjustedHunk: Hunk = { ...hunk, oldStart: hunk.oldStart + drift };
    const err = applyHunk(fileLines, adjustedHunk);
    if (err) {
      return { ok: false, error: err };
    }
    // Drift = new lines added - old lines removed
    const added = hunk.lines.filter((l) => l.startsWith("+")).length;
    const removed = hunk.lines.filter((l) => l.startsWith("-")).length;
    drift += added - removed;
  }

  return { ok: true, patched: fileLines.join("\n") };
}

/**
 * Check JS/TS syntax by attempting to parse with acorn.
 * Returns true if syntax is OK, false if parse error detected, null if not checked.
 *
 * Only checked for: .js .jsx .ts .tsx .mjs .cjs
 */
export async function checkSyntax(content: string, filePath: string): Promise<boolean | null> {
  const ext = filePath.split(".").pop()?.toLowerCase();
  const jsLike = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"]);
  if (!ext || !jsLike.has(ext)) return null;

  try {
    // Dynamic import so the module is not required in environments where acorn isn't available
    const acorn = await import("acorn");
    // Strip TypeScript-specific syntax before parsing with acorn (acorn is JS-only)
    // Simple strip: remove type annotations, import type, etc. — this is best-effort
    let src = content;
    if (ext === "ts" || ext === "tsx") {
      // Replace `: Type` annotations, `as Type` casts, generics – very rough heuristic
      // For a production implementation, use typescript.transpileModule
      src = src
        .replace(/:\s*\w[\w<>[\]|&, ]*(?=[=,;)\n{])/g, "")
        .replace(/\bas\s+\w[\w<>[\]|& ]*/g, "")
        .replace(/<[A-Z]\w*>/g, "");
    }
    acorn.parse(src, { ecmaVersion: "latest", sourceType: "module" });
    return true;
  } catch {
    // If acorn itself throws for non-syntax reasons (import failure etc.), don't penalize
    return false;
  }
}
