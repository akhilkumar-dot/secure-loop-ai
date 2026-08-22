/**
 * SecureLoop SAST Rule Engine
 *
 * Deterministic pattern-based scanner modelled after Semgrep's
 * p/owasp-top-ten, p/nosql-injection, and p/nodejsscan packs.
 *
 * Contract:
 *   - SAST rules are the SOURCE OF TRUTH for detection.
 *   - LLM is NEVER the detector — only the explainer/patcher.
 *   - Rule IDs follow Semgrep registry format for paper citation.
 *   - source: "sast" = deterministic | "llm-heuristic" = secondary
 */

export interface SastFinding {
  rule_id: string;
  cwe: string;
  severity: "critical" | "high" | "medium" | "low";
  vulnerability_class: "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";
  file_path: string;
  line_start: number;
  line_end: number;
  raw_message: string;
  matched_text: string;
  code_lines: Array<{ n: number; code: string; vuln: boolean }>;
  source: "sast" | "llm-heuristic";
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

function mkCodeLines(
  lines: string[],
  center: number,
  ctx = 2,
): Array<{ n: number; code: string; vuln: boolean }> {
  const start = Math.max(0, center - ctx);
  const end = Math.min(lines.length - 1, center + ctx);
  return Array.from({ length: end - start + 1 }, (_, i) => ({
    n: start + i + 1,
    code: lines[start + i] ?? "",
    vuln: start + i === center,
  }));
}

function win(lines: string[], from: number, size = 8): string {
  return lines.slice(from, Math.min(from + size, lines.length)).join("\n");
}

const USER_INPUT = /req\.(body|query|params|files)\b/;
const MONGO_OPS =
  /\.(findOne|find|findById|findByIdAndUpdate|updateOne|updateMany|deleteOne|deleteMany|replaceOne|count|countDocuments|aggregate)\s*\(/;
const SANITIZED = /sanitize|escape|validator\.|isString|typeof\s+\w+\s*===\s*['"]string['"]/i;

type Rule = (lines: string[], filePath: string) => SastFinding[];

/* ── Rule 1: NoSQLi — direct user input in MongoDB query ─────────────────── */
const ruleNoSqlDirectInput: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!MONGO_OPS.test(line)) continue;
    const ctx = win(lines, i, 8);
    if (!USER_INPUT.test(ctx)) continue;
    if (SANITIZED.test(ctx)) continue;
    out.push({
      rule_id: "javascript.mongodb.nosqli.nosql-injection-req-body",
      cwe: "CWE-943",
      severity: "critical",
      vulnerability_class: "sqli",
      file_path: fp,
      line_start: i + 1,
      line_end: Math.min(i + 4, lines.length),
      raw_message:
        "Unsanitized req.body/query/params flows into a MongoDB query. An attacker can inject operators like {$gt:''} to bypass auth or dump data.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 3),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 2: NoSQLi — $where with string concatenation ───────────────────── */
const ruleNoSqlWhere: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const whereRe = /\$where\s*:/;
  const concatRe = /\+\s*(req\.(session|body|query|params)|userId|this\.\w+)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!whereRe.test(line)) continue;
    const ctx = win(lines, Math.max(0, i - 2), 6);
    if (!concatRe.test(ctx) && !USER_INPUT.test(ctx)) continue;
    out.push({
      rule_id: "javascript.mongodb.nosqli.nosql-where-injection",
      cwe: "CWE-943",
      severity: "critical",
      vulnerability_class: "sqli",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "MongoDB $where operator with string concatenation allows arbitrary JavaScript injection evaluated by the MongoDB engine.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 3: XSS — innerHTML with non-literal value ─────────────────────── */
const ruleXssInnerHtml: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const re = /\.innerHTML\s*\+?=\s*(.+)/;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(re);
    if (!m) continue;
    const rhs = (m[1] ?? "").trim();
    // pure string literal → safe
    if (/^["'`][^"'`+]*["'`]\s*;?\s*$/.test(rhs)) continue;
    out.push({
      rule_id: "javascript.browser.security.innerHTML-assignment.innerHTML-assignment",
      cwe: "CWE-79",
      severity: "high",
      vulnerability_class: "xss",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "innerHTML assigned a non-literal value. If this value contains user-controlled data, it enables stored or reflected XSS. Use textContent or DOMPurify.",
      matched_text: lines[i]!.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 4: XSS — res.send/res.write with user input (server-side) ────────*/
const ruleXssResSend: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const resSend = /res\.(send|write|end)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!resSend.test(line)) continue;
    const ctx = win(lines, Math.max(0, i - 3), 7);
    if (!USER_INPUT.test(ctx) && !/req\.(session|user)/.test(ctx)) continue;
    if (/encode|escape|sanitize|DOMPurify|xss\(/.test(ctx)) continue;
    out.push({
      rule_id: "javascript.express.xss.res-send-user-data.res-send-user-data",
      cwe: "CWE-79",
      severity: "high",
      vulnerability_class: "xss",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "res.send/write called with data that may include user-controlled input. Ensure HTML encoding before reflecting user data in responses.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 3),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 5: XSS — eval() with user input ────────────────────────────────── */
const ruleXssEval: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const evalRe = /\beval\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!evalRe.test(line)) continue;
    const ctx = win(lines, Math.max(0, i - 2), 5);
    if (!USER_INPUT.test(ctx) && !/req\.(session|user)/.test(ctx)) continue;
    out.push({
      rule_id: "javascript.lang.security.audit.eval-user-input.eval-user-input",
      cwe: "CWE-79",
      severity: "critical",
      vulnerability_class: "xss",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "eval() called with user-controlled input enables arbitrary code execution (XSS and RCE).",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 6: XSS — unescaped Swig/EJS/Pug template variable ─────────────── */
const ruleXssTemplate: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  // EJS unescaped: <%- var %>, Handlebars: {{{ var }}}, Pug: != var (at start of pug statement)
  const unsafeRe = /<%-(.*?)%>|\{\{\{(.*?)\}\}\}|^\s*[\w.-]+!=\s+\w/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!unsafeRe.test(line)) continue;
    out.push({
      rule_id: "javascript.express.xss.unescaped-template-var.unescaped-template-var",
      cwe: "CWE-79",
      severity: "high",
      vulnerability_class: "xss",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "Template uses unescaped variable output (<%- in EJS, {{{ in Handlebars). If the value contains user data this is a stored/reflected XSS.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 14: Java — SQL injection via string concatenation in query ─────── */
const ruleJavaSqlInjection: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const javaSqlRe = /(?:createQuery|createNativeQuery|executeQuery|jdbcTemplate\.query|jdbcTemplate\.update)\s*\(/;
  const concatRe = /\+\s*\w+|`[^`]*\$\{/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (javaSqlRe.test(line) && concatRe.test(line)) {
      out.push({
        rule_id: "java.spring.security.audit.sqli.spring-sqli-concat",
        cwe: "CWE-89",
        severity: "critical",
        vulnerability_class: "sqli",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "Dynamic SQL query constructed with string concatenation in Java/Spring. Use parameterized queries or JPQL named parameters.",
        matched_text: line.trim(),
        code_lines: mkCodeLines(lines, i, 3),
        source: "sast",
      });
    }
  }
  return out;
};

/* ── Rule 15: Java — XSS via Servlet Response Writer ─────────────────────── */
const ruleJavaXssWriter: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const writerRe = /response\.getWriter\(\)\.(?:write|print|println)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (writerRe.test(line) && /\+\s*\w+/.test(line)) {
      out.push({
        rule_id: "java.lang.security.audit.xss.servlet-response-writer",
        cwe: "CWE-79",
        severity: "high",
        vulnerability_class: "xss",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "Unsanitized data written directly to HttpServletResponse output stream. This can lead to Reflected XSS.",
        matched_text: line.trim(),
        code_lines: mkCodeLines(lines, i, 2),
        source: "sast",
      });
    }
  }
  return out;
};

/* ── Rule 16: Java — Command Injection via ProcessBuilder / Runtime.exec ─── */
const ruleJavaCommandInjection: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const execRe = /(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (execRe.test(line) && /\+\s*\w+/.test(line)) {
      out.push({
        rule_id: "java.lang.security.audit.command-injection.process-builder",
        cwe: "CWE-78",
        severity: "critical",
        vulnerability_class: "other",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "OS Command execution with concatenated input parameters in Java. Use fixed command arrays without shell execution.",
        matched_text: line.trim(),
        code_lines: mkCodeLines(lines, i, 2),
        source: "sast",
      });
    }
  }
  return out;
};

/* ── Rule 17: Java — Spring Security CSRF Disabled ───────────────────────── */
const ruleJavaCsrfDisabled: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const csrfDisableRe = /\.csrf\(\)\.disable\(\)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (csrfDisableRe.test(line)) {
      out.push({
        rule_id: "java.spring.security.audit.csrf.spring-csrf-disabled",
        cwe: "CWE-352",
        severity: "medium",
        vulnerability_class: "csrf",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "Spring Security CSRF protection is explicitly disabled. Ensure state-changing endpoints use alternative token validation or SameSite cookies.",
        matched_text: line.trim(),
        code_lines: mkCodeLines(lines, i, 2),
        source: "sast",
      });
    }
  }
  return out;
};

/* ── Rule 7: CSRF — Express POST route with no CSRF check ────────────────── */
const ruleCsrf: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const postRoute = /(?:router|app)\.(post|put|patch|delete)\s*\(/;
  const csrfCheck = /csrfToken|csrf\(|csurf|req\.csrfToken|x-csrf/i;
  let hasCsrfMiddleware = lines.some((l) => csrfCheck.test(l));
  if (hasCsrfMiddleware) return out; // file already uses CSRF protection
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!postRoute.test(line)) continue;
    out.push({
      rule_id: "javascript.express.security.audit.csrf.csrf-not-enabled",
      cwe: "CWE-352",
      severity: "medium",
      vulnerability_class: "csrf",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "State-mutating route (POST/PUT/PATCH/DELETE) found with no CSRF protection. Add the csurf middleware or use SameSite cookies.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 8: Insecure session configuration ──────────────────────────────── */
const ruleInsecureSession: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const sessionCall = /(?:app|router)\.use\s*\(\s*session\s*\(|express-session/;
  for (let i = 0; i < lines.length; i++) {
    if (!sessionCall.test(lines[i]!)) continue;
    // Grab the session config block (next 20 lines)
    const block = lines.slice(i, Math.min(i + 20, lines.length)).join("\n");

    if (!/secure\s*:\s*true/.test(block)) {
      out.push({
        rule_id: "javascript.express.security.audit.session.session-no-secure.session-no-secure",
        cwe: "CWE-614",
        severity: "high",
        vulnerability_class: "other",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "express-session configured without `secure: true`. Session cookies will be sent over HTTP, exposing session IDs to network interception.",
        matched_text: lines[i]!.trim(),
        code_lines: mkCodeLines(lines, i, 3),
        source: "sast",
      });
    }

    if (!/httpOnly\s*:\s*true/.test(block)) {
      out.push({
        rule_id: "javascript.express.security.audit.session.session-no-httponly.session-no-httponly",
        cwe: "CWE-1004",
        severity: "medium",
        vulnerability_class: "other",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "express-session configured without `httpOnly: true`. Session cookies are accessible to JavaScript, enabling XSS-based session theft.",
        matched_text: lines[i]!.trim(),
        code_lines: mkCodeLines(lines, i, 3),
        source: "sast",
      });
    }

    // Weak/hardcoded secret
    if (/secret\s*:\s*['"`][^'"`]{1,20}['"`]/.test(block)) {
      out.push({
        rule_id: "javascript.express.security.audit.session.session-hardcoded-secret.session-hardcoded-secret",
        cwe: "CWE-331",
        severity: "high",
        vulnerability_class: "other",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "express-session uses a short hardcoded secret. Session tokens can be forged offline. Use a cryptographically random, environment-variable-backed secret.",
        matched_text: lines[i]!.trim(),
        code_lines: mkCodeLines(lines, i, 3),
        source: "sast",
      });
    }

    // MemoryStore (default — leaks in production)
    if (!/store\s*:/.test(block)) {
      out.push({
        rule_id: "javascript.express.security.audit.session.session-memory-store.session-memory-store",
        cwe: "CWE-400",
        severity: "medium",
        vulnerability_class: "other",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "express-session uses the default MemoryStore which leaks memory and does not persist across restarts. Use connect-mongo or connect-redis in production.",
        matched_text: lines[i]!.trim(),
        code_lines: mkCodeLines(lines, i, 3),
        source: "sast",
      });
    }
    break; // one session block per file
  }
  return out;
};

/* ── Rule 9: SQL injection — string concatenation in query ───────────────── */
const ruleSqlInjection: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const sqlRe = /(?:query|execute|db\.run|connection\.query)\s*\(\s*[`'"]/;
  const concatRe = /\+\s*(req\.(body|query|params)|\w+)\s*\+|`[^`]*\$\{.*req\./;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!sqlRe.test(line) && !concatRe.test(line)) continue;
    if (sqlRe.test(line) && concatRe.test(line)) {
      out.push({
        rule_id: "javascript.lang.security.audit.sqli.node-sqli-injection",
        cwe: "CWE-89",
        severity: "critical",
        vulnerability_class: "sqli",
        file_path: fp,
        line_start: i + 1,
        line_end: i + 1,
        raw_message:
          "SQL query built by string concatenation/interpolation with user input. Use parameterized queries or a query builder.",
        matched_text: line.trim(),
        code_lines: mkCodeLines(lines, i, 3),
        source: "sast",
      });
    }
  }
  return out;
};

/* ── Rule 10: Insecure deserialization ───────────────────────────────────── */
const ruleDeserialize: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const re = /(?:serialize\.unserialize|node-serialize|unserialize)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!re.test(line)) continue;
    const ctx = win(lines, Math.max(0, i - 3), 7);
    if (!USER_INPUT.test(ctx)) continue;
    out.push({
      rule_id: "javascript.lang.security.audit.unsafe-deserialization.unsafe-deserialization",
      cwe: "CWE-502",
      severity: "critical",
      vulnerability_class: "insecure_deserialization",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "Unsafe deserialization of user-controlled data. node-serialize/unserialize can execute arbitrary code via IIFE in the serialized payload.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 11: Command injection ─────────────────────────────────────────── */
const ruleCommandInjection: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const execRe = /(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!execRe.test(line)) continue;
    const ctx = win(lines, Math.max(0, i - 3), 7);
    if (!USER_INPUT.test(ctx) && !/req\.(session|user)/.test(ctx)) continue;
    out.push({
      rule_id: "javascript.lang.security.audit.child-process-injection.child-process-injection",
      cwe: "CWE-78",
      severity: "critical",
      vulnerability_class: "other",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "Shell command executed with user-controlled input. An attacker can inject shell metacharacters to run arbitrary OS commands.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 12: Path traversal ────────────────────────────────────────────── */
const rulePathTraversal: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const fsRe = /fs\.(readFile|readFileSync|createReadStream|writeFile|appendFile)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!fsRe.test(line)) continue;
    const ctx = win(lines, Math.max(0, i - 3), 7);
    if (!USER_INPUT.test(ctx)) continue;
    if (/path\.join|path\.resolve|normalize/.test(ctx)) continue;
    out.push({
      rule_id: "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal",
      cwe: "CWE-22",
      severity: "high",
      vulnerability_class: "other",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "File system operation with user-controlled path and no path.resolve/normalize guard. An attacker can use '../' sequences to access arbitrary files.",
      matched_text: line.trim(),
      code_lines: mkCodeLines(lines, i, 2),
      source: "sast",
    });
  }
  return out;
};

/* ── Rule 13: Hardcoded credentials ─────────────────────────────────────── */
const ruleHardcodedSecrets: Rule = (lines, fp) => {
  const out: SastFinding[] = [];
  const secretKey =
    /(?:password|passwd|secret|api_key|apikey|token|auth_token)\s*[:=]\s*['"`][^'"`\s]{6,}['"`]/i;
  const envRef = /process\.env\.|require\(['"]dotenv['"]\)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!secretKey.test(line)) continue;
    if (envRef.test(line)) continue; // reading from env is OK
    if (/placeholder|example|your[-_]|<.*>/.test(line)) continue;
    out.push({
      rule_id: "javascript.lang.security.audit.hardcoded-credentials.hardcoded-credentials",
      cwe: "CWE-798",
      severity: "high",
      vulnerability_class: "other",
      file_path: fp,
      line_start: i + 1,
      line_end: i + 1,
      raw_message:
        "Hardcoded credential found. Move secrets to environment variables and rotate the exposed value immediately.",
      matched_text: line.trim().replace(/(['"`])[^'"`]{3}[^'"`]*\1/, "$1***$1"),
      code_lines: mkCodeLines(lines, i, 1),
      source: "sast",
    });
  }
  return out;
};

/* ── Orchestrator ────────────────────────────────────────────────────────── */

const ALL_RULES: Rule[] = [
  ruleNoSqlDirectInput,
  ruleNoSqlWhere,
  ruleXssInnerHtml,
  ruleXssResSend,
  ruleXssEval,
  ruleXssTemplate,
  ruleCsrf,
  ruleInsecureSession,
  ruleSqlInjection,
  ruleDeserialize,
  ruleCommandInjection,
  rulePathTraversal,
  ruleHardcodedSecrets,
  ruleJavaSqlInjection,
  ruleJavaXssWriter,
  ruleJavaCommandInjection,
  ruleJavaCsrfDisabled,
];

/**
 * Extension to language mapping for guard-rail verification.
 */
function getFileLanguage(filePath: string): string {
  const ext = "." + filePath.split(".").pop()?.toLowerCase();
  switch (ext) {
    case ".js":
    case ".jsx":
    case ".ts":
    case ".tsx":
    case ".mjs":
    case ".cjs":
    case ".html":
    case ".htm":
    case ".ejs":
    case ".hbs":
    case ".vue":
      return "javascript";
    case ".java":
    case ".jsp":
      return "java";
    case ".py":
      return "python";
    case ".rb":
      return "ruby";
    case ".php":
      return "php";
    case ".cs":
      return "csharp";
    case ".go":
      return "go";
    default:
      return "unknown";
  }
}

/**
 * Language-mismatch guard rail.
 * Checks if the rule ID's language prefix matches the target file's language.
 */
function isRuleLanguageCompatible(ruleId: string, fileLanguage: string): boolean {
  if (fileLanguage === "unknown") return true;
  const prefix = ruleId.split(".")[0]?.toLowerCase();
  if (!prefix) return true;

  if (prefix === "javascript" || prefix === "js") {
    return fileLanguage === "javascript";
  }
  if (prefix === "java") {
    return fileLanguage === "java";
  }
  if (prefix === "python" || prefix === "py") {
    return fileLanguage === "python";
  }
  if (prefix === "ruby") {
    return fileLanguage === "ruby";
  }
  if (prefix === "php") {
    return fileLanguage === "php";
  }
  if (prefix === "go") {
    return fileLanguage === "go";
  }

  return true;
}

/**
 * Run all SAST rules against a single file.
 * Deduplicates findings at the same line + rule and enforces language guard rails.
 */
export function scanFile(filePath: string, content: string): SastFinding[] {
  const lines = content.split("\n");
  const seen = new Set<string>();
  const findings: SastFinding[] = [];
  const fileLang = getFileLanguage(filePath);

  for (const rule of ALL_RULES) {
    for (const f of rule(lines, filePath)) {
      // Language-mismatch guard rail check
      if (!isRuleLanguageCompatible(f.rule_id, fileLang)) {
        console.warn(`[sast-guardrail] Dropped mismatched finding ${f.rule_id} on ${filePath}`);
        continue;
      }

      const key = `${f.rule_id}:${f.line_start}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }

  return findings;
}

/**
 * Run SAST across all repo files.
 * Returns findings sorted by severity then file path.
 */
export function runSast(
  files: Array<{ path: string; content: string }>,
): SastFinding[] {
  const SEVERITY_ORDER: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  return files
    .flatMap((f) => scanFile(f.path, f.content))
    .sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
        a.file_path.localeCompare(b.file_path),
    );
}

/** NodeGoat ground-truth fixture — used for before/after comparison */
export const NODEGOAT_GROUND_TRUTH = [
  { file: "app/routes/profile.js", cwe: "CWE-943", desc: "NoSQLi via req.body in User.findOne" },
  { file: "app/routes/research.js", cwe: "CWE-943", desc: "NoSQLi via $where string concat" },
  { file: "app/routes/contributions.js", cwe: "CWE-79", desc: "Stored XSS in contribution body" },
  { file: "app/routes/memos.js", cwe: "CWE-79", desc: "Stored XSS in memo content" },
  { file: "app/server.js", cwe: "CWE-614", desc: "Insecure session: no secure flag, weak secret" },
] as const;
