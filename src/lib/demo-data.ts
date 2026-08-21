/*
 * SecureLoop demo / seed data ("Try a sample repo" fixture mode).
 * Mirrors the Mongoose models from the spec so swapping in Lovable Cloud
 * persistence later is a data-source change, not a UI rewrite.
 */

export type Severity = "critical" | "high" | "medium" | "low";
export type VulnClass = "sqli" | "xss" | "csrf" | "insecure_deserialization";
export type FindingStatus =
  | "open"
  | "explained"
  | "patched"
  | "validated"
  | "accepted"
  | "rejected";

export interface Project {
  id: string;
  name: string;
  sourceType: "git" | "zip";
  repoUrl?: string;
  defaultBranch: string;
  lastScanStatus: "done" | "failed" | "running";
  lastScanAt: string;
  findingsCount: number;
  score: number;
  sample?: boolean;
}

export interface CodeLine {
  n: number;
  code: string;
  vuln?: boolean;
}

export interface DiffLine {
  type: "add" | "del" | "ctx" | "hunk";
  code: string;
}

export interface Explanation {
  whatItIs: string;
  whyItHappened: string;
  owaspCategory: string;
  howFixWorks: string;
  model: string;
}

export interface Validation {
  vulnerabilityGone: boolean;
  testsPassed: boolean | null; // null = no test suite detected
  newIssuesFound: number;
  verdict: "accepted" | "rejected";
  failedCheck?: string;
  logs: string[];
  validatedAt: string;
}

export interface Quiz {
  question: string;
  options: string[];
  correctIndex: number;
}

export interface Finding {
  id: string;
  projectId: string;
  tool: "semgrep" | "zap";
  ruleId: string;
  cwe: string;
  severity: Severity;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  vulnerabilityClass: VulnClass;
  rawMessage: string;
  status: FindingStatus;
  code: CodeLine[];
  explanation: Explanation;
  diff: DiffLine[];
  validation: Validation | null;
  quiz: Quiz;
}

export const projects: Project[] = [
  {
    id: "vulnshop",
    name: "vulnshop-api",
    sourceType: "git",
    repoUrl: "github.com/you/vulnshop-api",
    defaultBranch: "main",
    lastScanStatus: "done",
    lastScanAt: "12 min ago",
    findingsCount: 6,
    score: 72,
    sample: true,
  },
  {
    id: "crm",
    name: "legacy-crm-portal",
    sourceType: "git",
    repoUrl: "github.com/you/legacy-crm-portal",
    defaultBranch: "main",
    lastScanStatus: "done",
    lastScanAt: "2 days ago",
    findingsCount: 14,
    score: 58,
  },
  {
    id: "checkout",
    name: "checkout-service",
    sourceType: "zip",
    defaultBranch: "main",
    lastScanStatus: "done",
    lastScanAt: "6 days ago",
    findingsCount: 2,
    score: 91,
  },
];

const sqliExplanation: Explanation = {
  whatItIs:
    "User-supplied input from req.query.id is concatenated directly into a SQL string. An attacker can pass a crafted id like ' OR '1'='1 to read, modify, or delete arbitrary rows.",
  whyItHappened:
    "The query is built with template-literal interpolation instead of bound parameters, so the database cannot distinguish data from SQL syntax.",
  owaspCategory: "A03:2021 — Injection",
  howFixWorks:
    "The patch switches to a parameterized query ($1 placeholder). The driver sends the value separately from the query text, so input can never be parsed as SQL.",
  model: "google/gemini-3.7-flash",
};

export const findings: Finding[] = [
  {
    id: "f1",
    projectId: "vulnshop",
    tool: "semgrep",
    ruleId: "javascript.express.sql-injection",
    cwe: "CWE-89",
    severity: "critical",
    filePath: "routes/users.js",
    lineStart: 42,
    lineEnd: 44,
    vulnerabilityClass: "sqli",
    rawMessage: "User-controlled data flows into a raw SQL query string.",
    status: "validated",
    code: [
      { n: 39, code: "router.get('/user', async (req, res) => {" },
      { n: 40, code: "  const { id } = req.query;" },
      { n: 41, code: "" },
      {
        n: 42,
        code: "  const q = `SELECT * FROM users WHERE id = '${id}'`;",
        vuln: true,
      },
      { n: 43, code: "  const result = await db.query(q);", vuln: true },
      { n: 44, code: "  res.json(result.rows[0]);", vuln: true },
      { n: 45, code: "});" },
    ],
    explanation: sqliExplanation,
    diff: [
      { type: "hunk", code: "@@ routes/users.js @@" },
      { type: "ctx", code: "  const { id } = req.query;" },
      {
        type: "del",
        code: "- const q = `SELECT * FROM users WHERE id = '${id}'`;",
      },
      { type: "del", code: "- const result = await db.query(q);" },
      {
        type: "add",
        code: "+ const q = 'SELECT * FROM users WHERE id = $1';",
      },
      { type: "add", code: "+ const result = await db.query(q, [id]);" },
      { type: "ctx", code: "  res.json(result.rows[0]);" },
    ],
    validation: {
      vulnerabilityGone: true,
      testsPassed: true,
      newIssuesFound: 0,
      verdict: "accepted",
      logs: [
        "$ secureloop validate patch-8f2c1",
        "▸ cloning @ 3fa9c21 into ephemeral workspace… done",
        "▸ applying diff… clean apply",
        "▸ semgrep --rule javascript.express.sql-injection routes/users.js",
        "  ✓ original rule no longer fires",
        "▸ semgrep (full pack) on changed files",
        "  ✓ 0 new findings introduced",
        "▸ npm test (41 tests)",
        "  ✓ 41 passed, 0 failed",
        "verdict: ACCEPTED — vulnerability removed, tests green, no new issues",
      ],
      validatedAt: "2026-08-21T06:41:00Z",
    },
    quiz: {
      question:
        "Why do parameterized queries prevent SQL injection, while escaping often fails?",
      options: [
        "They encrypt the input before it reaches the database",
        "The query structure is parsed before user data is bound, so input can never become SQL syntax",
        "They strip all quotes from user input automatically",
        "They run the query in a read-only transaction",
      ],
      correctIndex: 1,
    },
  },
  {
    id: "f2",
    projectId: "vulnshop",
    tool: "semgrep",
    ruleId: "javascript.react.dangerously-set-inner-html",
    cwe: "CWE-79",
    severity: "high",
    filePath: "web/components/ProfileBio.tsx",
    lineStart: 17,
    lineEnd: 17,
    vulnerabilityClass: "xss",
    rawMessage:
      "Unescaped user input rendered via dangerouslySetInnerHTML enables stored XSS.",
    status: "validated",
    code: [
      { n: 14, code: "export function ProfileBio({ bio }: { bio: string }) {" },
      { n: 15, code: "  return (" },
      { n: 16, code: "    <div className=\"bio\">" },
      {
        n: 17,
        code: "      <div dangerouslySetInnerHTML={{ __html: bio }} />",
        vuln: true,
      },
      { n: 18, code: "    </div>" },
      { n: 19, code: "  );" },
      { n: 20, code: "}" },
    ],
    explanation: {
      whatItIs:
        "A stored bio field is injected into the DOM as raw HTML. A bio containing <script> or an onerror handler executes in every visitor's browser.",
      whyItHappened:
        "dangerouslySetInnerHTML bypasses React's automatic output escaping, and the bio is never sanitized server- or client-side.",
      owaspCategory: "A03:2021 — Injection (XSS)",
      howFixWorks:
        "The patch sanitizes the bio with a strict allow-list (DOMPurify) before rendering, stripping scriptable markup while preserving safe formatting.",
      model: "google/gemini-3.7-flash",
    },
    diff: [
      { type: "hunk", code: "@@ web/components/ProfileBio.tsx @@" },
      { type: "add", code: "+ import DOMPurify from 'dompurify';" },
      { type: "ctx", code: "  return (" },
      {
        type: "del",
        code: "-     <div dangerouslySetInnerHTML={{ __html: bio }} />",
      },
      {
        type: "add",
        code: "+     <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />",
      },
      { type: "ctx", code: "  );" },
    ],
    validation: {
      vulnerabilityGone: true,
      testsPassed: true,
      newIssuesFound: 0,
      verdict: "accepted",
      logs: [
        "$ secureloop validate patch-9a1d4",
        "▸ cloning @ 3fa9c21 into ephemeral workspace… done",
        "▸ applying diff… clean apply",
        "▸ semgrep re-scan on changed files",
        "  ✓ original rule no longer fires · 0 new findings",
        "▸ npm test (41 tests)",
        "  ✓ 41 passed, 0 failed",
        "verdict: ACCEPTED",
      ],
      validatedAt: "2026-08-21T06:44:00Z",
    },
    quiz: {
      question:
        "What is the safest default way to render user text in React?",
      options: [
        "dangerouslySetInnerHTML with a regex filter",
        "Plain JSX interpolation — React escapes output by default",
        "innerHTML after replacing <script> tags",
        "Base64-encoding the text first",
      ],
      correctIndex: 1,
    },
  },
  {
    id: "f3",
    projectId: "vulnshop",
    tool: "zap",
    ruleId: "zap.absence-of-anti-csrf-tokens",
    cwe: "CWE-352",
    severity: "high",
    filePath: "routes/cart.js",
    lineStart: 8,
    lineEnd: 11,
    vulnerabilityClass: "csrf",
    rawMessage:
      "State-changing POST endpoint has no anti-CSRF token verification.",
    status: "rejected",
    code: [
      { n: 6, code: "// no csurf middleware mounted on this router" },
      { n: 7, code: "" },
      { n: 8, code: "router.post('/cart/checkout', async (req, res) => {", vuln: true },
      { n: 9, code: "  await chargeCard(req.user, req.body.cardId);", vuln: true },
      { n: 10, code: "  res.redirect('/order/confirm');", vuln: true },
      { n: 11, code: "});" },
    ],
    explanation: {
      whatItIs:
        "The checkout POST relies only on the session cookie. A malicious site can auto-submit a cross-origin form and trigger a charge with the victim's session.",
      whyItHappened:
        "The router was mounted without the CSRF middleware the rest of the app uses, so no per-session token is required.",
      owaspCategory: "A01:2021 — Broken Access Control",
      howFixWorks:
        "The candidate patch mounts csurf on the router and requires a valid token. Validation rejected it: the existing checkout integration tests post without a token and now fail — the tests must be updated alongside the patch.",
      model: "google/gemini-3.7-flash",
    },
    diff: [
      { type: "hunk", code: "@@ routes/cart.js @@" },
      { type: "add", code: "+ import csrf from 'csurf';" },
      { type: "add", code: "+ const csrfProtection = csrf();" },
      {
        type: "del",
        code: "- router.post('/cart/checkout', async (req, res) => {",
      },
      {
        type: "add",
        code: "+ router.post('/cart/checkout', csrfProtection, async (req, res) => {",
      },
      { type: "ctx", code: "  await chargeCard(req.user, req.body.cardId);" },
    ],
    validation: {
      vulnerabilityGone: true,
      testsPassed: false,
      newIssuesFound: 0,
      verdict: "rejected",
      failedCheck: "tests_passed",
      logs: [
        "$ secureloop validate patch-c77b0",
        "▸ cloning @ 3fa9c21 into ephemeral workspace… done",
        "▸ applying diff… clean apply",
        "▸ semgrep re-scan on changed files",
        "  ✓ original rule no longer fires · 0 new findings",
        "▸ npm test (41 tests)",
        "  ✖ 3 failed — test/checkout.int.js posts without CSRF token",
        "verdict: REJECTED — tests_passed check failed",
      ],
      validatedAt: "2026-08-21T06:47:00Z",
    },
    quiz: {
      question:
        "Why doesn't the SameSite=Lax cookie flag alone fully replace CSRF tokens on every flow?",
      options: [
        "SameSite is ignored by all mobile browsers",
        "Legacy clients, top-level GET navigations, and some subdomain setups still send cookies — a token proves intent, not just origin",
        "CSRF tokens are encrypted, cookies are not",
        "SameSite only works over HTTP/2",
      ],
      correctIndex: 1,
    },
  },
  {
    id: "f4",
    projectId: "vulnshop",
    tool: "semgrep",
    ruleId: "python.lang.security.pickle-loads",
    cwe: "CWE-502",
    severity: "critical",
    filePath: "worker/import_job.py",
    lineStart: 23,
    lineEnd: 23,
    vulnerabilityClass: "insecure_deserialization",
    rawMessage:
      "pickle.loads() on attacker-influenced bytes can execute arbitrary code.",
    status: "explained",
    code: [
      { n: 20, code: "def restore_session(blob: bytes) -> dict:" },
      { n: 21, code: "    # blob arrives from the upload endpoint" },
      { n: 22, code: "" },
      { n: 23, code: "    return pickle.loads(blob)", vuln: true },
      { n: 24, code: "" },
    ],
    explanation: {
      whatItIs:
        "pickle.loads executes embedded opcodes while deserializing. Any attacker who can reach the upload endpoint can run arbitrary Python on the worker.",
      whyItHappened:
        "pickle was chosen for convenience to persist session dicts, but it is a code-execution format, not a data format.",
      owaspCategory: "A08:2021 — Software and Data Integrity Failures",
      howFixWorks:
        "The patch replaces pickle with JSON plus an explicit schema check — JSON carries data only, so deserialization can never execute code.",
      model: "google/gemini-3.7-flash",
    },
    diff: [
      { type: "hunk", code: "@@ worker/import_job.py @@" },
      { type: "del", code: "- import pickle" },
      { type: "add", code: "+ import json" },
      {
        type: "del",
        code: "-     return pickle.loads(blob)",
      },
      {
        type: "add",
        code: "+     data = json.loads(blob.decode('utf-8'))",
      },
      {
        type: "add",
        code: "+     if not isinstance(data, dict) or 'uid' not in data:",
      },
      { type: "add", code: "+         raise ValueError('invalid session payload')" },
      { type: "add", code: "+     return data" },
    ],
    validation: null,
    quiz: {
      question:
        "Why is JSON preferred over pickle for untrusted input in Python?",
      options: [
        "JSON is faster to parse",
        "JSON describes data only — it has no mechanism to construct objects or execute code during parsing",
        "pickle is deprecated since Python 3.10",
        "JSON automatically validates types",
      ],
      correctIndex: 1,
    },
  },
  {
    id: "f5",
    projectId: "vulnshop",
    tool: "semgrep",
    ruleId: "javascript.express.sql-injection",
    cwe: "CWE-89",
    severity: "medium",
    filePath: "routes/search.js",
    lineStart: 12,
    lineEnd: 12,
    vulnerabilityClass: "sqli",
    rawMessage: "Search term concatenated into LIKE clause.",
    status: "accepted",
    code: [
      { n: 10, code: "router.get('/search', async (req, res) => {" },
      { n: 11, code: "  const { q } = req.query;" },
      {
        n: 12,
        code: "  const rows = await db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);",
        vuln: true,
      },
      { n: 13, code: "  res.json(rows);" },
      { n: 14, code: "});" },
    ],
    explanation: {
      ...sqliExplanation,
      whatItIs:
        "The search term is interpolated into a LIKE clause. A crafted term can break out of the pattern and append arbitrary SQL.",
    },
    diff: [
      { type: "hunk", code: "@@ routes/search.js @@" },
      {
        type: "del",
        code: "- const rows = await db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);",
      },
      {
        type: "add",
        code: "+ const rows = await db.query('SELECT * FROM products WHERE name LIKE $1', [`%${q}%`]);",
      },
    ],
    validation: {
      vulnerabilityGone: true,
      testsPassed: true,
      newIssuesFound: 0,
      verdict: "accepted",
      logs: [
        "$ secureloop validate patch-d31e9",
        "▸ re-scan clean · tests 41/41 · 0 new issues",
        "verdict: ACCEPTED",
      ],
      validatedAt: "2026-08-20T18:02:00Z",
    },
    quiz: {
      question:
        "In a parameterized LIKE clause, where does the % wildcard belong?",
      options: [
        "Inside the SQL string around the placeholder",
        "Concatenated into the bound parameter value",
        "Wildcards are not allowed with parameters",
        "In a separate PREPARE statement",
      ],
      correctIndex: 1,
    },
  },
  {
    id: "f6",
    projectId: "vulnshop",
    tool: "zap",
    ruleId: "zap.reflected-xss",
    cwe: "CWE-79",
    severity: "medium",
    filePath: "routes/search.js",
    lineStart: 21,
    lineEnd: 21,
    vulnerabilityClass: "xss",
    rawMessage: "Query parameter reflected into HTML response without encoding.",
    status: "open",
    code: [
      { n: 19, code: "router.get('/search/page', (req, res) => {" },
      { n: 20, code: "  const { q } = req.query;" },
      {
        n: 21,
        code: "  res.send(`<h1>Results for ${q}</h1>`);",
        vuln: true,
      },
      { n: 22, code: "});" },
    ],
    explanation: {
      whatItIs:
        "The search page reflects q into raw HTML. A crafted link executes script in the victim's browser when they open it.",
      whyItHappened:
        "The response is built with string interpolation instead of the template engine, so no output encoding is applied.",
      owaspCategory: "A03:2021 — Injection (XSS)",
      howFixWorks:
        "The pending patch routes rendering through the template engine's escaped output helper.",
      model: "google/gemini-3.7-flash",
    },
    diff: [],
    validation: null,
    quiz: {
      question:
        "Reflected XSS is best prevented by:",
      options: [
        "Validating input length",
        "Context-aware output encoding at render time",
        "HTTPS",
        "Rate limiting the endpoint",
      ],
      correctIndex: 1,
    },
  },
];

export const classLabels: Record<VulnClass, string> = {
  sqli: "SQL Injection",
  xss: "XSS",
  csrf: "CSRF",
  insecure_deserialization: "Insecure Deserialization",
};

export const statusLabels: Record<FindingStatus, string> = {
  open: "open",
  explained: "explained",
  patched: "patched",
  validated: "validated",
  accepted: "accepted",
  rejected: "rejected",
};

export const scoreHistory = [
  { date: "Jul 20", overall: 44, sqli: 30, xss: 40, csrf: 50, deserialization: 55 },
  { date: "Jul 27", overall: 51, sqli: 45, xss: 48, csrf: 55, deserialization: 58 },
  { date: "Aug 03", overall: 58, sqli: 60, xss: 55, csrf: 55, deserialization: 62 },
  { date: "Aug 10", overall: 63, sqli: 70, xss: 62, csrf: 58, deserialization: 65 },
  { date: "Aug 17", overall: 68, sqli: 85, xss: 66, csrf: 60, deserialization: 68 },
  { date: "Aug 21", overall: 72, sqli: 92, xss: 72, csrf: 60, deserialization: 70 },
];

export const scoreByCategory = [
  { key: "sqli", label: "SQL Injection", value: 92, fixed: 3, open: 0 },
  { key: "xss", label: "XSS", value: 72, fixed: 2, open: 1 },
  { key: "csrf", label: "CSRF", value: 60, fixed: 0, open: 1 },
  { key: "deserialization", label: "Insecure Deserialization", value: 70, fixed: 0, open: 1 },
];

export const scanStages = [
  "queued",
  "scanning",
  "explaining",
  "patching",
  "validating",
  "done",
] as const;

export const scanLogScript: { stage: number; line: string; tone?: "ok" | "err" | "warn" | "dim" }[] = [
  { stage: 0, line: "$ secureloop scan github.com/you/vulnshop-api" },
  { stage: 0, line: "job queued · position 1 · est. 90s", tone: "dim" },
  { stage: 1, line: "▸ cloning @ main (3fa9c21) into ephemeral workspace… done" },
  { stage: 1, line: "▸ semgrep: 214 rules · 38 files", tone: "warn" },
  { stage: 1, line: "  ✖ routes/users.js:42      sqli    CWE-89   critical", tone: "err" },
  { stage: 1, line: "  ✖ web/ProfileBio.tsx:17   xss     CWE-79   high", tone: "err" },
  { stage: 1, line: "  ✖ worker/import_job.py:23 deser.  CWE-502  critical", tone: "err" },
  { stage: 1, line: "  ✖ routes/search.js:12     sqli    CWE-89   medium", tone: "err" },
  { stage: 1, line: "▸ zap baseline: no runnable web app detected — skipped", tone: "dim" },
  { stage: 1, line: "scan complete · 6 findings persisted", tone: "ok" },
  { stage: 2, line: "▸ llm: explaining 6 findings (secrets stripped)…", tone: "warn" },
  { stage: 2, line: "  ✓ 6/6 explanations generated", tone: "ok" },
  { stage: 3, line: "▸ llm: generating candidate patches…", tone: "warn" },
  { stage: 3, line: "  ✓ 6/6 unified diffs generated", tone: "ok" },
  { stage: 4, line: "▸ sandbox validation (ephemeral container per patch)", tone: "warn" },
  { stage: 4, line: "  patch-8f2c1  re-scan ✓  tests 41/41 ✓  new issues 0 ✓  → ACCEPTED", tone: "ok" },
  { stage: 4, line: "  patch-9a1d4  re-scan ✓  tests 41/41 ✓  new issues 0 ✓  → ACCEPTED", tone: "ok" },
  { stage: 4, line: "  patch-c77b0  re-scan ✓  tests 38/41 ✖  → REJECTED (tests_passed)", tone: "err" },
  { stage: 4, line: "  patch-d31e9  re-scan ✓  tests 41/41 ✓  new issues 0 ✓  → ACCEPTED", tone: "ok" },
  { stage: 5, line: "done · 4 patches ready for review · 1 failed validation", tone: "ok" },
];
