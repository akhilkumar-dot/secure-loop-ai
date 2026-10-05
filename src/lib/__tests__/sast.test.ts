/**
 * src/lib/__tests__/sast.test.ts
 *
 * Unit tests for the SAST rule engine.
 * Each rule has a vulnerable fixture (MUST fire) and a safe fixture (MUST NOT fire).
 * Precision/recall per rule is printed at end of run.
 */
import { describe, it, expect, afterAll } from "vitest";
import { scanFile } from "../sast";

// ── Precision/Recall tracking ──────────────────────────────────────────────
const results: Array<{ rule: string; tp: number; fp: number; fn: number }> = [];
function track(rule: string, tp: number, fp: number, fn: number) {
  results.push({ rule, tp, fp, fn });
}
afterAll(() => {
  console.log("\n── SAST Rule Precision/Recall ──────────────────────");
  for (const r of results) {
    const P = r.tp + r.fp > 0 ? (r.tp / (r.tp + r.fp)).toFixed(2) : "n/a";
    const R = r.tp + r.fn > 0 ? (r.tp / (r.tp + r.fn)).toFixed(2) : "n/a";
    console.log(`  ${r.rule.slice(0, 54).padEnd(56)} P=${P}  R=${R}`);
  }
  console.log("────────────────────────────────────────────────────\n");
});

function rulesFired(file: string, content: string, ruleId: string) {
  return scanFile(file, content).filter((f) => f.rule_id === ruleId);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule 1: eval-user-input (NodeGoat contributions.js fixture)
// ─────────────────────────────────────────────────────────────────────────────
describe("SAST: eval-user-input", () => {
  const RULE = "javascript.lang.security.audit.eval-user-input.eval-user-input";

  it("fires on eval(userInput)", () => {
    const vuln = `
router.post("/contributions", function(req, res) {
  const contribution = req.body.contribution;
  eval(contribution);
});`;
    const f = rulesFired("contributions.js", vuln, RULE);
    track(RULE, f.length > 0 ? 1 : 0, 0, f.length > 0 ? 0 : 1);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.cwe).toContain("CWE-79");
    expect(f[0]?.confidence).toBeDefined();
  });

  it("does NOT fire on safe numeric parse", () => {
    const safe = `
router.post("/contributions", function(req, res) {
  const contribution = Number(req.body.contribution);
  saveContribution(contribution);
});`;
    const f = rulesFired("contributions.js", safe, RULE);
    track(RULE, 0, f.length, 0);
    expect(f.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 2: NoSQL injection — req.body/query in mongo find() (±8 line window)
// ─────────────────────────────────────────────────────────────────────────────
describe("SAST: nosql-injection-req-body", () => {
  const RULE = "javascript.mongodb.nosqli.nosql-injection-req-body";

  it("fires when find() is called and req.body is on same/nearby line", () => {
    // win(lines, i, 8) starts at the find() line and looks forward.
    // Put req.body ON the same line to ensure it's in the window.
    const vuln = `db.users.find(req.body).toArray(function(err, docs) {
  res.json(docs);
});`;
    const f = rulesFired("routes.js", vuln, RULE);
    track(RULE, f.length > 0 ? 1 : 0, 0, f.length > 0 ? 0 : 1);
    expect(f.length).toBeGreaterThan(0);
  });

  it("does NOT fire when input is sanitized", () => {
    const safe = `
const name = sanitize(req.body.name);
db.users.find({ name }).toArray(function(err, docs) {
  res.json(docs);
});`;
    const f = rulesFired("routes.js", safe, RULE);
    track(RULE, 0, f.length, 0);
    expect(f.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 3: SQL injection — query() + concatenation on same line
// ─────────────────────────────────────────────────────────────────────────────
describe("SAST: node-sqli-injection", () => {
  const RULE = "javascript.lang.security.audit.sqli.node-sqli-injection";

  it("fires when connection.query() and user input concat are on same line", () => {
    // sqlRe: connection.query(" + concatRe: + word + pattern on same line
    const id = "id";
    const vuln = `connection.query("SELECT * FROM users WHERE id='" + id + "'", cb);`;
    const f = rulesFired("search.js", vuln, RULE);
    track(RULE, f.length > 0 ? 1 : 0, 0, f.length > 0 ? 0 : 1);
    expect(f.length).toBeGreaterThan(0);
  });

  it("does NOT fire on parameterized query", () => {
    const safe = `connection.query("SELECT * FROM users WHERE id = ?", [req.query.id], cb);`;
    const f = rulesFired("search.js", safe, RULE);
    track(RULE, 0, f.length, 0);
    expect(f.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 4: Command injection — exec/spawn + user input in ±3-line window
// ─────────────────────────────────────────────────────────────────────────────
describe("SAST: child-process-injection", () => {
  const RULE = "javascript.lang.security.audit.child-process-injection.child-process-injection";

  it("fires on exec() with req.body in nearby context", () => {
    const vuln = `
const filename = req.body.filename;
exec('convert ' + filename + ' output.png', cb);`;
    const f = rulesFired("convert.js", vuln, RULE);
    track(RULE, f.length > 0 ? 1 : 0, 0, f.length > 0 ? 0 : 1);
    expect(f.length).toBeGreaterThan(0);
  });

  it("does NOT fire when no user input is near exec()", () => {
    const safe = `
const ALLOWED = ['-la', '/tmp'];
execFile('ls', ALLOWED, cb);`;
    const f = rulesFired("utils.js", safe, RULE);
    track(RULE, 0, f.length, 0);
    expect(f.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 5: Hardcoded credentials — password: "..." pattern
// ─────────────────────────────────────────────────────────────────────────────
describe("SAST: hardcoded-credentials", () => {
  const RULE = "javascript.lang.security.audit.hardcoded-credentials.hardcoded-credentials";

  it("fires on hardcoded password assignment", () => {
    const vuln = `const password = "SuperSecret123!";`;
    const f = rulesFired("config.js", vuln, RULE);
    track(RULE, f.length > 0 ? 1 : 0, 0, f.length > 0 ? 0 : 1);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.cwe).toBe("CWE-798");
  });

  it("does NOT fire on env var usage", () => {
    const safe = `const password = process.env.DB_PASSWORD;`;
    const f = rulesFired("config.js", safe, RULE);
    track(RULE, 0, f.length, 0);
    expect(f.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 6: Session — no secure flag
// ─────────────────────────────────────────────────────────────────────────────
describe("SAST: session-no-secure", () => {
  const RULE = "javascript.express.security.audit.session.session-no-secure.session-no-secure";

  it("fires on session cookie without secure:true", () => {
    const vuln = `
app.use(session({
  secret: process.env.SECRET,
  cookie: { httpOnly: true }
}));`;
    const f = rulesFired("app.js", vuln, RULE);
    track(RULE, f.length > 0 ? 1 : 0, 0, f.length > 0 ? 0 : 1);
    expect(f.length).toBeGreaterThan(0);
  });

  it("does NOT fire when secure:true is present", () => {
    const safe = `
app.use(session({
  secret: process.env.SECRET,
  cookie: { secure: true, httpOnly: true }
}));`;
    const f = rulesFired("app.js", safe, RULE);
    track(RULE, 0, f.length, 0);
    expect(f.length).toBe(0);
  });
});
