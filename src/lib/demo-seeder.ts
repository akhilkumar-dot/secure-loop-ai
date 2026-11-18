/**
 * src/lib/demo-seeder.ts
 *
 * Seeds realistic demonstration data for SecureLoop Review 3 walkthrough.
 * Populates:
 *   - OWASP WebGoat audit project
 *   - Scan run with realistic SAST findings
 *   - Gemini explanation and validated patches
 *   - 3-of-4 recurring misconception trigger ("sqli_encrypt")
 *   - Due spaced-repetition reviews (SQLi due now, XSS due in 3 days)
 *   - Security score breakdown
 */

import { supabase } from "@/lib/supabase";

export async function seedDemoData(
  userId: string,
): Promise<{ projectId: string; findingId: string }> {
  // 1. Clean up any existing demo projects for this user to ensure idempotent seed
  const { data: existingProjects } = await supabase
    .from("projects")
    .select("id")
    .eq("owner_id", userId)
    .eq("name", "OWASP WebGoat Audit");

  if (existingProjects && existingProjects.length > 0) {
    for (const p of existingProjects) {
      await supabase.from("projects").delete().eq("id", p.id);
    }
  }

  // 2. Insert Demo Project
  const { data: project, error: pErr } = await supabase
    .from("projects")
    .insert({
      owner_id: userId,
      name: "OWASP WebGoat Audit",
      source_type: "git",
      repo_url: "https://github.com/WebGoat/WebGoat",
      default_branch: "main",
    })
    .select()
    .single();

  if (pErr || !project) {
    throw new Error(`Failed to create demo project: ${pErr?.message}`);
  }

  const projectId = project.id;

  // 3. Insert Scan Run
  const { data: scanRun } = await supabase
    .from("scan_runs")
    .insert({
      project_id: projectId,
      status: "done",
      tools: ["semgrep", "sast-rules"],
      findings_count: 4,
      patch_success_rate: 1.0,
      syntax_pass_rate: 1.0,
      vuln_removal_rate: 1.0,
      acceptance_rate: 0.25,
      time_to_fix_seconds: 4,
    })
    .select()
    .single();

  const scanRunId = scanRun?.id ?? projectId;

  // 4. Insert Findings
  // Finding 1: SQL Injection (Validated patch ready for user decision!)
  const { data: finding1 } = await supabase
    .from("findings")
    .insert({
      project_id: projectId,
      scan_run_id: scanRunId,
      tool: "semgrep",
      rule_id: "javascript.sql.node-sqli-injection",
      cwe: "CWE-89",
      severity: "critical",
      file_path: "src/main/resources/webgoat/contributions.js",
      line_start: 7,
      line_end: 9,
      vulnerability_class: "sqli",
      raw_message:
        "User-controlled data from req.query flows directly into raw SQL statement without parameterization.",
      status: "validated",
      code_lines: [
        { n: 5, code: "router.get('/user', async (req, res) => {", vuln: false },
        { n: 6, code: "  const userId = req.query.userId;", vuln: false },
        {
          n: 7,
          code: "  const query = \"SELECT * FROM users WHERE id = '\" + userId + \"' AND status = 'active'\";",
          vuln: true,
        },
        { n: 8, code: "  const results = await db.query(query);", vuln: true },
        { n: 9, code: "  res.json(results);", vuln: false },
        { n: 10, code: "});", vuln: false },
      ],
    })
    .select()
    .single();

  // Finding 2: XSS (Already accepted)
  await supabase.from("findings").insert({
    project_id: projectId,
    scan_run_id: scanRunId,
    tool: "semgrep",
    rule_id: "javascript.browser.security.innerHTML-assignment.innerHTML-assignment",
    cwe: "CWE-79",
    severity: "high",
    file_path: "src/main/resources/webgoat/search.component.ts",
    line_start: 14,
    line_end: 15,
    vulnerability_class: "xss",
    raw_message: "Unsanitized URL parameter assigned directly to element.innerHTML.",
    status: "accepted",
  });

  // Finding 3: CSRF (Open)
  await supabase.from("findings").insert({
    project_id: projectId,
    scan_run_id: scanRunId,
    tool: "sast-rules",
    rule_id: "java.spring.security.audit.csrf.spring-csrf-disabled",
    cwe: "CWE-352",
    severity: "medium",
    file_path: "src/main/java/org/owasp/webgoat/SecurityConfig.java",
    line_start: 18,
    line_end: 20,
    vulnerability_class: "csrf",
    raw_message: "Spring Security CSRF explicitly disabled via http.csrf().disable().",
    status: "open",
  });

  // Finding 4: Insecure Deserialization (Open)
  await supabase.from("findings").insert({
    project_id: projectId,
    scan_run_id: scanRunId,
    tool: "semgrep",
    rule_id: "javascript.lang.security.audit.unsafe-deserialization.unsafe-deserialization",
    cwe: "CWE-502",
    severity: "critical",
    file_path: "src/main/resources/webgoat/profile.js",
    line_start: 12,
    line_end: 14,
    vulnerability_class: "insecure_deserialization",
    raw_message: "node-serialize unserialize() invoked on untrusted base64 cookie data.",
    status: "open",
  });

  const findingId = finding1?.id;

  // 5. Insert Explanation for Finding 1
  if (findingId) {
    const { data: exp } = await supabase
      .from("explanations")
      .insert({
        finding_id: findingId,
        what_it_is:
          "User-supplied query parameter 'userId' is concatenated directly into SQL text. Attackers can supply \"' OR '1'='1\" to bypass authentication or extract sensitive records.",
        why_it_happened:
          "The query string is dynamically assembled via string concatenation before reaching db.query(), preventing the database parser from separating code from data.",
        owasp_category: "A03:2021 — Injection",
        how_fix_works:
          "The patch replaces direct string concatenation with parameterized placeholders ($1). The database driver binds user input as a literal value.",
        confidence: "high",
        is_applicable: true,
      })
      .select()
      .single();

    // 6. Insert Validated Patch for Finding 1
    await supabase.from("patches").insert({
      finding_id: findingId,
      explanation_id: exp?.id,
      diff: `@@ -7,2 +7,2 @@
-  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
-  const results = await db.query(query);
+  const query = "SELECT * FROM users WHERE id = $1 AND status = 'active'";
+  const results = await db.query(query, [userId]);`,
      validation_diff_applies: true,
      validation_vulnerability_gone: true,
      validation_syntax_ok: true,
      validation_new_issues: 0,
      validation_method: "deterministic",
      validation_verdict: "accepted",
      validation_logs: [
        "▸ Deterministic Sandbox Verification",
        "✓ Unified diff applied cleanly to isolated sandbox copy",
        "✓ AST Syntax check passed (no syntax errors introduced)",
        "✓ Rule javascript.sql.node-sqli-injection re-scanned: 0 findings (REMEDIATED)",
        "✓ 0 new security regressions introduced",
        "ACCEPTED — verified fix safe to merge",
      ],
    });
  }

  // 7. Seed 4 Quiz attempts demonstrating recurring misconception:
  // 3 out of last 4 attempts choose misconception "sqli_encrypt"
  const attemptIds: string[] = [];
  const baseTime = new Date();

  // Attempt 1 (3 days ago - wrong with sqli_encrypt)
  const t1 = new Date(baseTime);
  t1.setDate(t1.getDate() - 3);
  const { data: a1 } = await supabase
    .from("education_checks")
    .insert({
      finding_id: findingId,
      user_id: userId,
      question_id: "sqli_easy_1",
      vuln_class: "sqli",
      tier: "easy",
      question: "Why do parameterized queries prevent SQL injection?",
      options: [
        "They encrypt the input before reaching the database",
        "The query structure is parsed before user data is bound — input can never become SQL syntax",
        "They strip all quotes from user input",
        "They run queries in a read-only transaction",
      ],
      correct_index: 1,
      user_answer: 0,
      correct: false,
      misconception_id: "sqli_encrypt",
      answered_at: t1.toISOString(),
    })
    .select()
    .single();
  if (a1?.id) attemptIds.push(a1.id);

  // Attempt 2 (2 days ago - wrong with sqli_encrypt)
  const t2 = new Date(baseTime);
  t2.setDate(t2.getDate() - 2);
  const { data: a2 } = await supabase
    .from("education_checks")
    .insert({
      finding_id: findingId,
      user_id: userId,
      question_id: "sqli_easy_2",
      vuln_class: "sqli",
      tier: "easy",
      question: "Which of the following is the safest way to build a SQL query with user input?",
      options: [
        "Concatenate the input after escaping single quotes",
        "Use a prepared statement with a placeholder (e.g. WHERE id = ?)",
        "Sanitise the input with a regex before interpolating it",
        "Use string templates inside a stored procedure",
      ],
      correct_index: 1,
      user_answer: 0,
      correct: false,
      misconception_id: "sqli_encrypt",
      answered_at: t2.toISOString(),
    })
    .select()
    .single();
  if (a2?.id) attemptIds.push(a2.id);

  // Attempt 3 (1 day ago - wrong with sqli_encrypt)
  const t3 = new Date(baseTime);
  t3.setDate(t3.getDate() - 1);
  const { data: a3 } = await supabase
    .from("education_checks")
    .insert({
      finding_id: findingId,
      user_id: userId,
      question_id: "sqli_easy_1",
      vuln_class: "sqli",
      tier: "easy",
      question: "Why do parameterized queries prevent SQL injection?",
      options: [
        "They encrypt the input before reaching the database",
        "The query structure is parsed before user data is bound — input can never become SQL syntax",
        "They strip all quotes from user input",
        "They run queries in a read-only transaction",
      ],
      correct_index: 1,
      user_answer: 0,
      correct: false,
      misconception_id: "sqli_encrypt",
      answered_at: t3.toISOString(),
    })
    .select()
    .single();
  if (a3?.id) attemptIds.push(a3.id);

  // Attempt 4 (30 mins ago - correct!)
  const t4 = new Date(baseTime);
  t4.setMinutes(t4.getMinutes() - 30);
  await supabase.from("education_checks").insert({
    finding_id: findingId,
    user_id: userId,
    question_id: "sqli_easy_1",
    vuln_class: "sqli",
    tier: "easy",
    question: "Why do parameterized queries prevent SQL injection?",
    options: [
      "They encrypt the input before reaching the database",
      "The query structure is parsed before user data is bound — input can never become SQL syntax",
      "They strip all quotes from user input",
      "They run queries in a read-only transaction",
    ],
    correct_index: 1,
    user_answer: 1,
    correct: true,
    misconception_id: null,
    answered_at: t4.toISOString(),
  });

  // 8. Insert Recurring Misconception row
  await supabase.from("recurring_misconceptions").upsert(
    {
      user_id: userId,
      vuln_class: "sqli",
      misconception_id: "sqli_encrypt",
      misconception_label: "Believes encoding/encrypting input prevents SQL injection",
      supporting_attempt_ids: attemptIds,
      occurrences: 3,
      flagged_at: new Date().toISOString(),
      resolved_at: null,
    },
    { onConflict: "user_id,misconception_id" },
  );

  // 9. Insert Mastery Profiles & Spaced Repetition Schedule
  // SQLi: Due for review NOW
  await supabase.from("mastery_profiles").upsert(
    {
      user_id: userId,
      vuln_class: "sqli",
      attempts_count: 4,
      correct_count: 1,
      tier_reached: "easy",
      interval_days: 1,
      ease_factor: 2.2,
      last_reviewed_at: t4.toISOString(),
      next_review_at: new Date().toISOString(), // Due now!
    },
    { onConflict: "user_id,vuln_class" },
  );

  // XSS: Next review in 3 days
  const xssNext = new Date();
  xssNext.setDate(xssNext.getDate() + 3);
  await supabase.from("mastery_profiles").upsert(
    {
      user_id: userId,
      vuln_class: "xss",
      attempts_count: 3,
      correct_count: 3,
      tier_reached: "medium",
      interval_days: 3,
      ease_factor: 2.6,
      last_reviewed_at: new Date().toISOString(),
      next_review_at: xssNext.toISOString(),
    },
    { onConflict: "user_id,vuln_class" },
  );

  // CSRF: Next review in 5 days
  const csrfNext = new Date();
  csrfNext.setDate(csrfNext.getDate() + 5);
  await supabase.from("mastery_profiles").upsert(
    {
      user_id: userId,
      vuln_class: "csrf",
      attempts_count: 2,
      correct_count: 2,
      tier_reached: "medium",
      interval_days: 5,
      ease_factor: 2.5,
      last_reviewed_at: new Date().toISOString(),
      next_review_at: csrfNext.toISOString(),
    },
    { onConflict: "user_id,vuln_class" },
  );

  // Deserialization: Due for review
  await supabase.from("mastery_profiles").upsert(
    {
      user_id: userId,
      vuln_class: "insecure_deserialization",
      attempts_count: 1,
      correct_count: 0,
      tier_reached: "easy",
      interval_days: 1,
      ease_factor: 2.35,
      last_reviewed_at: new Date().toISOString(),
      next_review_at: new Date().toISOString(),
    },
    { onConflict: "user_id,vuln_class" },
  );

  // 10. Insert Security Score
  await supabase.from("security_scores").insert({
    project_id: projectId,
    user_id: userId,
    overall: 76,
    sqli: 55,
    xss: 90,
    csrf: 85,
    deserialization: 75,
    other: 100,
    computed_at: new Date().toISOString(),
  });

  return { projectId, findingId: findingId ?? "" };
}
