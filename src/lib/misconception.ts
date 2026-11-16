/**
 * src/lib/misconception.ts
 * Pure, testable recurrence detection for recurring misconceptions.
 */
import { supabase } from "@/lib/supabase";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QuizAttempt {
  id: string;
  vuln_class: string;
  tier: string;
  question_id: string;
  misconception_id: string | null;
  correct: boolean;
  answered_at: string;
}

export interface RecurringMisconception {
  misconceptionId: string;
  misconceptionLabel: string;
  vulnClass: string;
  supportingAttemptIds: string[]; // IDs of education_checks rows that triggered it
  occurrences: number;            // how many of last 4 triggered it
}

// ---------------------------------------------------------------------------
// Misconception labels (extracted from quiz data)
// ---------------------------------------------------------------------------

export const MISCONCEPTION_LABELS: Record<string, string> = {
  sqli_encrypt: "Believes encoding/encrypting input prevents SQL injection",
  sqli_strip_chars: "Believes stripping special characters reliably prevents SQL injection",
  sqli_readonly_tx: "Confuses read-only transactions with parameterization",
  sqli_string_concat: "Uses string concatenation thinking it is safe",
  sqli_escape_sufficient: "Believes escaping is as safe as parameterization",
  sqli_sanitize_first: "Believes sanitising before interpolation is sufficient",
  sqli_limited_scope: "Underestimates the blast radius of SQL injection",
  sqli_readonly_safe: "Believes read-only DB access limits SQL injection risk",
  sqli_schema_required: "Believes schema knowledge is required for SQL injection",
  sqli_orm_always_vuln: "Believes all ORM usage is automatically vulnerable",
  sqli_type_safe_lang: "Confuses language type safety with SQL injection protection",
  sqli_two_payloads: "Confuses second-order with repeated injection in one request",
  sqli_blocked_first: "Confuses a blocked injection with the second-order pattern",
  sqli_stored_proc_only: "Narrows second-order SQL injection to stored procedures only",
  sqli_params_unreliable: "Underestimates the reliability of parameterized queries",
  sqli_blacklist_sufficient: "Believes input blacklisting reliably prevents SQL injection",
  sqli_stored_proc_safe: "Underestimates stored procedures as a defense",
  sqli_orm_safe_always: "Underestimates ORM parameterization as a defense",
  sqli_precedence_wrong: "Misunderstands SQL operator precedence (AND vs OR)",
  sqli_syntax_breaks: "Believes malformed-looking payloads always break query syntax",
  sqli_only_empty_cat: "Only considers the left side of the OR condition",
  sqli_orderby_safe: "Believes ORDER BY clauses cannot be exploited for injection",
  sqli_auth_protects: "Believes authentication prevents SQL injection",
  sqli_mysql_only: "Believes SQL injection risk depends on the database vendor",
  sqli_regex_orderby: "Relies on regex filtering to sanitise dynamic SQL fragments",
  sqli_quoted_orderby: "Believes quoting a column name makes it safe",
  sqli_urlencode_sql: "Applies URL encoding as a SQL injection defense",
  xss_regex_filter: "Believes regex filtering reliably prevents XSS",
  xss_strip_script: "Believes removing <script> tags is sufficient XSS protection",
  xss_base64_safe: "Believes base64 encoding sanitises malicious content for display",
  xss_jsx_interp_unsafe: "Believes JSX interpolation is unsafe for text content",
  xss_controlled_input_unsafe: "Confuses a controlled input with XSS risk",
  xss_img_src_safe: "Underestimates javascript: URI risk in src attributes",
  xss_cookies_only: "Underestimates XSS impact beyond cookie theft",
  xss_httponly_stops_all: "Believes HttpOnly cookies eliminate XSS risk",
  xss_payment_only: "Underestimates XSS scope beyond high-value targets",
  xss_csp_complete: "Believes CSP alone fully prevents XSS",
  xss_nonce_bypasses_csp: "Believes nonces weaken CSP security",
  xss_csp_images_only: "Misunderstands what CSP's default-src directive covers",
  xss_dom_requires_auth: "Confuses authentication requirements of XSS variants",
  xss_dom_is_stored: "Confuses DOM-based XSS with stored XSS",
  xss_reflected_get_only: "Narrows reflected XSS to GET parameters only",
  xss_encode_at_storage: "Believes encoding at storage time is the right XSS defense",
  xss_encode_once_safe: "Believes one-time encoding at any point is sufficient",
  xss_react_specific: "Believes encoding risk is framework-dependent",
  xss_react_sanitizes_href: "Believes React sanitizes href attributes",
  xss_fragment_xss: "Narrows href XSS to fragment-based attacks",
  xss_url_length: "Believes URL length determines XSS risk",
  xss_dompurify_complete: "Believes DOMPurify is a complete XSS solution in all contexts",
  xss_base64_bypasses_purify: "Believes encoding bypasses client-side sanitisation",
  xss_unicode_bypass: "Believes unicode escaping bypasses DOMPurify",
  xss_html_encode_in_js: "Applies HTML encoding when JavaScript encoding is needed",
  xss_url_encode_in_js: "Applies URL encoding in a JavaScript string context",
  xss_quotes_safe: "Believes quote choice eliminates JS injection risk",
  csrf_is_xss: "Confuses CSRF with Cross-Site Scripting (XSS)",
  csrf_is_mitm: "Confuses CSRF with man-in-the-middle attacks",
  csrf_is_dos: "Confuses CSRF with denial-of-service attacks",
  csrf_get_only: "Believes CSRF only targets GET requests",
  csrf_delete_only: "Narrows CSRF risk to DELETE requests only",
  csrf_post_requires_interaction: "Believes POST requests require explicit user interaction",
  csrf_token_client_only: "Adds CSRF tokens to forms but does not verify them server-side",
  csrf_hidden_field_safe: "Believes hidden fields are inaccessible to cross-origin pages",
  csrf_token_per_request: "Confuses per-session tokens with per-request token rotation requirements",
  csrf_samesite_mobile: "Believes SameSite is unsupported on mobile browsers",
  csrf_token_encrypted: "Confuses CSRF token unpredictability with encryption",
  csrf_samesite_http2: "Believes SameSite requires HTTP/2",
  csrf_json_immune: "Believes JSON Content-Type alone prevents CSRF",
  csrf_rest_immune: "Believes REST APIs are inherently CSRF-immune",
  csrf_rest_get_only: "Narrows REST API CSRF risk to GET-based state changes",
  csrf_referer_reliable: "Believes the Referer header is a reliable CSRF defence",
  csrf_https_referer: "Believes HTTPS guarantees a reliable Referer header",
  csrf_referer_http_only: "Narrows Referer unreliability to HTTP-only contexts",
  csrf_strict_complete: "Believes SameSite=Strict is a complete CSRF defence in all scenarios",
  csrf_redirect_unauth_only: "Underestimates open redirect risk for authenticated sessions",
  csrf_redirect_same_domain: "Restricts redirect exploitation to same-domain targets",
  csrf_httponly_stops_xss_read: "Believes HttpOnly prevents all XSS-based CSRF bypass",
  csrf_double_submit_unbreakable: "Believes the double-submit cookie pattern is unbreakable",
  csrf_xss_subdomain_only: "Restricts XSS-based CSRF bypass to same-subdomain XSS",
  csrf_lax_referer: "Relies on Referer header as a primary CSRF control",
  csrf_https_rate_limit: "Confuses rate limiting with CSRF protection",
  csrf_token_in_url: "Stores CSRF tokens in URLs where they appear in Referer and logs",
  deser_json_faster: "Chooses JSON.parse over eval for performance, not security reasons",
  deser_json_validates: "Confuses JSON parsing with input type validation",
  deser_eval_no_nested: "Believes eval() has structural limitations rather than security issues",
  deser_pickle_slow: "Chooses alternatives to pickle for performance, not security reasons",
  deser_pickle_deprecated: "Believes pickle is deprecated; misidentifies the actual risk",
  deser_pickle_size: "Focuses on payload size rather than security risk",
  deser_limited_to_java_python: "Believes deserialization risk is limited to Python and Java",
  deser_reflection_required: "Believes deserialization risk requires language-level reflection",
  deser_requires_admin: "Believes insecure deserialization requires elevated process privileges",
  deser_trusted_source: "Assumes data from internal/trusted sources is safe to deserialize directly",
  deser_hmac_sufficient: "Believes HMAC signing fully prevents deserialization attacks",
  deser_pickle_python2: "Believes pickle deserialization is only dangerous in Python 2",
  deser_gadget_post_exploit: "Confuses gadget chains with post-exploitation API abuse",
  deser_gadget_debug: "Confuses gadget chains with debug utilities",
  deser_gadget_hardware: "Confuses software gadget chains with hardware attack tools",
  deser_validate_after: "Believes validating after deserialization is sufficient",
  deser_type_check_sufficient: "Believes type checking after deserialization prevents the exploit",
  deser_validation_stops_gadgets: "Believes post-deserialization validation can interrupt gadget chain execution",
  deser_signature_sufficient: "Believes payload signing fully prevents deserialization attacks",
  deser_hmac_unbreakable: "Overestimates HMAC's ability to protect against deserialization attacks",
  deser_pickle_ignores_hmac: "Misunderstands the relationship between HMAC checking and deserialization",
  deser_catch_exceptions: "Believes exception handling prevents deserialization gadget exploits",
  deser_encrypt_stream: "Believes encrypting the serialized stream prevents gadget chain attacks",
  deser_security_manager: "Relies on SecurityManager which is deprecated and was bypassable",
  deser_json_executes: "Believes JSON.parse() can execute embedded function expressions",
  deser_require_auto_exec: "Believes require() calls execute automatically without being invoked",
  deser_buffer_overflow: "Confuses a logic-level deserialization flaw with a memory corruption bug",
};

// ---------------------------------------------------------------------------
// Pure detection logic (no DB calls — fully testable in isolation)
// ---------------------------------------------------------------------------

/**
 * Detects recurring misconceptions from a list of quiz attempts.
 *
 * Recurrence rule: sort attempts by answered_at descending, take the last 4.
 * If the same misconception_id appears in ≥3 of those 4, flag it.
 * Requires exactly 4 attempts (fewer than 4 → never flag; not enough data).
 * Ties: if two misconceptions both reach ≥3, both are flagged.
 *
 * @param attempts - All quiz attempts to consider (pre-filtered by vuln_class if needed).
 * @param misconceptionLabels - Map from misconceptionId → human-readable label.
 */
export function findRecurringMisconceptions(
  attempts: QuizAttempt[],
  misconceptionLabels: Record<string, string>,
): RecurringMisconception[] {
  if (attempts.length < 4) {
    return [];
  }

  // Sort descending by answered_at, take the 4 most recent.
  const sorted = [...attempts].sort(
    (a, b) => new Date(b.answered_at).getTime() - new Date(a.answered_at).getTime(),
  );
  const last4 = sorted.slice(0, 4);

  // Count occurrences of each non-null misconception_id in the window.
  const counts = new Map<string, string[]>(); // misconceptionId → attempt IDs
  for (const attempt of last4) {
    if (attempt.misconception_id !== null) {
      const existing = counts.get(attempt.misconception_id) ?? [];
      existing.push(attempt.id);
      counts.set(attempt.misconception_id, existing);
    }
  }

  const results: RecurringMisconception[] = [];
  for (const [misconceptionId, attemptIds] of counts.entries()) {
    if (attemptIds.length >= 3) {
      // Determine vulnClass from the first supporting attempt
      const supporting = last4.filter((a) => a.misconception_id === misconceptionId);
      const vulnClass = supporting[0]?.vuln_class ?? "";

      results.push({
        misconceptionId,
        misconceptionLabel:
          misconceptionLabels[misconceptionId] ?? misconceptionId,
        vulnClass,
        supportingAttemptIds: attemptIds,
        occurrences: attemptIds.length,
      });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// DB-backed helpers
// ---------------------------------------------------------------------------

/**
 * Fetches the last 4 education_checks for user+vulnClass, runs
 * findRecurringMisconceptions, writes any new flags to the
 * recurring_misconceptions table, and returns the detected list.
 */
export async function detectAndSaveRecurringMisconceptions(
  userId: string,
  vulnClass: string,
): Promise<RecurringMisconception[]> {
  // Fetch last 4 attempts for this user + vuln class.
  const { data: rows, error } = await supabase
    .from("education_checks")
    .select("id, vuln_class, tier, question_id, misconception_id, correct, answered_at")
    .eq("user_id", userId)
    .eq("vuln_class", vulnClass)
    .order("answered_at", { ascending: false })
    .limit(4);

  if (error || !rows) {
    console.error("detectAndSaveRecurringMisconceptions: fetch error", error);
    return [];
  }

  const attempts: QuizAttempt[] = rows.map((r) => ({
    id: r.id as string,
    vuln_class: r.vuln_class as string,
    tier: r.tier as string,
    question_id: r.question_id as string,
    misconception_id: r.misconception_id as string | null,
    correct: r.correct as boolean,
    answered_at: r.answered_at as string,
  }));

  const detected = findRecurringMisconceptions(attempts, MISCONCEPTION_LABELS);

  // Persist any newly detected misconceptions (upsert by user_id + misconception_id).
  for (const item of detected) {
    const { error: upsertError } = await supabase
      .from("recurring_misconceptions")
      .upsert(
        {
          user_id: userId,
          vuln_class: item.vulnClass,
          misconception_id: item.misconceptionId,
          misconception_label: item.misconceptionLabel,
          supporting_attempt_ids: item.supportingAttemptIds,
          occurrences: item.occurrences,
          flagged_at: new Date().toISOString(),
          resolved_at: null,
        },
        { onConflict: "user_id,misconception_id" },
      );

    if (upsertError) {
      console.error("detectAndSaveRecurringMisconceptions: upsert error", upsertError);
    }
  }

  return detected;
}

/**
 * Fetch existing, unresolved recurring misconceptions for a user (for
 * dashboard display). Returns rows where resolved_at IS NULL.
 */
export async function getRecurringMisconceptions(
  userId: string,
): Promise<
  Array<{
    id: string;
    vuln_class: string;
    misconception_id: string;
    misconception_label: string;
    supporting_attempt_ids: string[];
    flagged_at: string;
  }>
> {
  const { data, error } = await supabase
    .from("recurring_misconceptions")
    .select(
      "id, vuln_class, misconception_id, misconception_label, supporting_attempt_ids, flagged_at",
    )
    .eq("user_id", userId)
    .is("resolved_at", null)
    .order("flagged_at", { ascending: false });

  if (error || !data) {
    console.error("getRecurringMisconceptions: fetch error", error);
    return [];
  }

  return data as Array<{
    id: string;
    vuln_class: string;
    misconception_id: string;
    misconception_label: string;
    supporting_attempt_ids: string[];
    flagged_at: string;
  }>;
}
