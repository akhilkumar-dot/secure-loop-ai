/**
 * src/lib/quiz-bank.ts
 *
 * Full 36-question tiered quiz bank for SecureLoop.
 * 4 vulnerability classes × 3 difficulty tiers = 36 questions.
 * Every wrong answer maps to a named misconceptionId from misconception.ts.
 *
 * Pass threshold (server-side enforced): 2 out of 3 correct (≥67%) on
 * the last 3 attempts at the current tier unlocks the next tier.
 */

export type VulnClass = "sqli" | "xss" | "csrf" | "insecure_deserialization";
export type Tier = "easy" | "medium" | "hard";

export interface TieredOption {
  text: string;
  /** misconceptionId if this wrong answer is chosen; null for the correct option */
  misconceptionId: string | null;
}

export interface TieredQuestion {
  id: string; // e.g. "sqli_easy_1"
  vulnClass: VulnClass;
  tier: Tier;
  question: string;
  options: TieredOption[]; // exactly 4 options
  correctIndex: number; // 0-based index into options[]
  source: string; // Authoritative source reference (OWASP, MITRE CWE, etc.)
}

// ---------------------------------------------------------------------------
// TIER PROGRESSION
// ---------------------------------------------------------------------------

/**
 * Pass threshold: a user must get ≥ 2 out of their last 3 attempts correct
 * at tier T to unlock tier T+1 for that vulnerability class.
 * easy → medium: 2/3 correct in last 3 easy attempts
 * medium → hard: 2/3 correct in last 3 medium attempts
 */
export const PASS_THRESHOLD = { required: 2, outOf: 3 };

/**
 * Determine which tiers are unlocked for a user based on their attempt history.
 * Returns a set of unlocked tiers for the given vuln class.
 * This is the pure logic used server-side — no Supabase calls here.
 */
export function getUnlockedTiers(attempts: Array<{ tier: Tier; correct: boolean }>): Set<Tier> {
  const unlocked = new Set<Tier>(["easy"]);

  // Check easy → medium
  const easyAttempts = attempts.filter((a) => a.tier === "easy");
  const lastEasy = easyAttempts.slice(-PASS_THRESHOLD.outOf);
  if (
    lastEasy.length >= PASS_THRESHOLD.outOf &&
    lastEasy.filter((a) => a.correct).length >= PASS_THRESHOLD.required
  ) {
    unlocked.add("medium");
  }

  // Check medium → hard (only if medium unlocked)
  if (unlocked.has("medium")) {
    const mediumAttempts = attempts.filter((a) => a.tier === "medium");
    const lastMedium = mediumAttempts.slice(-PASS_THRESHOLD.outOf);
    if (
      lastMedium.length >= PASS_THRESHOLD.outOf &&
      lastMedium.filter((a) => a.correct).length >= PASS_THRESHOLD.required
    ) {
      unlocked.add("hard");
    }
  }

  return unlocked;
}

// ---------------------------------------------------------------------------
// QUIZ BANK (36 questions)
// ---------------------------------------------------------------------------

export const QUIZ_BANK: TieredQuestion[] = [
  // =========================================================================
  // SQL INJECTION — EASY (conceptual foundation)
  // =========================================================================
  {
    id: "sqli_easy_1",
    vulnClass: "sqli",
    tier: "easy",
    question: "Why do parameterized queries prevent SQL injection?",
    options: [
      {
        text: "The query structure is parsed before user data is bound — input can never become SQL syntax",
        misconceptionId: null,
      },
      {
        text: "They encrypt the input before reaching the database",
        misconceptionId: "sqli_encrypt",
      },
      { text: "They strip all quotes from user input", misconceptionId: "sqli_strip_chars" },
      { text: "They run queries in a read-only transaction", misconceptionId: "sqli_readonly_tx" },
    ],
    correctIndex: 0,
    source:
      "OWASP SQL Injection Prevention Cheat Sheet: Query Parameterization (https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "sqli_easy_2",
    vulnClass: "sqli",
    tier: "easy",
    question: "Which of the following is the safest way to build a SQL query with user input?",
    options: [
      {
        text: "Concatenate the input after escaping single quotes",
        misconceptionId: "sqli_escape_sufficient",
      },
      {
        text: "Sanitise the input with a regex before interpolating it",
        misconceptionId: "sqli_sanitize_first",
      },
      {
        text: "Use a prepared statement with a placeholder (e.g. WHERE id = ?)",
        misconceptionId: null,
      },
      {
        text: "Use string templates inside a stored procedure",
        misconceptionId: "sqli_stored_proc_safe",
      },
    ],
    correctIndex: 2,
    source:
      "OWASP SQL Injection Prevention Cheat Sheet: Primary Defenses (https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "sqli_easy_3",
    vulnClass: "sqli",
    tier: "easy",
    question:
      "An attacker submits ' OR '1'='1 as a username. What class of vulnerability does this exploit?",
    options: [
      { text: "Cross-Site Scripting (XSS)", misconceptionId: "sqli_limited_scope" },
      {
        text: "SQL Injection — the payload escapes the string literal and alters the query logic",
        misconceptionId: null,
      },
      {
        text: "CSRF — the browser sends the payload to a third-party server",
        misconceptionId: "sqli_limited_scope",
      },
      {
        text: "Command Injection — the shell interprets the single quotes",
        misconceptionId: "sqli_limited_scope",
      },
    ],
    correctIndex: 1,
    source:
      "MITRE CWE-89: Improper Neutralization of Special Elements used in an SQL Command (https://cwe.mitre.org/data/definitions/89.html)",
  },

  // =========================================================================
  // SQL INJECTION — MEDIUM (exploitation patterns)
  // =========================================================================
  {
    id: "sqli_medium_1",
    vulnClass: "sqli",
    tier: "medium",
    question: "What is 'second-order' SQL injection?",
    options: [
      {
        text: "An attack that sends two malicious payloads in one HTTP request",
        misconceptionId: "sqli_two_payloads",
      },
      {
        text: "A SQL injection that only works through stored procedures",
        misconceptionId: "sqli_stored_proc_only",
      },
      {
        text: "An injection that is blocked by the WAF on first attempt then retried",
        misconceptionId: "sqli_blocked_first",
      },
      {
        text: "A payload stored safely at first but executed as SQL when retrieved later in a different context",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "OWASP Top 10 - A03:2021 Injection & PortSwigger Second-Order SQLi (https://portswigger.net/web-security/sql-injection#what-is-second-order-sql-injection)",
  },
  {
    id: "sqli_medium_2",
    vulnClass: "sqli",
    tier: "medium",
    question:
      "A developer says: 'I validated and parameterized all user inputs — my app is safe from SQL injection.' What is missing from this claim?",
    options: [
      {
        text: "Parameterized queries are not fully reliable across all database drivers",
        misconceptionId: "sqli_params_unreliable",
      },
      {
        text: "The developer should use an ORM instead of raw queries",
        misconceptionId: "sqli_orm_always_vuln",
      },
      {
        text: "Second-order SQL injection from stored or computed values not treated as untrusted",
        misconceptionId: null,
      },
      {
        text: "SQL injection requires knowing the database schema, so validation is usually sufficient",
        misconceptionId: "sqli_schema_required",
      },
    ],
    correctIndex: 2,
    source:
      "OWASP SQL Injection Prevention: Defense in Depth (https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "sqli_medium_3",
    vulnClass: "sqli",
    tier: "medium",
    question:
      "A query is: SELECT * FROM users WHERE role='admin' AND active=1 OR id=<input>. If input = 0 OR 1=1, what happens?",
    options: [
      {
        text: "All rows returned — OR 1=1 evaluates true for every row after the AND clause",
        misconceptionId: null,
      },
      {
        text: "No rows returned — the WHERE clause short-circuits on the AND",
        misconceptionId: "sqli_precedence_wrong",
      },
      {
        text: "A syntax error — the injected payload breaks the query",
        misconceptionId: "sqli_syntax_breaks",
      },
      {
        text: "Only the empty category rows returned — the left side of OR is empty",
        misconceptionId: "sqli_only_empty_cat",
      },
    ],
    correctIndex: 0,
    source: "MITRE CWE-89 & SQL Operator Precedence Standards (ISO/IEC 9075: SQL-92)",
  },

  // =========================================================================
  // SQL INJECTION — HARD (advanced / ORDER BY / ORM edge cases)
  // =========================================================================
  {
    id: "sqli_hard_1",
    vulnClass: "sqli",
    tier: "hard",
    question:
      "A developer builds: SELECT * FROM products ORDER BY <column_name_from_request>. Why can't parameterized queries fix this?",
    options: [
      {
        text: "ORDER BY clauses are not parsed by the SQL engine, so injection is impossible there",
        misconceptionId: "sqli_orderby_safe",
      },
      {
        text: "The risk only exists in MySQL; other databases handle dynamic ORDER BY safely",
        misconceptionId: "sqli_mysql_only",
      },
      {
        text: "Authentication middleware will block unauthenticated requests before they reach ORDER BY",
        misconceptionId: "sqli_auth_protects",
      },
      {
        text: "Parameters bind data values only — identifiers like column names must be validated against an allowlist server-side",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "OWASP SQL Injection Prevention: Dynamic Query Building & Allowlisting (https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "sqli_hard_2",
    vulnClass: "sqli",
    tier: "hard",
    question:
      "An ORM auto-generates: SELECT * FROM users WHERE <raw_filter>. The raw_filter comes from user input. Is the ORM's parameterization protecting this query?",
    options: [
      {
        text: "Yes — ORMs always parameterize query fragments automatically",
        misconceptionId: "sqli_orm_safe_always",
      },
      {
        text: "No — raw/literal query fragments bypass ORM parameterization; only structured query builders or allowlists are safe",
        misconceptionId: null,
      },
      {
        text: "Yes — the ORM uses regex to filter dangerous SQL keywords from raw inputs",
        misconceptionId: "sqli_regex_orderby",
      },
      {
        text: "Yes — quoting the identifier with backticks or double quotes makes it safe",
        misconceptionId: "sqli_quoted_orderby",
      },
    ],
    correctIndex: 1,
    source: "MITRE CWE-89 & PostgreSQL / MySQL Order By Injection Guide",
  },
  {
    id: "sqli_hard_3",
    vulnClass: "sqli",
    tier: "hard",
    question:
      "Which defense is most robust against SQL injection in a column-name dynamic filter scenario?",
    options: [
      {
        text: "Allowlist the column name against a hardcoded set of valid column names before using it",
        misconceptionId: null,
      },
      {
        text: "URL-encode the column name before inserting it into the query",
        misconceptionId: "sqli_urlencode_sql",
      },
      {
        text: "Apply a blacklist regex to remove SQL keywords like SELECT, DROP, OR",
        misconceptionId: "sqli_blacklist_sufficient",
      },
      {
        text: "Wrap the column name in quotes and escape internal quotes with a backslash",
        misconceptionId: "sqli_escape_sufficient",
      },
    ],
    correctIndex: 0,
    source: "OWASP SQL Injection Prevention: Defense-in-Depth and Dynamic Identifiers",
  },

  // =========================================================================
  // XSS — EASY
  // =========================================================================
  {
    id: "xss_easy_1",
    vulnClass: "xss",
    tier: "easy",
    question: "What is the safest default way to render user-supplied text in a React component?",
    options: [
      {
        text: "dangerouslySetInnerHTML with a regex filter that removes <script> tags",
        misconceptionId: "xss_regex_filter",
      },
      { text: "Base64-encode the text before rendering it", misconceptionId: "xss_base64_safe" },
      {
        text: "innerHTML after replacing <script> tags with empty strings",
        misconceptionId: "xss_strip_script",
      },
      {
        text: "Plain JSX interpolation {userText} — React escapes HTML by default",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "OWASP Cross-Site Scripting Prevention Cheat Sheet: Output Encoding (https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "xss_easy_2",
    vulnClass: "xss",
    tier: "easy",
    question:
      "A developer says: 'I used React's controlled inputs — there's no XSS risk.' What is wrong with this reasoning?",
    options: [
      {
        text: "Controlled inputs are still vulnerable because React does not escape event handlers",
        misconceptionId: "xss_controlled_input_unsafe",
      },
      {
        text: "React's JSX interpolation is framework-specific — it is only safe in React, not in Vue or Angular",
        misconceptionId: "xss_react_specific",
      },
      {
        text: "Controlled inputs are safe for text, but dangerouslySetInnerHTML or href={userUrl} can still introduce XSS",
        misconceptionId: null,
      },
      {
        text: "Nothing — controlled inputs completely prevent XSS",
        misconceptionId: "xss_jsx_interp_unsafe",
      },
    ],
    correctIndex: 2,
    source:
      "React Security Documentation: Preventing XSS in JSX (https://react.dev/learn/rendering-lists#why-does-react-need-keys)",
  },
  {
    id: "xss_easy_3",
    vulnClass: "xss",
    tier: "easy",
    question:
      "Which of the following correctly limits XSS impact when it cannot be fully prevented?",
    options: [
      {
        text: "Setting HttpOnly on session cookies — this prevents all script access to the cookie",
        misconceptionId: "xss_httponly_stops_all",
      },
      {
        text: "HttpOnly cookies reduce cookie theft, but XSS can still perform actions, exfiltrate data, or rewrite the DOM",
        misconceptionId: null,
      },
      {
        text: "XSS only matters for payment pages — other pages are low risk",
        misconceptionId: "xss_payment_only",
      },
      {
        text: "XSS only allows stealing cookies — it cannot modify page content",
        misconceptionId: "xss_cookies_only",
      },
    ],
    correctIndex: 1,
    source:
      "OWASP XSS Prevention: Safe URL Attributes & javascript: Pseudo-Protocol (https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
  },

  // =========================================================================
  // XSS — MEDIUM
  // =========================================================================
  {
    id: "xss_medium_1",
    vulnClass: "xss",
    tier: "medium",
    question:
      "A CSP header is set with default-src 'self'; script-src 'nonce-abc'. What does it NOT prevent?",
    options: [
      {
        text: "It prevents everything — CSP is a complete XSS solution",
        misconceptionId: "xss_csp_complete",
      },
      {
        text: "DOM-based XSS that uses trusted inline scripts with the correct nonce, or XSS in nonce-whitelisted scripts",
        misconceptionId: null,
      },
      {
        text: "Adding a nonce makes CSP weaker — attackers can replay the nonce",
        misconceptionId: "xss_nonce_bypasses_csp",
      },
      {
        text: "CSP's default-src only covers image loading, not script execution",
        misconceptionId: "xss_csp_images_only",
      },
    ],
    correctIndex: 1,
    source:
      "OWASP Top 10 - A03:2021 Injection & CWE-79: Cross-Site Scripting (https://cwe.mitre.org/data/definitions/79.html)",
  },
  {
    id: "xss_medium_2",
    vulnClass: "xss",
    tier: "medium",
    question: "What distinguishes DOM-based XSS from reflected XSS?",
    options: [
      {
        text: "DOM-based XSS is executed by client-side JS reading attacker-controlled sources without a server round-trip",
        misconceptionId: null,
      },
      {
        text: "DOM-based XSS requires the user to be authenticated; reflected XSS does not",
        misconceptionId: "xss_dom_requires_auth",
      },
      {
        text: "DOM-based XSS stores the payload in the database; reflected XSS does not",
        misconceptionId: "xss_dom_is_stored",
      },
      {
        text: "Reflected XSS only works via GET parameters; DOM-based works via POST",
        misconceptionId: "xss_reflected_get_only",
      },
    ],
    correctIndex: 0,
    source:
      "MDN Web Docs: Content Security Policy (CSP) (https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)",
  },
  {
    id: "xss_medium_3",
    vulnClass: "xss",
    tier: "medium",
    question: "When should you encode user data for XSS prevention?",
    options: [
      {
        text: "Encode once at storage time — data written to the DB is safe to render later",
        misconceptionId: "xss_encode_at_storage",
      },
      {
        text: "Encoding is React-specific; plain HTML pages do not require encoding",
        misconceptionId: "xss_react_specific",
      },
      {
        text: "Encoding once at any step in the pipeline is sufficient",
        misconceptionId: "xss_encode_once_safe",
      },
      {
        text: "Encode at the point of rendering, context-specifically (HTML, JS, URL contexts differ)",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "OWASP Cheat Sheet: DOM-based XSS Prevention (https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)",
  },

  // =========================================================================
  // XSS — HARD
  // =========================================================================
  {
    id: "xss_hard_1",
    vulnClass: "xss",
    tier: "hard",
    question:
      "React renders: <a href={userInput}>Click</a>. The user submits javascript:alert(1). What happens?",
    options: [
      {
        text: "React sanitizes href attributes — javascript: URIs are blocked automatically",
        misconceptionId: "xss_react_sanitizes_href",
      },
      {
        text: "Only XSS via URL fragments (#...) is possible in href — javascript: requires a full page reload",
        misconceptionId: "xss_fragment_xss",
      },
      {
        text: "The javascript: URI executes when clicked — React does not sanitize href scheme; validate/allowlist the protocol server-side",
        misconceptionId: null,
      },
      {
        text: "Long URLs are truncated by the browser before execution — the payload won't work",
        misconceptionId: "xss_url_length",
      },
    ],
    correctIndex: 2,
    source:
      "OWASP Cross-Site Scripting Prevention: Context-Aware Encoding Rules (https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "xss_hard_2",
    vulnClass: "xss",
    tier: "hard",
    question:
      "A developer adds DOMPurify before innerHTML insertion. What attack vector does this NOT cover?",
    options: [
      {
        text: "DOMPurify is a complete XSS solution — no vectors remain",
        misconceptionId: "xss_dompurify_complete",
      },
      { text: "Unicode-escaped payloads bypass DOMPurify", misconceptionId: "xss_unicode_bypass" },
      {
        text: "Base64-encoded payloads bypass DOMPurify's sanitisation",
        misconceptionId: "xss_base64_bypasses_purify",
      },
      {
        text: "JavaScript string contexts (e.g. element.onclick = userInput) where HTML encoding ≠ JS encoding",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "React Security: Sanitizing dangerouslySetInnerHTML & Href Attributes (https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)",
  },
  {
    id: "xss_hard_3",
    vulnClass: "xss",
    tier: "hard",
    question:
      "Code: element.setAttribute('onclick', userInput). DOMPurify has already sanitised userInput for HTML. Is this safe?",
    options: [
      {
        text: "Yes — DOMPurify sanitisation covers all contexts",
        misconceptionId: "xss_html_encode_in_js",
      },
      {
        text: "No — onclick is a JavaScript context; HTML sanitisation does not prevent JS injection in event attributes",
        misconceptionId: null,
      },
      {
        text: "No — but only if userInput contains single quotes; double quotes are safe in onclick",
        misconceptionId: "xss_quotes_safe",
      },
      {
        text: "Yes — URL-encoding the input before setAttribute prevents injection",
        misconceptionId: "xss_url_encode_in_js",
      },
    ],
    correctIndex: 1,
    source: "DOMPurify Documentation & HTML Sanitizer API (https://github.com/cure53/DOMPurify)",
  },

  // =========================================================================
  // CSRF — EASY
  // =========================================================================
  {
    id: "csrf_easy_1",
    vulnClass: "csrf",
    tier: "easy",
    question: "What is a CSRF attack?",
    options: [
      {
        text: "An attacker tricks a victim's browser into making authenticated requests to a site without the victim's intent",
        misconceptionId: null,
      },
      {
        text: "An attacker injects malicious scripts into a web page viewed by other users",
        misconceptionId: "csrf_is_xss",
      },
      {
        text: "An attacker intercepts and modifies traffic between the browser and server",
        misconceptionId: "csrf_is_mitm",
      },
      {
        text: "An attacker sends a large number of requests to overwhelm the server",
        misconceptionId: "csrf_is_dos",
      },
    ],
    correctIndex: 0,
    source:
      "MITRE CWE-352: Cross-Site Request Forgery (CSRF) (https://cwe.mitre.org/data/definitions/352.html)",
  },
  {
    id: "csrf_easy_2",
    vulnClass: "csrf",
    tier: "easy",
    question: "Which HTTP methods are most commonly exploited in CSRF attacks?",
    options: [
      {
        text: "Only GET requests — POST requests require explicit form submission",
        misconceptionId: "csrf_get_only",
      },
      {
        text: "Only DELETE requests — other methods are protected by browser CORS",
        misconceptionId: "csrf_delete_only",
      },
      {
        text: "State-changing requests (POST, PUT, DELETE, PATCH) — GET should be idempotent",
        misconceptionId: null,
      },
      {
        text: "POST requests require user interaction to send, so they cannot be forged",
        misconceptionId: "csrf_post_requires_interaction",
      },
    ],
    correctIndex: 2,
    source:
      "OWASP Cross-Site Request Forgery Prevention Cheat Sheet: State-Changing GETs (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "csrf_easy_3",
    vulnClass: "csrf",
    tier: "easy",
    question: "A developer adds a CSRF token to every HTML form. What additional step is required?",
    options: [
      {
        text: "Nothing — adding the token to the form is sufficient",
        misconceptionId: "csrf_token_client_only",
      },
      {
        text: "The token must be stored in a hidden input field that is inaccessible to other origins",
        misconceptionId: "csrf_hidden_field_safe",
      },
      {
        text: "The server must verify the token on every state-changing request and reject requests with missing/invalid tokens",
        misconceptionId: null,
      },
      {
        text: "The token must be rotated on every single request (per-request tokens)",
        misconceptionId: "csrf_token_per_request",
      },
    ],
    correctIndex: 2,
    source:
      "OWASP CSRF Prevention Cheat Sheet: Synchronizer Token Pattern (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)",
  },

  // =========================================================================
  // CSRF — MEDIUM
  // =========================================================================
  {
    id: "csrf_medium_1",
    vulnClass: "csrf",
    tier: "medium",
    question: "Why doesn't SameSite=Lax cookie alone fully replace CSRF tokens?",
    options: [
      { text: "SameSite is ignored by mobile browsers", misconceptionId: "csrf_samesite_mobile" },
      {
        text: "SameSite only works over HTTP/2 connections",
        misconceptionId: "csrf_samesite_http2",
      },
      {
        text: "CSRF tokens are encrypted; SameSite cookies are not",
        misconceptionId: "csrf_token_encrypted",
      },
      {
        text: "Legacy clients, top-level GET navigations, and subdomains still send cookies — a synchronizer token proves intent",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "MDN Web Docs: SameSite Cookie Attribute (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)",
  },
  {
    id: "csrf_medium_2",
    vulnClass: "csrf",
    tier: "medium",
    question:
      "A REST API accepts JSON only (Content-Type: application/json). Is it immune to CSRF?",
    options: [
      {
        text: "Yes — JSON Content-Type cannot be sent cross-origin without a CORS preflight that the server rejects",
        misconceptionId: "csrf_json_immune",
      },
      {
        text: "No — fetch() with mode:'no-cors' can send plain-text JSON; the Content-Type check is not a reliable CSRF defence",
        misconceptionId: null,
      },
      {
        text: "Yes — REST APIs are inherently stateless and therefore CSRF-immune",
        misconceptionId: "csrf_rest_immune",
      },
      {
        text: "No — but only if the API uses GET to trigger state changes",
        misconceptionId: "csrf_rest_get_only",
      },
    ],
    correctIndex: 1,
    source:
      "OWASP CSRF Prevention: JSON Endpoints & Custom Request Headers (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)",
  },
  {
    id: "csrf_medium_3",
    vulnClass: "csrf",
    tier: "medium",
    question: "Can a Referer header be used as a sole CSRF defence?",
    options: [
      {
        text: "No — the Referer header can be absent (privacy settings, HTTPS→HTTP redirects) and in some cases can be spoofed",
        misconceptionId: null,
      },
      {
        text: "Yes — the Referer header is set by the browser and cannot be forged by JavaScript",
        misconceptionId: "csrf_referer_reliable",
      },
      {
        text: "Yes — over HTTPS the Referer header is always present and trustworthy",
        misconceptionId: "csrf_https_referer",
      },
      {
        text: "No — but only on HTTP sites; HTTPS sites can rely on Referer safely",
        misconceptionId: "csrf_referer_http_only",
      },
    ],
    correctIndex: 0,
    source:
      "OWASP CSRF Prevention: Referer and Origin Header Validation Limitations (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)",
  },

  // =========================================================================
  // CSRF — HARD
  // =========================================================================
  {
    id: "csrf_hard_1",
    vulnClass: "csrf",
    tier: "hard",
    question:
      "An app uses SameSite=Strict on its session cookie. Under what scenario can CSRF still succeed?",
    options: [
      {
        text: "An open redirect on the same origin can serve as a same-site initiator, bypassing SameSite=Strict for authenticated requests",
        misconceptionId: null,
      },
      {
        text: "SameSite=Strict is a complete CSRF defence — no CSRF is possible",
        misconceptionId: "csrf_strict_complete",
      },
      {
        text: "Attackers can only exploit redirects when the victim is not logged in",
        misconceptionId: "csrf_redirect_unauth_only",
      },
      {
        text: "Open redirects only work if the attacker controls a page on the same domain",
        misconceptionId: "csrf_redirect_same_domain",
      },
    ],
    correctIndex: 0,
    source:
      "RFC 6265bis & OWASP CSRF Prevention: SameSite Cookie Lax/Strict Bypass via Top-Level Navigation",
  },
  {
    id: "csrf_hard_2",
    vulnClass: "csrf",
    tier: "hard",
    question:
      "An XSS vulnerability exists on a subdomain (sub.example.com). The main app (example.com) uses SameSite=Lax and CSRF tokens. What is at risk?",
    options: [
      {
        text: "Nothing — HttpOnly prevents the XSS from reading CSRF tokens",
        misconceptionId: "csrf_httponly_stops_xss_read",
      },
      {
        text: "The XSS on sub.example.com can read the CSRF token from the DOM and forge authenticated requests to example.com",
        misconceptionId: null,
      },
      {
        text: "The double-submit cookie pattern would prevent this — it is unbreakable",
        misconceptionId: "csrf_double_submit_unbreakable",
      },
      {
        text: "XSS-based CSRF bypass only works if both pages are on the exact same subdomain",
        misconceptionId: "csrf_xss_subdomain_only",
      },
    ],
    correctIndex: 1,
    source: "OWASP CSRF Prevention: Double Submit Cookie Pattern & Subdomain Overwrite Risks",
  },
  {
    id: "csrf_hard_3",
    vulnClass: "csrf",
    tier: "hard",
    question: "Which of the following is the most robust combined CSRF defence for a modern SPA?",
    options: [
      {
        text: "SameSite=Lax cookies with Referer header validation as the primary control",
        misconceptionId: "csrf_lax_referer",
      },
      {
        text: "HTTPS with rate limiting — this prevents automated CSRF attacks",
        misconceptionId: "csrf_https_rate_limit",
      },
      {
        text: "SameSite=Strict session cookie + synchronizer CSRF token in a custom request header (not a cookie)",
        misconceptionId: null,
      },
      {
        text: "Store the CSRF token in the URL query string so the server can always read it",
        misconceptionId: "csrf_token_in_url",
      },
    ],
    correctIndex: 2,
    source: "OWASP Cross-Site Request Forgery Prevention Cheat Sheet: Defense in Depth",
  },

  // =========================================================================
  // INSECURE DESERIALIZATION — EASY
  // =========================================================================
  {
    id: "deser_easy_1",
    vulnClass: "insecure_deserialization",
    tier: "easy",
    question: "Why is JSON.parse() preferred over eval() for parsing untrusted data?",
    options: [
      { text: "JSON.parse() is faster than eval()", misconceptionId: "deser_json_faster" },
      {
        text: "eval() cannot handle nested objects correctly",
        misconceptionId: "deser_eval_no_nested",
      },
      {
        text: "JSON.parse() automatically validates that the input matches a schema",
        misconceptionId: "deser_json_validates",
      },
      {
        text: "JSON describes data only — it cannot construct objects or execute code during parsing; eval() can run arbitrary JS",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "OWASP Deserialization Cheat Sheet: Serialization Formats vs Code Execution (https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)",
  },
  {
    id: "deser_easy_2",
    vulnClass: "insecure_deserialization",
    tier: "easy",
    question: "Why is Python's pickle module dangerous for untrusted input?",
    options: [
      {
        text: "pickle is slower than JSON for large payloads",
        misconceptionId: "deser_pickle_slow",
      },
      {
        text: "pickle produces larger payloads than JSON, causing memory issues",
        misconceptionId: "deser_pickle_size",
      },
      {
        text: "pickle is deprecated since Python 3.10",
        misconceptionId: "deser_pickle_deprecated",
      },
      {
        text: "pickle can execute arbitrary Python code during deserialization via __reduce__",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source:
      "Python Official Documentation: pickle module security advisory (https://docs.python.org/3/library/pickle.html)",
  },
  {
    id: "deser_easy_3",
    vulnClass: "insecure_deserialization",
    tier: "easy",
    question:
      "Which languages or platforms are most commonly affected by insecure deserialization?",
    options: [
      {
        text: "Only Python and Java — other languages' serialization formats are safe",
        misconceptionId: "deser_limited_to_java_python",
      },
      {
        text: "Only languages with runtime reflection APIs",
        misconceptionId: "deser_reflection_required",
      },
      {
        text: "Any language with a serialization format that can represent executable logic or complex objects (Java, Python, PHP, Ruby, .NET, Node)",
        misconceptionId: null,
      },
      {
        text: "Only server-side languages running as root/admin processes",
        misconceptionId: "deser_requires_admin",
      },
    ],
    correctIndex: 2,
    source:
      "MITRE CWE-502: Deserialization of Untrusted Data (https://cwe.mitre.org/data/definitions/502.html)",
  },

  // =========================================================================
  // INSECURE DESERIALIZATION — MEDIUM
  // =========================================================================
  {
    id: "deser_medium_1",
    vulnClass: "insecure_deserialization",
    tier: "medium",
    question:
      "A developer says: 'We HMAC-sign the serialized payload — only we can produce valid tokens, so deserialization is safe.' What is the flaw?",
    options: [
      {
        text: "Nothing — HMAC signing fully prevents deserialization attacks",
        misconceptionId: "deser_hmac_sufficient",
      },
      {
        text: "If the HMAC key is compromised, or if the deserializer runs before HMAC verification, an attacker can craft malicious payloads",
        misconceptionId: null,
      },
      {
        text: "pickle ignores HMAC signatures entirely, so signing has no effect on Python pickle",
        misconceptionId: "deser_pickle_ignores_hmac",
      },
      {
        text: "HMAC only protects Python 2 pickle; Python 3 pickle is inherently safer",
        misconceptionId: "deser_pickle_python2",
      },
    ],
    correctIndex: 1,
    source: "OWASP Deserialization Cheat Sheet: HMAC Limitations in Object Deserialization",
  },
  {
    id: "deser_medium_2",
    vulnClass: "insecure_deserialization",
    tier: "medium",
    question: "What is a 'gadget chain' in the context of deserialization attacks?",
    options: [
      {
        text: "A sequence of existing application classes whose methods are chained to achieve code execution during deserialization",
        misconceptionId: null,
      },
      {
        text: "A sequence of API calls an attacker makes after gaining initial access",
        misconceptionId: "deser_gadget_post_exploit",
      },
      {
        text: "A debugging tool used to trace serialization calls",
        misconceptionId: "deser_gadget_debug",
      },
      {
        text: "A hardware-level side-channel attack leveraging CPU branch predictors",
        misconceptionId: "deser_gadget_hardware",
      },
    ],
    correctIndex: 0,
    source:
      "Frohoff & ysoserial: Understanding Java Gadget Chains (https://github.com/frohoff/ysoserial)",
  },
  {
    id: "deser_medium_3",
    vulnClass: "insecure_deserialization",
    tier: "medium",
    question:
      "A developer validates the deserialized object's fields after calling deserialize(). Does this prevent deserialization attacks?",
    options: [
      {
        text: "Yes — validation after deserialization catches all malicious payloads",
        misconceptionId: "deser_validate_after",
      },
      {
        text: "No — gadget chains execute during deserialization before the validation step runs",
        misconceptionId: null,
      },
      {
        text: "Yes — checking the object's type before validation is sufficient",
        misconceptionId: "deser_type_check_sufficient",
      },
      {
        text: "Yes — post-deserialization validation interrupts gadget chain execution",
        misconceptionId: "deser_validation_stops_gadgets",
      },
    ],
    correctIndex: 1,
    source:
      "OWASP Deserialization Cheat Sheet: Execution Flow During Deserialization vs Validation",
  },

  // =========================================================================
  // INSECURE DESERIALIZATION — HARD
  // =========================================================================
  {
    id: "deser_hard_1",
    vulnClass: "insecure_deserialization",
    tier: "hard",
    question:
      "An attacker sends a crafted serialized object to a Java endpoint. The payload uses existing library classes to chain method calls. How does this bypass input validation?",
    options: [
      {
        text: "Signing the payload prevents this if the signature is checked first",
        misconceptionId: "deser_signature_sufficient",
      },
      {
        text: "Java's SecurityManager would catch and block gadget chain execution",
        misconceptionId: "deser_security_manager",
      },
      {
        text: "HMAC is unbreakable — the attacker cannot produce a valid signed payload without the key",
        misconceptionId: "deser_hmac_unbreakable",
      },
      {
        text: "The gadget chain executes during the deserialize() call itself — before any application-level validation code runs",
        misconceptionId: null,
      },
    ],
    correctIndex: 3,
    source: "MITRE CWE-502 & Oracle Secure Coding Standard for Java: Serialization",
  },
  {
    id: "deser_hard_2",
    vulnClass: "insecure_deserialization",
    tier: "hard",
    question:
      "A Node.js app uses node-serialize to restore user session data from a cookie. What is the risk?",
    options: [
      {
        text: "node-serialize can deserialize IIFE syntax, allowing arbitrary code execution when the cookie is restored",
        misconceptionId: null,
      },
      {
        text: "No risk — node-serialize uses JSON internally, which cannot execute code",
        misconceptionId: "deser_json_executes",
      },
      {
        text: "No risk — require() calls inside the payload would need to be explicitly invoked to run",
        misconceptionId: "deser_require_auto_exec",
      },
      {
        text: "The risk is a buffer overflow — node-serialize does not bounds-check the cookie size",
        misconceptionId: "deser_buffer_overflow",
      },
    ],
    correctIndex: 0,
    source: "CVE-2017-5941: node-serialize Untrusted Code Execution via IIFE",
  },
  {
    id: "deser_hard_3",
    vulnClass: "insecure_deserialization",
    tier: "hard",
    question:
      "What is the most robust defence against insecure deserialization when you must accept serialized data from an external source?",
    options: [
      {
        text: "Wrap the deserializer in a try/catch — exceptions during gadget execution will be caught",
        misconceptionId: "deser_catch_exceptions",
      },
      {
        text: "Encrypt the serialized stream — attackers cannot modify an encrypted payload",
        misconceptionId: "deser_encrypt_stream",
      },
      {
        text: "Use a data-only format (JSON/protobuf) with strict schema validation, or deserialize in an isolated sandbox with no dangerous classes on the classpath",
        misconceptionId: null,
      },
      {
        text: "Enable Java's SecurityManager to block gadget chains at runtime",
        misconceptionId: "deser_security_manager",
      },
    ],
    correctIndex: 2,
    source:
      "OWASP Deserialization Prevention Cheat Sheet: Architectural Remediation (https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)",
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Get questions for a specific class + tier */
export function getQuestionsForTier(vulnClass: VulnClass, tier: Tier): TieredQuestion[] {
  return QUIZ_BANK.filter((q) => q.vulnClass === vulnClass && q.tier === tier);
}

/** Pick one question from a tier (rotate by attempt count to avoid repetition) */
export function pickQuestion(
  vulnClass: VulnClass,
  tier: Tier,
  attemptCount: number,
): TieredQuestion | null {
  const questions = getQuestionsForTier(vulnClass, tier);
  if (questions.length === 0) return null;
  return questions[attemptCount % questions.length] ?? null;
}

/** Get the misconception ID for a wrong answer */
export function getMisconceptionId(question: TieredQuestion, chosenIndex: number): string | null {
  if (chosenIndex === question.correctIndex) return null;
  return question.options[chosenIndex]?.misconceptionId ?? null;
}
