# SecureLoop

**AI-Powered Closed-Loop Secure Code Review Platform**

SecureLoop scans any public or private GitHub repository for real security vulnerabilities, explains each finding in plain language, generates a candidate fix as a unified diff, and validates that fix using AI-based re-analysis — all before a developer ever sees it. Every accept/reject decision is recorded, and an interactive education check after each decision reinforces the underlying secure-coding concept.

> Detection alone isn't the hard part. Neither is getting an LLM to *suggest* a fix. The hard part is trusting that an AI-generated patch actually works. SecureLoop's contribution is the closed validation loop between "AI wrote a patch" and "a developer should accept it."

---

## Table of Contents

- [Why SecureLoop](#why-secureloop)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [SAST Rule Coverage](#sast-rule-coverage)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Usage](#usage)
- [Data Model](#data-model)
- [Validation Pipeline](#validation-pipeline)
- [Developer Decision Flow](#developer-decision-flow)
- [Security Score](#security-score)
- [Roadmap](#roadmap)
- [Research Context](#research-context)
- [License](#license)

---

## Why SecureLoop

Traditional SAST tools detect vulnerabilities but produce noisy output that's hard to act on. AI coding assistants suggest fixes but rarely verify whether a patch actually removes the vulnerability, passes existing tests, or introduces new problems. SecureLoop closes that loop:

- **Detect** — deterministic, regex-pattern SAST rules modelled after Semgrep's `p/owasp-top-ten` and `p/nosql-injection` rule packs, running entirely in-process (no CLI dependency).
- **Explain** — Google Gemini translates each finding into a plain-language writeup: what the vulnerability is, why the specific code pattern triggered it, its OWASP Top 10 category, and how the proposed fix eliminates it.
- **Patch** — Gemini generates a minimal, surgical unified diff targeting only the vulnerable code.
- **Validate** — Gemini re-reads the original code alongside the generated diff and evaluates three checks: vulnerability eliminated, no new issues introduced, simulated test pass. Verdict is `ACCEPTED` or `REJECTED`, with the specific failing condition recorded.
- **Decide** — the developer reviews the finding, explanation, diff, and validation result, then accepts or rejects. All decisions are persisted.
- **Learn** — a short quiz tied to the vulnerability class (`sqli`, `xss`, `csrf`, `insecure_deserialization`) is shown after every decision, answers are stored, and a per-category security score tracks improvement over time.

---

## How It Works

```
GitHub Repo URL
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1 · FILE INGESTION                                        │
│  GitHub REST API (tree + blob endpoints) fetches all source     │
│  files matching target extensions. Skips node_modules, dist,    │
│  build, minified files, and lock files. Results cached          │
│  in-memory keyed by owner/repo + commit SHA.                    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2 · SAST SCAN  (deterministic — source of truth)          │
│  17 pattern rules run in-browser via TypeScript against every   │
│  fetched file. Rule IDs follow Semgrep registry format.         │
│  Each finding: rule_id, CWE, severity, file, line, code snippet.│
│  Language guard-rail drops rule/file language mismatches.       │
│  Output sorted by severity then file path.                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3 · LLM HEURISTIC PASS  (secondary — never overrides SAST)│
│  Sends files in batches to Gemini for a secondary pass          │
│  targeting logic/access-control bugs SAST rules miss:           │
│  broken access control, IDOR, missing authorization checks.     │
│  Findings labeled source:"llm-heuristic" and kept separate.     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4 · PERSIST                                               │
│  All findings (SAST + LLM) written to Supabase (PostgreSQL).    │
│  scan_runs row updated through each stage:                       │
│  queued → scanning → explaining → patching → validating → done  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 5 · EXPLAIN  (Gemini AI)                                  │
│  Per finding: what_it_is, why_it_happened, owasp_category,      │
│  how_fix_works, confidence (high/medium/low/not_applicable).     │
│  False positives flagged with error_type:"false_positive".       │
│  Identical rule+message pairs cached in-memory within a run.    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 6 · PATCH  (Gemini AI)                                    │
│  Reads vulnerable code + explanation, produces a minimal        │
│  unified diff. Markdown fences stripped from response.          │
│  Stored against the finding with model attribution.             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 7 · VALIDATE  (Gemini AI — self-check)                    │
│  Gemini re-reads original + patch and evaluates:                │
│  • vulnerability_gone: boolean                                   │
│  • tests_passed: boolean                                         │
│  • new_issues: number                                            │
│  Verdict: "accepted" only if all three checks pass.             │
│  "rejected" patches are persisted with the failing check name.  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 8 · SCORE                                                 │
│  Per-project security_scores row computed: overall + sqli,      │
│  xss, csrf, deserialization. Tracked across every scan run.     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Browser (React 19 SPA)                    │
│                                                              │
│  TanStack Router (file-based, type-safe)                     │
│  TanStack Query (server-state cache)                         │
│  Radix UI primitives + Tailwind CSS v4                       │
│  Recharts (security score trend charts)                      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  SAST Engine  (sast.ts — pure TypeScript, in-browser) │   │
│  │  17 regex-pattern rules, language guard-rail,         │   │
│  │  dedup at rule_id:line_start, severity-sorted output  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AI Provider Layer  (gemini.ts + gemini-provider.ts)  │   │
│  │  Primary:    gemini-3.8-flash                         │   │
│  │  Fallback 1: gemini-3.1-flash-lite                   │   │
│  │  Fallback 2: gemini-flash-lite-latest                │   │
│  │  Retry: 2 attempts per model, 1.5s delay on 503/429  │   │
│  │  Also supports: OpenRouter, OpenAI, Cohere (by key   │   │
│  │  prefix — AQ./AIza → Gemini, sk-or- → OpenRouter,   │   │
│  │  sk- → OpenAI)                                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  GitHub Integration  (github.ts)                      │   │
│  │  REST API: tree + blob endpoints (no git binary)      │   │
│  │  Commit SHA-keyed in-memory file cache                │   │
│  │  Supports public repos + PAT for private              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────┬────────────────────────────────────┘
                          │ Supabase JS client (anon key + RLS)
                          ▼
┌──────────────────────────────────────────────────────────────┐
│              Supabase  (PostgreSQL + Auth)                    │
│                                                              │
│  profiles            — user display name, GitHub PAT,        │
│                        encrypted AI API key, LLM provider    │
│  projects            — repo URL, source type, default branch │
│  scan_runs           — status, stage, metrics per run        │
│  findings            — rule_id, CWE, severity, file, line,   │
│                        code_lines, status, tool label        │
│  explanations        — what/why/owasp/how, model, confidence │
│  patches             — unified diff, model, validation result│
│  developer_decisions — accept/reject/override per patch+user │
│  education_checks    — quiz question, options, answer, score  │
│  security_scores     — overall + per-category, per scan run  │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼  (SSR entry / Cloudflare Worker)
┌──────────────────────────────────────────────────────────────┐
│         Nitro (via TanStack Start)  — server entry            │
│  Cloudflare Workers preset · src/server.ts wraps SSR         │
│  h3-swallowed error normalization → clean 500 HTML page      │
└──────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| **Framework** | TanStack Start v1 | SSR + file-based routing via TanStack Router |
| **Runtime** | React 19, TypeScript 5.8 | Strict mode |
| **Build** | Vite 8 + Rolldown + Nitro | Cloudflare Workers deploy target |
| **Styling** | Tailwind CSS v4 | JIT, CSS variables design tokens |
| **Component primitives** | Radix UI | Accessible headless components |
| **Charts** | Recharts | Security score trend line chart |
| **Forms** | React Hook Form + Zod | Schema-validated inputs |
| **Server state** | TanStack Query v5 | Caching, background refetch |
| **Database** | Supabase (PostgreSQL) | Row Level Security, realtime subscriptions |
| **Auth** | Supabase Auth | GitHub OAuth + magic link |
| **SAST engine** | Custom TypeScript (sast.ts) | 17 rules, Semgrep-compatible rule IDs, runs in-browser |
| **Primary AI** | Google Gemini (`@google/generative-ai` v0.24) | gemini-3.8-flash + 2-tier fallback |
| **AI fallback** | OpenRouter · OpenAI · Cohere | Auto-selected by API key prefix |
| **GitHub integration** | GitHub REST API | No git binary dependency; serverless-safe |
| **Icons** | Lucide React | |
| **Linting** | ESLint 9 + TypeScript ESLint + Prettier | |
| **Deploy target** | Cloudflare Workers (via Nitro) | Can also deploy to Vercel (Node.js preset) |

---

## SAST Rule Coverage

All 17 rules run deterministically in-browser. Rule IDs follow Semgrep registry format for citability. Language guard-rails prevent cross-language false positives.

### JavaScript / TypeScript / Node.js (13 rules)

| Rule ID | CWE | Severity | What It Detects |
|---|---|---|---|
| `javascript.mongodb.nosqli.nosql-injection-req-body` | CWE-943 | critical | `req.body/query/params` flowing unsanitized into MongoDB query methods |
| `javascript.mongodb.nosqli.nosql-where-injection` | CWE-943 | critical | `$where` operator with string concatenation (arbitrary JS in MongoDB) |
| `javascript.browser.security.innerHTML-assignment` | CWE-79 | high | `innerHTML` assigned a non-literal value |
| `javascript.express.xss.res-send-user-data` | CWE-79 | high | `res.send/write` with user-controlled data and no encoding |
| `javascript.lang.security.audit.eval-user-input` | CWE-79 | critical | `eval()` called with user input (XSS + RCE) |
| `javascript.express.xss.unescaped-template-var` | CWE-79 | high | Unescaped output in EJS (`<%-`), Handlebars (`{{{`), or Pug (`!=`) |
| `javascript.express.security.audit.csrf.csrf-not-enabled` | CWE-352 | medium | POST/PUT/PATCH/DELETE route with no `csurf` or CSRF token check |
| `javascript.express.security.audit.session.session-no-secure` | CWE-614 | high | `express-session` without `secure: true` |
| `javascript.express.security.audit.session.session-no-httponly` | CWE-1004 | medium | `express-session` without `httpOnly: true` |
| `javascript.express.security.audit.session.session-hardcoded-secret` | CWE-331 | high | Short hardcoded session secret |
| `javascript.express.security.audit.session.session-memory-store` | CWE-400 | medium | `express-session` using default MemoryStore (leaks in production) |
| `javascript.lang.security.audit.sqli.node-sqli-injection` | CWE-89 | critical | SQL query built with string concatenation and user input |
| `javascript.lang.security.audit.unsafe-deserialization` | CWE-502 | critical | `node-serialize/unserialize` with user-controlled data |
| `javascript.lang.security.audit.child-process-injection` | CWE-78 | critical | `exec/spawn` with user input (OS command injection) |
| `javascript.lang.security.audit.path-traversal` | CWE-22 | high | `fs.readFile/writeFile` with user path and no `path.resolve` guard |
| `javascript.lang.security.audit.hardcoded-credentials` | CWE-798 | high | Hardcoded passwords, API keys, tokens, secrets in source |

### Java / Spring (4 rules)

| Rule ID | CWE | Severity | What It Detects |
|---|---|---|---|
| `java.spring.security.audit.sqli.spring-sqli-concat` | CWE-89 | critical | JPQL/JDBC query built with string concatenation |
| `java.lang.security.audit.xss.servlet-response-writer` | CWE-79 | high | Unsanitized data written to `HttpServletResponse` output stream |
| `java.lang.security.audit.command-injection.process-builder` | CWE-78 | critical | `ProcessBuilder`/`Runtime.exec` with concatenated input |
| `java.spring.security.audit.csrf.spring-csrf-disabled` | CWE-352 | medium | `.csrf().disable()` in Spring Security configuration |

### Language Support

`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.html`, `.htm`, `.ejs`, `.hbs`, `.vue`, `.java`, `.jsp`, `.py`, `.rb`, `.php`, `.cs`, `.go`

---

## Getting Started

### Prerequisites

- Node.js ≥ 20 (or Bun ≥ 1.1)
- A [Supabase](https://supabase.com) project with the schema applied
- A [Google AI Studio](https://aistudio.google.com/app/apikey) API key (Gemini)
- A GitHub account (OAuth login) and optionally a Personal Access Token for private repos

### Installation

```bash
git clone https://github.com/<your-org>/secure-loop-ai.git
cd secure-loop-ai
cp .env.example .env   # fill in keys — see Configuration below
npm install
npm run dev            # starts Vite dev server
```

### Build for Production

```bash
npm run build          # outputs to .output/ (Cloudflare Workers format)
```

To deploy to Vercel instead, change the Nitro preset to `vercel` in `vite.config.ts` or set `NITRO_PRESET=vercel` in the environment.

---

## Configuration

Copy `.env.example` to `.env` and populate:

| Variable | Description |
|---|---|
| `VITE_SUPABASE_URL` | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Supabase anonymous (public) key |
| `VITE_GEMINI_API_KEY` | Google AI Studio key — keys starting `AQ.` or `AIza` |
| `GEMINI_API_KEY` | Same key, exposed server-side for SSR |
| `VITE_OPENAI_API_KEY` | Optional — used if no Gemini key; keys starting `sk-` |
| `VITE_OPENROUTER_API_KEY` | Optional — used as final fallback; keys starting `sk-or-` |

**AI provider auto-routing:** The provider is selected automatically by key prefix — no `LLM_PROVIDER` flag needed. Keys starting `AQ.` or `AIza` → Gemini. `sk-or-` → OpenRouter. `sk-` → OpenAI. Any other long alphanumeric string → Cohere.

**GitHub token:** Stored per-user in Supabase `profiles.github_token` (set in Settings). Used only to call GitHub REST API for private repo file access. Never sent to any AI provider.

---

## Usage

1. **Sign in** via GitHub OAuth on the login page.
2. **Create a project** — paste a GitHub repo URL (public or private).
3. **Trigger a scan** — click *start scan* on the project scan page. Watch the live pipeline log: `cloning → sast → explaining → patching → validating → done`.
4. **Review findings** — browse the findings list, filterable by severity and vulnerability class.
5. **Open a finding** — see the vulnerable code, plain-language explanation, proposed patch diff, and validation verdict side-by-side.
6. **Accept or Reject** — record your decision. Accepted patches need to be applied manually to your repo (`git apply patch.diff`).
7. **Answer the quiz** — reinforces the concept behind the vulnerability class.
8. **Track your score** — the Security Score page shows an overall score and per-category breakdown (SQLi, XSS, CSRF, Deserialization) across all scans.

---

## Data Model

```
projects
  └── scan_runs (one per scan trigger)
        └── findings (one per vulnerability instance)
              ├── explanations (one per finding)
              └── patches
                    └── developer_decisions (one per accept/reject action)

education_checks  (one per quiz answer, linked to finding + user)
security_scores   (one per scan run, per project)
profiles          (one per user — stores GitHub token + AI key)
```

All tables are owned by the authenticated user via Supabase Row Level Security (RLS). No finding or patch data is accessible cross-account.

---

## Validation Pipeline

For every candidate patch, Gemini performs a three-check validation pass:

| Check | Pass condition |
|---|---|
| `vulnerability_gone` | The original vulnerability pattern no longer exists in the patched code |
| `tests_passed` | No logic regressions introduced (simulated via AI re-analysis) |
| `new_issues` | Zero new vulnerability patterns introduced by the patch |

**Verdict:**
- `accepted` — all three checks pass
- `rejected` — any check fails; `validation_failed_check` records which one

Both accepted and rejected patches are stored and visible. Rejected patches surface the specific failure reason so nothing is accepted on faith.

Per-run metrics stored on `scan_runs`: `patch_success_rate`, `test_pass_rate`, `vuln_removal_rate`, `new_vulns_rate`, `acceptance_rate`, `time_to_fix_seconds`.

---

## Developer Decision Flow

```
Patch shown to developer
        │
   ┌────┴────┐
   │         │
accept     reject
   │         │
   └────┬────┘
        │
 INSERT developer_decisions
 (patch_id, user_id, action, is_override)
        │
 UPDATE findings.status
 ("accepted" | "rejected")
        │
 Quiz displayed
 (tied to vulnerability_class)
        │
 INSERT education_checks
 (question, user_answer, correct)
        │
 Link → Security Score page
```

If the AI validation verdict was `rejected` but the developer clicks accept anyway, the decision is recorded with `is_override: true`.

---

## Security Score

A score from 0–100 is computed per project, per scan run, and broken down into four categories:

| Category | CWE families covered |
|---|---|
| SQL Injection | CWE-89, CWE-943 (NoSQLi) |
| XSS | CWE-79 |
| CSRF | CWE-352 |
| Deserialization | CWE-502 |

The **Security Score** page renders a `Recharts` `LineChart` tracking score over time across all scan runs, so developers can see measurable improvement as findings are accepted and fixed.

---

## Roadmap

- [x] GitHub REST API repo ingestion (no git binary — serverless-safe)
- [x] In-browser deterministic SAST engine (17 rules, Semgrep-compatible rule IDs)
- [x] LLM heuristic secondary pass (logic/access-control bugs)
- [x] Google Gemini AI integration with multi-tier model fallback
- [x] Multi-provider support (Gemini, OpenRouter, OpenAI, Cohere) via key prefix auto-routing
- [x] AI-based patch validation (3-check closed loop)
- [x] Developer accept/reject decision logging
- [x] Per-vulnerability-class education quiz
- [x] Security score dashboard with trend chart
- [x] Project deletion with full cascade (findings, scans, scores)
- [ ] Copy-to-clipboard patch button (one-click `git apply`)
- [ ] Score recalculation on patch accept (without requiring full re-scan)
- [ ] Auto-rejection retry with regenerated patch
- [ ] GitHub PR creation from accepted patch
- [ ] Python, Ruby, PHP, Go rule packs (Java SAST rules already shipped)

---

## Research Context

SecureLoop's scope is deliberately narrow: it does not claim to be the first system to detect vulnerabilities or generate AI patches — an active body of work covers both (Pearce et al. 2023; APPATCH, USENIX Security 2025; Zhou et al., ACM TOSEM 2025). What existing systems generally don't provide is automated, measurable validation of whether a generated patch actually works before a developer sees it. Prior evaluation (Zhang et al., 2024) shows LLM-generated fixes frequently fail on real-world code. SecureLoop's closed-loop validation, combined with an explicit developer-education layer, is the specific gap this project targets.

---

## License

MIT
