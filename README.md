# Secure Loop AI

BUILD PROMPT — SecureLoop

AI-Assisted Secure Code Review & Developer Education Platform (Capstone Project 1)

Paste this entire document into Claude Code (or another agentic coding tool) as the task brief. It is written to be handed to an AI agent directly — it specifies product, architecture, data models, APIs, the validation pipeline, and the exact visual design system to follow.

0. What you are building

SecureLoop is a closed-loop AI-assisted secure code review platform. A developer submits a repository (GitHub URL or ZIP). The system scans it for vulnerabilities (Semgrep for code, OWASP ZAP for running web apps), sends findings to an LLM for a plain-language explanation and a candidate patch, automatically validates that patch in an isolated sandbox (re-scan + re-run tests + no-new-findings check), and only then surfaces it to the developer for accept/reject. Every accepted/rejected fix also feeds a short interactive check and a security score, so the tool teaches secure coding instead of just applying it silently.

This is not "AI finds bugs" or "AI writes patches" — those already exist (Semgrep Autofix, GitHub Copilot Autofix, APPATCH, VulRepair, etc.). The product and the research contribution are the same thing: a validated, human-in-the-loop remediation loop with measurable education outcomes, which the literature (Zhang et al. 2024, IWSPA; Zhou et al. 2024/2025, TOSEM survey) shows is exactly the missing piece — LLMs generate plausible-looking patches that often don't actually fix the vulnerability, break tests, or silently introduce new issues.

i also gave a design templete , so just follow that template , remove unrealted buttons or functionalities 

Research framing to keep in the code/docs (for the paper, not just the app)

Build the system so it can produce the comparison table below as real experimental output, not a mockup:

Approach Detect Explain Patch Validate Semgrep only ✓ ✗ ✗ — LLM only ✓ ✓ ✓ ✗ Semgrep + LLM ✓ ✓ ✓ partial SecureLoop (this project) ✓ ✓ ✓ ✓

Log every run's metrics (see §7) so these numbers are real, exportable data — this is what turns the semester project into a defensible paper.

1. Non-negotiable production-grade requirements

Do not build a prototype that only works on the happy path. Specifically:

Isolation: every patch is applied and tested inside an ephemeral Docker container / sandboxed clone, never on the developer's actual working copy.

Auth: real user accounts (email+password via bcrypt, or GitHub OAuth), JWT-based sessions, per-user data isolation.

Async by design: scanning, LLM calls, and validation are slow — use a job queue (BullMQ + Redis), not blocking HTTP requests. Frontend polls or subscribes via WebSocket for live status.

Idempotent, resumable pipeline: if a scan job crashes mid-way, it should be retryable without corrupting state.

Secrets never touch the LLM prompt or logs: strip .env, credentials, API keys, tokens from any code sent to the LLM.

Rate limiting & cost control on LLM calls (queue + per-user quota).

Structured logging (pino/winston) and an audit trail of every accept/reject decision.

Tests: unit tests for the validation engine's accept/reject logic (this is the core research claim — it must be correct), integration tests for the scan→explain→patch→validate pipeline using fixture repos with known CVE-style bugs.

CI: GitHub Actions running lint + tests on every push.

Dockerized for local dev (docker-compose up: app, Mongo, Redis, sandbox runner).

Seed data / demo mode: a "Try a sample repo" button using a bundled vulnerable fixture repo, so the product can be demoed without a real GitHub account.

2. Tech stack

Layer Technology Notes Frontend React + TypeScript + Vite Tailwind CSS for styling (see design system §5) Backend Node.js + Express + TypeScript REST API Job queue BullMQ + Redis scan / LLM / validation jobs Static analysis Semgrep (code) run via CLI in a subprocess/container DAST OWASP ZAP (baseline scan) only for repos that expose a runnable web app Sandbox execution Docker (ephemeral containers per validation run) ffi via dockerode or CLI LLM OpenAI GPT-4o or Google Gemini 1.5/2.0 — abstract behind an LLMProvider interface never hardcode one vendor Database MongoDB + Mongoose Git integration simple-git / Git CLI clone, isolated branch per patch, PR creation via GitHub API Auth JWT + bcrypt, optional GitHub OAuth Realtime Socket.IO (or SSE) scan/validation progress PDF export Puppeteer or pdf-lib downloadable vulnerability report

3. High-level architecture

┌────────────┐      ┌───────────────┐      ┌──────────────────┐
│  React SPA │◄────►│  Express API  │◄────►│     MongoDB       │
└────────────┘      └───────┬───────┘      └──────────────────┘
                             │
                             ▼
                     ┌───────────────┐
                     │  BullMQ Queue │ (Redis)
                     └───────┬───────┘
              ┌──────────────┼───────────────┐
              ▼              ▼               ▼
      ┌───────────┐  ┌──────────────┐ ┌──────────────┐
      │ Scan Worker│  │  LLM Worker  │ │Validate Worker│
      │ (Semgrep/  │  │ (explain +   │ │ (Docker sandbox│
      │  ZAP)      │  │  patch gen)  │ │  re-scan+tests)│
      └───────────┘  └──────────────┘ └──────────────┘


Pipeline state machine per finding: detected → explained → patch_generated → validating → validated_accepted | validated_rejected → developer_reviewed.

4. Data models (Mongoose)

User { _id, email, passwordHash, githubToken?, createdAt }

Project {
  _id, ownerId, name, sourceType: 'git'|'zip', repoUrl?, defaultBranch,
  lastScanId, createdAt
}

ScanRun {
  _id, projectId, status: 'queued'|'scanning'|'explaining'|'patching'|'validating'|'done'|'failed',
  startedAt, finishedAt, commitSha, tool: ['semgrep','zap'], findingsCount
}

Finding {
  _id, scanRunId, tool, ruleId, cwe, severity, filePath, lineStart, lineEnd,
  vulnerabilityClass: 'sqli'|'xss'|'csrf'|'insecure_deserialization'|'other',
  rawMessage, status: 'open'|'explained'|'patched'|'validated'|'accepted'|'rejected'
}

Explanation {
  _id, findingId, whatItIs, whyItHappened, owaspCategory, howFixWorks, model, generatedAt
}

Patch {
  _id, findingId, diff, explanationId, model, generatedAt,
  validation: {
    vulnerabilityGone: boolean, testsPassed: boolean, newIssuesFound: number,
    logs: string, validatedAt: Date, verdict: 'accepted'|'rejected'
  }
}

DeveloperDecision { _id, patchId, userId, action: 'accept'|'reject', prUrl?, decidedAt }

EducationCheck { _id, findingId, question, options, correctIndex, userAnswer, correct: boolean }

SecurityScore { _id, projectId, overall, byCategory: { sqli, xss, csrf, deserialization }, computedAt }


5. Design system — match the uploaded reference EXACTLY

The reference screenshot is a dark, terminal/IDE-inspired developer-tool landing page (in the style of Superset). Replicate these tokens precisely across marketing pages and the in-app dashboard — don't switch to a generic admin-panel look once past the landing page.

Colors

--bg:            #0A0A0A   (near-black page background)
--bg-elevated:   #121212   (cards, panels, terminal windows)
--border:        #262626   (hairline 1px borders everywhere — this look leans on borders, not shadows)
--text-primary:  #F2F1EC   (warm off-white, not pure white)
--text-secondary:#8C8C87   (muted gray for subheads/labels)
--accent:        #FF5C33   (warm orange/red — used sparingly: buttons, active states, small dot/status indicators)
--success:       #3ECF8E
--danger:        #FF5C5C


Typography

Headlines: a monospace or geometric sans (e.g. Söhne Mono / fallback "JetBrains Mono", monospace) for large display headings — tight tracking, e.g. "Run 100+ Coding Agents in Parallel."

Body copy: clean sans-serif (Inter or system-ui), text-secondary color, generous line-height.

Small section eyebrows in uppercase, letter-spaced, tiny (e.g. "01 // AGENTS", "AUTOMATED PATCHING") — used above every feature section, exactly like "TRUSTED BY BUILDERS FROM", "01 OF AGENTS" in the reference.

Code/terminal UI text always in monospace with syntax-highlight colors (green for additions, red for deletions/removed vulnerable lines, orange for warnings).

Layout patterns to copy

Hero: centered headline + subhead, two pill-shaped buttons side by side (Join waitlist filled dark w/ orange dot, View on GitHub outline), both with a small leading dot/icon.

Faux terminal/IDE window directly under the hero — rounded-corner window with traffic-light dots, monospace content inside, subtle border, sits on the dark background like a floating screenshot. Use this exact pattern for: the scan results view, the patch diff view, and the validation log view.

Logo/trust strip: a row of muted grayscale-style logos/wordmarks under the hero ("Trusted by builders from…") — repurpose this for "Scans powered by Semgrep · OWASP ZAP · GPT-4o" on your landing page.

Feature sections: numbered eyebrow label, bold short headline, 1-2 line description, paired with a screenshot-style panel (bordered, dark, monospace content) — alternate text-left/panel-right and panel-left/text-right down the page.

Two/three-column feature grids with a small icon, short headline, one-line description — used for secondary features.

Testimonial grid: 3-column card grid, avatar + name + role + short quote, bordered cards on --bg-elevated.

Footer CTA: full-width centered "Try it now" band before the footer, same pill buttons as hero.

FAQ: simple accordion, left-aligned question, + icon, hairline dividers, no heavy styling.

Buttons: pill-shaped (rounded-full), 1px border, small dot/glyph before the label, subtle hover glow only — no gradients, no drop shadows, no rounded-xl cards with soft shadows (that would break the aesthetic).

Background: pure flat dark, optionally a very faint grid/dot pattern (as in the reference's footer/CTA sections) — never a gradient mesh or blob.

Apply this design system to:

Marketing/landing page — hero pitching SecureLoop the same way the reference pitches its product, feature sections mapped 1:1 to SecureLoop's actual features (see §6.1).

In-app dashboard — keep dark theme, bordered panels, monospace for code/diffs/logs, pill buttons. The vulnerability list, patch diff viewer, and validation log should all look like the "faux terminal window" component from the landing page — don't switch to a generic light/white SaaS-dashboard look.

6. Pages & screens to build

6.1 Marketing site (public, unauthenticated)

Landing page (/) — hero: "Ship secure code, not just detected bugs." / subhead about the closed validation loop. Terminal-window hero visual showing a live-looking scan → patch → validated sequence. Feature sections: (1) Detect with Semgrep + ZAP, (2) AI explains in plain language, (3) AI patches, (4) Every patch is re-scanned and re-tested before you ever see it (this is the hero differentiator — give it the most visual weight), (5) Learn as you fix (education layer + security score). Testimonials can be placeholder/seed content. FAQ: "How is this different from Copilot Autofix?", "Do you train on my code?", "What languages are supported?", "Is my repo ever sent anywhere insecure?". Footer CTA: "Try SecureLoop now" with Get started / View on GitHub.

Login / Signup

6.2 App (authenticated)

Dashboard — list of connected projects, last scan status, security score badge per project, "New scan" button (GitHub URL or ZIP upload).

Scan progress view — realtime pipeline state (scanning → explaining → patching → validating) shown as a terminal-style live log window (Socket.IO stream), matching the hero terminal component visually.

Findings list — table/list of vulnerabilities by severity/CWE, filterable by class (SQLi/XSS/CSRF/Insecure Deserialization), status badges (open/patched/validated/accepted/rejected).

Finding detail — split view: left = vulnerable code with the flagged lines highlighted; right = LLM explanation (what/why/OWASP category), then the diff of the proposed patch below (monospace, +/- colored), then the validation result panel: ✅/❌ vulnerability removed, ✅/❌ tests passed, count of new issues introduced, raw validation log (collapsible terminal window). Accept/Reject buttons only enabled once validation has run.

Post-decision micro-quiz — short interactive check tied to the vulnerability class just fixed (e.g. 2-3 question quiz on why parameterized queries prevent SQLi), updates the security score.

Security score dashboard — overall score + per-category (SQLi/XSS/CSRF/Deserialization) trend over time, chart component styled dark/monospace-consistent (recharts, but restyle default colors to match the palette).

PDF report / PR generation — download button (report per §7) and "Open pull request" button that pushes the accepted patch to a new branch via the GitHub API.

Settings — GitHub token, LLM provider choice, notification prefs.

7. The validation pipeline (this is the actual research contribution — implement carefully)

For every candidate patch:

Clone the project at the finding's commit into an ephemeral workspace (/tmp/validate/<runId> or a Docker volume).

Apply the LLM-generated diff.

Re-run Semgrep on the changed file(s) — the specific ruleId that fired originally must not fire again.

Re-run Semgrep on the whole changed file (not just the same rule) to catch newly introduced issues.

If the project has a test suite (detect via package.json/pytest.ini/etc.), run it in the sandbox; record pass/fail.

Compute verdict:

accepted only if: original rule no longer fires AND no new findings introduced AND (no test suite OR tests pass).

otherwise rejected, with the specific failing condition recorded (don't just say "failed" — store which check failed, this is what makes your metrics meaningful).

Never let a rejected patch reach the developer as if it were ready — show it labeled clearly as "did not pass validation" with the reason, still viewable for transparency but not one-click-acceptable without an explicit override toggle (log overrides separately, they're a research-relevant metric too).

Log per-run: detection accuracy proxy, false-positive rate (if you seed known-vulnerable fixtures with ground truth), patch success rate, test pass rate, vulnerability-removal rate, new-vulnerabilities-introduced rate, patch acceptance rate, time-to-fix. Store these on ScanRun so they're queryable for your evaluation section later.

8. LLM prompting

Abstract all LLM calls behind:

interface LLMProvider {
  explainVulnerability(finding: Finding, codeContext: string): Promise<Explanation>
  generatePatch(finding: Finding, explanation: Explanation, codeContext: string): Promise<{diff: string}>
  generateQuizQuestion(vulnerabilityClass: string): Promise<EducationCheck>
}


Explanation prompt must ask for: plain-language description, root cause, OWASP Top-10 category, and why the specific patch approach works — output as structured JSON, not free text, so the UI can render it in fixed sections.

Patch prompt must include the surrounding function/file (not just the flagged line), the CWE ID, and an explicit instruction to preserve existing behavior/tests and output a unified diff only.

Never include .env contents, secrets, or credentials in any prompt — strip known secret patterns before sending code context.

Cap context size sent per finding; chunk large files around the vulnerable region.

9. Vulnerability classes to support at launch (per proposal)

Class Detect via Patch strategy SQL Injection Semgrep rule pack Rewrite to parameterized/prepared statements XSS Semgrep + ZAP Escape/sanitize output before render CSRF Semgrep + ZAP Introduce/verify per-session CSRF token Insecure Deserialization Semgrep Restrict allowed classes, prefer JSON, validate types

10. Suggested build order (semester-scoped milestones)

Repo intake (GitHub URL/ZIP) + Semgrep scan worker + findings persisted and listed in UI (no AI yet). Get the dark/terminal design system nailed on landing + findings list first.

LLM explanation + patch generation wired to findings (no validation yet) — diff viewer UI.

Sandbox validation pipeline (§7) — this is the core contribution, budget the most time here, plus unit tests proving the accept/reject logic is correct on seeded fixture repos with known good/bad patches.

Accept/reject workflow + PR creation + PDF report.

Education layer (micro-quiz) + security score computation/dashboard.

OWASP ZAP integration for runnable web apps (stretch if time-constrained — the code-only path via Semgrep is the core deliverable).

Polish marketing landing page to match the reference design pixel-for-pixel; record metrics from real scan runs for the paper's evaluation section.

11. Deliverables checklist (map back to proposal §7)

[ ] Repo URL / ZIP intake

[ ] Automated Semgrep scanning

[ ] Dashboard listing all detected vulnerabilities

[ ] AI-generated plain-language explanations

[ ] AI-generated secure code suggestions

[ ] Automated patch validation (re-scan + tests) — with logged, queryable metrics

[ ] Accept/reject workflow with downloadable PDF report

[ ] (Bonus, strengthens the research angle) Education micro-checks + security score

[ ] (Bonus) PR auto-generation via GitHub API

Build this as a real, runnable monorepo (/frontend, /backend, /worker, docker-compose.yml). Start with milestone 1 and confirm the design system renders correctly before moving to the pipeline logic.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/ef31ee4b-e260-4508-b068-0cc1944ff39e).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
