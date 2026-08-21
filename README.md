# SecureLoop

**AI-Assisted Secure Code Review & Developer Education Platform**

SecureLoop scans a codebase for security vulnerabilities, uses an LLM to explain each finding in plain language and generate a candidate patch, then **automatically validates that patch in an isolated sandbox** — re-running the security scan and test suite — before ever showing it to a developer. Every accept/reject decision is logged, and a short interactive check reinforces the underlying secure-coding concept, so the tool teaches secure coding rather than silently applying it.

> Detection alone isn't the hard part anymore, and neither is getting an LLM to *suggest* a fix. The hard part — and the gap this project targets — is trusting that an AI-generated patch actually works. SecureLoop's contribution is the closed validation loop between "AI wrote a patch" and "a developer should accept it."

---

## Table of Contents

- [Why SecureLoop](#why-secureloop)
- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Overview](#api-overview)
- [Validation Pipeline](#validation-pipeline)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Research Context](#research-context)
- [Contributing](#contributing)
- [License](#license)

---

## Why SecureLoop

Static analysis tools (Semgrep, OWASP ZAP) reliably detect vulnerabilities but don't explain them accessibly or guide a developer to a validated fix. AI coding assistants suggest fixes but rarely verify whether a patch actually removes the vulnerability, passes existing tests, or introduces new problems elsewhere. SecureLoop sits in that gap:

- **Detect** — deterministic scanning via Semgrep (static analysis) and OWASP ZAP (dynamic analysis for running web apps).
- **Explain** — an LLM translates each finding into a plain-language explanation: what it is, why it happened, its OWASP category, and how the proposed fix works.
- **Patch** — the LLM generates a candidate fix as a unified diff.
- **Validate** — the patch is applied in an isolated sandbox; the original scan is re-run, the test suite (if present) is executed, and the patch is only surfaced as fix-ready if the vulnerability is gone, tests pass, and no new issues were introduced.
- **Decide** — the developer reviews the explanation, diff, and validation result, then accepts or rejects.
- **Learn** — a short quiz tied to the vulnerability class reinforces the concept and updates a per-category security score.

## How it works

```
Repository (Git URL / ZIP)
        │
        ▼
  Semgrep + ZAP scan ──► Findings
        │
        ▼
   LLM explanation ──► plain-language writeup + OWASP category
        │
        ▼
   LLM patch generation ──► unified diff
        │
        ▼
  Isolated sandbox validation
   ├─ vulnerability re-scanned — must be gone
   ├─ existing tests re-run — must pass
   └─ fresh scan — no new findings introduced
        │
        ▼
  Accept-ready patch shown to developer
        │
        ▼
  Developer accepts / rejects ──► optional PR ──► micro-quiz ──► security score updated
```

Rejected patches are never silently hidden — they're shown labeled with the specific check that failed (vulnerability still present / tests broke / new issue introduced), so nothing gets accepted on faith.

## Architecture

```
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
      ┌───────────┐  ┌──────────────┐ ┌────────────────┐
      │ Scan Worker│  │  LLM Worker  │ │ Validate Worker │
      │ (Semgrep/  │  │ (explain +   │ │ (Docker sandbox,│
      │  ZAP)      │  │  patch gen)  │ │  re-scan+tests) │
      └───────────┘  └──────────────┘ └────────────────┘
```

Scanning, LLM calls, and sandbox validation are all queued jobs, not blocking HTTP requests — the frontend receives live progress over WebSocket.

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Backend | Node.js, Express, TypeScript |
| Job Queue | BullMQ + Redis |
| Static Analysis | Semgrep |
| Dynamic Analysis | OWASP ZAP (baseline scan) |
| Sandbox Execution | Docker (ephemeral containers per validation run) |
| LLM Provider | OpenAI GPT-4o / Google Gemini — abstracted behind a common `LLMProvider` interface |
| Database | MongoDB + Mongoose |
| Git Integration | simple-git, GitHub API (PR creation) |
| Auth | JWT + bcrypt, optional GitHub OAuth |
| Realtime | Socket.IO |

## Getting Started

### Prerequisites
- Node.js ≥ 20
- Docker & Docker Compose
- Semgrep CLI (`pip install semgrep` or via Docker)
- A GitHub personal access token (for repo intake / PR creation)
- An OpenAI or Google Gemini API key

### Installation

```bash
git clone https://github.com/<your-org>/secureloop.git
cd secureloop
cp .env.example .env   # fill in API keys, Mongo/Redis URIs, GitHub token
docker-compose up
```

This starts the API, worker processes, MongoDB, and Redis. The frontend is served separately in development:

```bash
cd frontend
npm install
npm run dev
```

### Try it without connecting a real repo

Use the **"Try a sample repo"** option on the dashboard, which runs SecureLoop against a bundled intentionally-vulnerable fixture project — no GitHub account required.

## Configuration

Environment variables (see `.env.example`):

| Variable | Description |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `REDIS_URL` | Redis connection string for BullMQ |
| `LLM_PROVIDER` | `openai` or `gemini` |
| `OPENAI_API_KEY` / `GEMINI_API_KEY` | LLM provider credentials |
| `GITHUB_TOKEN` | Used for repo cloning and PR creation |
| `JWT_SECRET` | Signing secret for auth tokens |
| `SEMGREP_RULESETS` | Comma-separated rule packs, default `p/owasp-top-ten,p/nosql-injection` |

## Usage

1. Sign in and connect a project via GitHub URL or ZIP upload.
2. Trigger a scan — progress streams live as `scanning → explaining → patching → validating`.
3. Review findings by severity and vulnerability class.
4. Open a finding to see the vulnerable code, the plain-language explanation, the proposed patch diff, and the validation result.
5. Accept a validated patch to open a pull request, or reject it — either action is logged.
6. Answer the short quiz that follows to reinforce the concept and update your security score.
7. Export a PDF vulnerability report at any time.

## API Overview

| Endpoint | Description |
|---|---|
| `POST /api/projects` | Register a new project (Git URL or ZIP) |
| `POST /api/projects/:id/scan` | Queue a new scan run |
| `GET /api/scans/:id` | Scan run status and findings |
| `GET /api/findings/:id` | Finding detail, explanation, patch, validation result |
| `POST /api/findings/:id/decision` | Accept or reject a validated patch |
| `POST /api/findings/:id/pr` | Open a pull request for an accepted patch |
| `GET /api/projects/:id/score` | Current security score, overall and by category |
| `GET /api/projects/:id/report` | Download PDF vulnerability report |

## Validation Pipeline

For every candidate patch:

1. Clone the project at the finding's commit into an ephemeral sandbox.
2. Apply the generated diff.
3. Re-run Semgrep against the changed file(s) — the originally-fired rule must no longer trigger.
4. Re-run Semgrep against the whole changed file to catch newly introduced issues.
5. Run the existing test suite, if one is detected.
6. Compute a verdict:
   - **Accepted** only if the original finding is gone, no new findings were introduced, and (if applicable) tests pass.
   - **Rejected** otherwise, with the specific failing condition recorded.

Per-run metrics (detection accuracy, patch success rate, test pass rate, new-issue rate, time-to-fix) are stored against each scan run for evaluation and reporting.

## Vulnerability Coverage

| Class | Detected via | Patch strategy |
|---|---|---|
| SQL Injection | Semgrep | Rewrite to parameterized / prepared statements |
| Cross-Site Scripting (XSS) | Semgrep + ZAP | Escape/sanitize output before rendering |
| Cross-Site Request Forgery (CSRF) | Semgrep + ZAP | Introduce and verify per-session CSRF tokens |
| Insecure Deserialization | Semgrep | Restrict allowed classes, prefer JSON, validate input types |

## Testing

```bash
npm run test          # unit tests
npm run test:integration   # full scan → explain → patch → validate pipeline against fixture repos
npm run lint
```

Integration tests run the pipeline against intentionally-vulnerable fixture projects (e.g. OWASP NodeGoat, DVWA) with hand-labeled ground truth, so the accept/reject logic in the validation engine is checked against known-correct outcomes, not just happy-path mocks.

## Roadmap

- [x] Repo intake (GitHub URL / ZIP)
- [x] Semgrep-based scanning
- [x] LLM explanation and patch generation
- [x] Sandbox patch validation
- [ ] OWASP ZAP integration for running web apps
- [ ] Developer education scoring dashboard polish
- [ ] Multi-LLM cross-validation of candidate patches

## Research Context

SecureLoop's contribution is deliberately scoped: it does not claim to be the first system to detect vulnerabilities or generate AI patches — an active body of work already covers both (LLM-based vulnerability repair, e.g. Pearce et al. 2023; APPATCH, USENIX Security 2025; survey by Zhou et al., ACM TOSEM 2025). What existing systems generally don't provide is automated, measurable validation of whether a generated patch actually works before a developer ever sees it — prior evaluation (Zhang et al., 2024) shows LLM-generated fixes frequently fail on real-world code. SecureLoop's closed-loop validation, combined with an explicit developer-education layer, is the specific gap this project targets.

## Contributing

Issues and pull requests are welcome. Please open an issue describing the change before submitting a large PR, and ensure `npm run lint` and `npm run test` pass locally.

## License

MIT
