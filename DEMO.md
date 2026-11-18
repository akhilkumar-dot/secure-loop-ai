# SecureLoop — Review 3 Demonstration Walkthrough (DEMO.md)

This walkthrough demonstrates the end-to-end capabilities implemented for **Review 3 (Weeks 6–9)**:

- **Misconception Detection** (Adaptive learning diagnosis, 3-of-4 recurrence rule)
- **Locked Tier Progression** (Server-side enforced thresholds: Easy → Medium → Hard)
- **Adaptive Mastery & Spaced Repetition** (SM-2 scheduler, live "Due for review" indicators)
- **Empirical Benchmark & False-Positive Evaluation** (OWASP benchmark set, honest recall/FP metrics)
- **Comprehensive Audit PDF Export** (Full remediation and learning report)

---

## Quick Setup (1-Click Demo Mode)

You can seed the full realistic demo history either via CLI or with a single click in the UI:

### Option A: From UI

1. Navigate to **http://localhost:5173/dashboard** (or your local port).
2. Click the **`load demo data`** button in the top right of the dashboard.
3. Realistic OWASP WebGoat project, scan findings, misconception history, and spaced reviews are instantly loaded!

### Option B: From Terminal

```bash
npm run seed:demo
```

---

## Step-by-Step Click Path

### Step 1: Dashboard Overview & Misconception Diagnosis

1. Visit `/dashboard`.
2. Observe the **Learning Diagnosis Card**:
   - Notice the diagnosis: _"Believes encoding/encrypting input prevents SQL injection"_.
   - Notice the supporting evidence: _"Triggered in 3 of your last 4 answers for this class"_.
   - Plain score is secondary; the actionable diagnosis is the primary focal point.
3. Observe the **Spaced Repetition & Due Reviews** grid:
   - **SQL Injection**: Marked **`● Due for review`** (SM-2 interval shortened due to recurring misconception).
   - **XSS**: Marked **`Next review in 3 days`** (Tier Medium, 100% accuracy).
   - **CSRF**: Marked **`Next review in 5 days`** (Tier Medium).

---

### Step 2: Finding Detail & Remediation End-to-End

1. In the **Projects** table on the dashboard, click on **`OWASP WebGoat Audit`**.
2. You will land on the Findings List (`/findings/:projectId`).
3. Click on the first critical finding: **`javascript.sql.node-sqli-injection`** (`contributions.js`).
4. On the Finding Detail page (`/finding/:findingId`):
   - **Inspect Code Snippet**: Red arrow indicates vulnerable concatenation at Line 7.
   - **Inspect Gemini Explanation**: Technical breakdown explaining why string interpolation fails.
   - **Inspect Sandbox Validation**: Diff applied to an isolated sandbox copy, verified with AST syntax check and Semgrep re-scan (0 findings remaining).
5. Click **`accept patch`**.

---

### Step 3: Locked Tiered Education Check

1. Immediately upon accepting the patch, the **Education Check** appears:
   - Notice the tier indicator: **`tier: easy`**.
   - Review the question with options mapped to named misconceptions.
   - Select option **(b)** (the correct parameterized query explanation) and click **`submit answer`**.
   - Notice the server-side tier gate verifies attempts before unlocking Medium tier (requires ≥ 2/3 correct).
   - The answer is logged to `education_checks`, the SM-2 interval is updated, and recurring misconceptions are re-evaluated.

---

### Step 4: Spaced Repetition in the Learning Hub (`/learn`)

1. In the top navigation, click **`learn`** or navigate to `/learn`.
2. Inspect the **Vulnerability Mastery Profiles**:
   - Each class displays its status: **Mastered**, **Learning**, or **Weak**.
   - View attempts count, accuracy percentage, and current tier reached.
3. Click **`Practice due review`** on SQL Injection:
   - An interactive practice card opens with a **similar-but-different** question rotated based on attempts count.
   - Answer the question and submit.
   - Notice the live feedback and instant recalculation of next review date!

---

### Step 5: PDF Audit Report Export (`/report/:projectId`)

1. From the Findings page or top navigation, click **`export PDF report`** (or go to `/report/:projectId`).
2. The print-ready **Security Audit & Learning Report** is rendered:
   - Clear header with **User Email**, **Project Name**, and **Generation Date**.
   - Executive Summary with security score and validated fix metrics.
   - Complete findings table with CWEs, severities, file locations, explanations, and unified diffs.
   - Learning diagnostics section detailing active recurring misconceptions.
   - Mastery & Spaced Repetition schedule table.
3. Click **`print / save as PDF`** (or press `Ctrl+P` / `Cmd+P`):
   - Notice the clean print stylesheet (`@media print`) with headers, proper page breaks, and stripped UI buttons ready for client delivery.

---

### Step 6: Empirical Benchmark & False-Positive Evaluation (`/benchmark`)

1. Click **`benchmark`** in the navigation header or run in terminal:
   ```bash
   npm run benchmark
   ```
2. On `/benchmark`:
   - Inspect the honest metrics banner:
     - **Detection Rate (Recall)**: 71% (10/14 detected)
     - **False Positive Rate**: 50% (honest evaluation on safe control snippets with secondary rule firings)
     - **Patch Validation Success Rate**: 62% (deterministic AST and re-scan validation)
   - In the sample results table, click **`mark FP`** on any row to simulate developer feedback:
     - Notice the rates recalculate dynamically in real time without refreshing.
   - Click the **`Copilot Autofix & Snyk Comparison Table`** tab:
     - View the matrix template with un-fabricated evaluation fields.
   - Click **`export CSV`** to download `secureloop-comparison-evaluation.csv`.

---

## Automated Verification Suite

Run all 72 unit tests spanning score computation, SAST detection, patch application, recurrence detection edge cases, SM-2 spaced repetition, and benchmark validation:

```bash
npm test
```

_(All 72 tests pass across 6 test suites)._
