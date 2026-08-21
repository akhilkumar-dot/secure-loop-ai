import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  ArrowRight,
  BrainCircuit,
  FileText,
  FlaskConical,
  GitPullRequest,
  GraduationCap,
  KeyRound,
  ListChecks,
  Minus,
  Plus,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";
import {
  Eyebrow,
  Logo,
  Pill,
  PillLink,
  TerminalWindow,
} from "@/components/chrome";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SecureLoop — Ship secure code, not just detected bugs" },
      {
        name: "description",
        content:
          "SecureLoop scans your repo with Semgrep and OWASP ZAP, explains every finding in plain language, generates a patch, and sandbox-validates it before you ever see it.",
      },
      { property: "og:title", content: "SecureLoop — Ship secure code, not just detected bugs" },
      {
        property: "og:description",
        content:
          "A closed-loop AI secure code review platform: detect, explain, patch, validate — then learn from every fix.",
      },
    ],
  }),
  component: LandingPage,
});

function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <MarketingNav />
      <Hero />
      <TrustStrip />
      <PipelineGrid />
      <ValidateSection />
      <LearnSection />
      <ComparisonSection />
      <Testimonials />
      <Faq />
      <FooterCta />
      <Footer />
    </div>
  );
}

/* ---------------------------------- nav ----------------------------------- */

function MarketingNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
        <Logo />
        <nav className="hidden items-center gap-7 font-mono text-xs text-subtle md:flex">
          <a href="#pipeline" className="transition-colors hover:text-foreground">
            pipeline
          </a>
          <a href="#validate" className="transition-colors hover:text-foreground">
            validation
          </a>
          <a href="#learn" className="transition-colors hover:text-foreground">
            education
          </a>
          <a href="#faq" className="transition-colors hover:text-foreground">
            faq
          </a>
        </nav>
        <div className="flex items-center gap-3">
          <Link
            to="/login"
            className="hidden font-mono text-xs text-subtle transition-colors hover:text-foreground sm:block"
          >
            sign in
          </Link>
          <PillLink to="/dashboard" className="px-4 py-2">
            try the demo
          </PillLink>
        </div>
      </div>
    </header>
  );
}

/* ---------------------------------- hero ----------------------------------- */

const heroTerminal = [
  { text: "$ secureloop scan github.com/you/vulnshop-api", tone: "fg" },
  { text: "▸ cloning @ 3fa9c21 into ephemeral workspace… done", tone: "dim" },
  { text: "▸ semgrep: 214 rules · 38 files scanned", tone: "warn" },
  { text: "  ✖ routes/users.js:42    sqli   CWE-89   critical", tone: "err" },
  { text: "  ✖ web/ProfileBio.tsx:17 xss    CWE-79   high", tone: "err" },
  { text: "▸ llm: explanations + candidate patches… done", tone: "warn" },
  { text: "▸ sandbox validation", tone: "warn" },
  { text: "  ✓ re-scan clean · ✓ 41/41 tests · ✓ 0 new issues", tone: "ok" },
  { text: "  patch #1 validated — ready for your review", tone: "ok" },
] as const;

function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div className="absolute inset-0 bg-dot-grid opacity-40 [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,black,transparent)]" />
      <div className="relative mx-auto max-w-6xl px-6 pt-24 pb-16 text-center md:pt-32">
        <Eyebrow className="mb-6">closed-loop secure code review</Eyebrow>
        <h1 className="mx-auto max-w-3xl font-display text-4xl font-semibold leading-[1.1] tracking-tight md:text-6xl">
          Ship secure code, not just detected bugs.
        </h1>
        <p className="mx-auto mt-6 max-w-xl text-base leading-relaxed text-subtle">
          SecureLoop scans your repo, explains every vulnerability in plain
          language, writes a candidate patch — and re-scans + re-tests it in an
          isolated sandbox before it ever reaches you.
        </p>
        <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
          <PillLink to="/dashboard">get started</PillLink>
          <PillLink to="/scan/demo" variant="outline">
            try a sample repo
          </PillLink>
        </div>

        <TerminalWindow
          title="secureloop — scan · patch · validate"
          className="mx-auto mt-16 max-w-2xl text-left"
        >
          {heroTerminal.map((l, i) => (
            <div
              key={i}
              className={
                l.tone === "err"
                  ? "text-danger"
                  : l.tone === "ok"
                    ? "text-success"
                    : l.tone === "warn"
                      ? "text-accent"
                      : l.tone === "dim"
                        ? "text-subtle"
                        : "text-foreground"
              }
            >
              {l.text}
            </div>
          ))}
        </TerminalWindow>
      </div>
    </section>
  );
}

/* ------------------------------- trust strip ------------------------------- */

function TrustStrip() {
  const items = ["Semgrep", "OWASP ZAP", "Gemini", "Docker sandboxes", "GitHub"];
  return (
    <section className="border-y border-border">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <Eyebrow className="text-center">scans powered by</Eyebrow>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-x-12 gap-y-4">
          {items.map((name) => (
            <span
              key={name}
              className="font-mono text-sm font-medium tracking-wide text-subtle/70"
            >
              {name}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* --------------------------- 3-col pipeline grid --------------------------- */

const pipelineFeatures = [
  {
    icon: ScanSearch,
    title: "Detect with Semgrep + ZAP",
    desc: "Static analysis across your codebase, plus baseline DAST when the repo runs a web app. SQLi, XSS, CSRF, insecure deserialization.",
  },
  {
    icon: BrainCircuit,
    title: "Explained in plain language",
    desc: "Every finding gets a structured explanation: what it is, the root cause, its OWASP category, and how the fix works.",
  },
  {
    icon: FileText,
    title: "Patched as a unified diff",
    desc: "The LLM sees the whole function, the CWE, and your tests — and outputs a reviewable diff, never a silent rewrite.",
  },
];

function PipelineGrid() {
  return (
    <section id="pipeline" className="mx-auto max-w-6xl px-6 py-24">
      <Eyebrow>01 // the pipeline</Eyebrow>
      <h2 className="mt-4 max-w-2xl font-display text-3xl font-semibold tracking-tight md:text-4xl">
        Ship your whole backlog of findings, not one prompt at a time.
      </h2>
      <div className="mt-12 grid gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-3">
        {pipelineFeatures.map((f) => (
          <div key={f.title} className="bg-elevated p-7">
            <f.icon className="size-5 text-accent" strokeWidth={1.5} />
            <h3 className="mt-5 font-mono text-sm font-semibold">{f.title}</h3>
            <p className="mt-2 text-sm leading-relaxed text-subtle">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ------------------------- validate (hero feature) ------------------------- */

function ValidateSection() {
  return (
    <section id="validate" className="border-t border-border">
      <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-24 md:grid-cols-2">
        <div>
          <Eyebrow>02 // validated, not vibes</Eyebrow>
          <h2 className="mt-4 font-display text-3xl font-semibold tracking-tight md:text-4xl">
            Every patch is re-scanned and re-tested before you ever see it.
          </h2>
          <p className="mt-5 leading-relaxed text-subtle">
            LLMs write plausible-looking patches that often don't fix the bug,
            break tests, or introduce new issues. SecureLoop applies each diff
            inside an ephemeral Docker sandbox, re-runs Semgrep on the changed
            files, and runs your test suite. A patch only reaches your review
            queue when the original rule no longer fires, no new findings
            appear, and the tests stay green.
          </p>
          <div className="mt-7 flex flex-wrap items-center gap-2 font-mono text-[11px]">
            {["detected", "explained", "patch_generated", "validating", "validated"].map(
              (s, i, arr) => (
                <span key={s} className="flex items-center gap-2">
                  <span className="rounded-full border border-border px-3 py-1 text-subtle">
                    {s}
                  </span>
                  {i < arr.length - 1 && (
                    <ArrowRight className="size-3 text-subtle/50" />
                  )}
                </span>
              ),
            )}
          </div>
        </div>
        <TerminalWindow title="validation — patch-8f2c1">
          <div className="text-subtle">$ secureloop validate patch-8f2c1</div>
          <div className="text-accent">▸ ephemeral container spun up (node:20)</div>
          <div className="text-accent">▸ applying diff… clean apply</div>
          <div className="text-foreground/80">▸ semgrep --rule javascript.express.sql-injection</div>
          <div className="text-success">  ✓ original rule no longer fires</div>
          <div className="text-foreground/80">▸ semgrep full pack on changed files</div>
          <div className="text-success">  ✓ 0 new findings introduced</div>
          <div className="text-foreground/80">▸ npm test</div>
          <div className="text-success">  ✓ 41 passed, 0 failed</div>
          <div className="mt-2 border-t border-border pt-2 text-success">
            verdict: ACCEPTED — ready for developer review
          </div>
        </TerminalWindow>
      </div>
    </section>
  );
}

/* --------------------------------- learn ----------------------------------- */

function LearnSection() {
  return (
    <section id="learn" className="border-t border-border">
      <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-24 md:grid-cols-2">
        <TerminalWindow title="education check — sqli" className="order-2 md:order-1">
          <div className="text-subtle">// quick check before the fix lands</div>
          <div className="mt-3 text-foreground">
            Why do parameterized queries prevent SQL injection?
          </div>
          <div className="mt-3 space-y-1.5">
            <div className="text-subtle">  a) they encrypt the input</div>
            <div className="text-success">
              [32m  b) the query is parsed before data is bound ✓ correct
            </div>
            <div className="text-subtle">  c) they strip all quotes</div>
          </div>
          <div className="mt-4 border-t border-border pt-3">
            <span className="text-subtle">security score</span>{" "}
            <span className="text-foreground">sqli</span>{" "}
            <span className="text-success">85 → 92</span>{" "}
            <span className="text-subtle">· overall</span>{" "}
            <span className="text-success">68 → 72</span>
          </div>
        </TerminalWindow>
        <div className="order-1 md:order-2">
          <Eyebrow>03 // learn as you fix</Eyebrow>
          <h2 className="mt-4 font-display text-3xl font-semibold tracking-tight md:text-4xl">
            Fixes that teach, not fixes that hide.
          </h2>
          <p className="mt-5 leading-relaxed text-subtle">
            Every accepted or rejected patch ends with a 60-second interactive
            check on the vulnerability class you just touched. Answers feed a
            per-category security score — SQLi, XSS, CSRF, deserialization — so
            you can watch your secure-coding instincts trend upward, and export
            the data for your team.
          </p>
          <div className="mt-7">
            <PillLink to="/score" variant="outline">
              see the score dashboard
            </PillLink>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------- comparison -------------------------------- */

const comparison = [
  { approach: "Semgrep only", detect: true, explain: false, patch: false, validate: "—" },
  { approach: "LLM only", detect: true, explain: true, patch: true, validate: "✗" },
  { approach: "Semgrep + LLM", detect: true, explain: true, patch: true, validate: "partial" },
  { approach: "SecureLoop", detect: true, explain: true, patch: true, validate: "✓", highlight: true },
];

function ComparisonSection() {
  return (
    <section className="border-t border-border">
      <div className="mx-auto max-w-6xl px-6 py-24">
        <Eyebrow>04 // why the loop matters</Eyebrow>
        <h2 className="mt-4 max-w-2xl font-display text-3xl font-semibold tracking-tight md:text-4xl">
          Detection is table stakes. Validation is the product.
        </h2>
        <div className="mt-12 overflow-hidden rounded-lg border border-border">
          <table className="w-full font-mono text-xs">
            <thead>
              <tr className="border-b border-border bg-elevated text-left text-subtle">
                <th className="px-5 py-3.5 font-medium uppercase tracking-wider">approach</th>
                <th className="px-5 py-3.5 font-medium uppercase tracking-wider">detect</th>
                <th className="px-5 py-3.5 font-medium uppercase tracking-wider">explain</th>
                <th className="px-5 py-3.5 font-medium uppercase tracking-wider">patch</th>
                <th className="px-5 py-3.5 font-medium uppercase tracking-wider">validate</th>
              </tr>
            </thead>
            <tbody>
              {comparison.map((row) => (
                <tr
                  key={row.approach}
                  className={
                    row.highlight
                      ? "bg-elevated text-foreground"
                      : "border-b border-border text-subtle"
                  }
                >
                  <td className="px-5 py-3.5">
                    {row.highlight && (
                      <span className="mr-2 inline-block size-1.5 rounded-full bg-accent align-middle" />
                    )}
                    {row.approach}
                  </td>
                  <td className="px-5 py-3.5">{row.detect ? "✓" : "✗"}</td>
                  <td className="px-5 py-3.5">{row.explain ? "✓" : "✗"}</td>
                  <td className="px-5 py-3.5">{row.patch ? "✓" : "✗"}</td>
                  <td
                    className={
                      row.validate === "✓"
                        ? "px-5 py-3.5 text-success"
                        : "px-5 py-3.5"
                    }
                  >
                    {row.validate}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-4 font-mono text-[11px] text-subtle">
          every secureloop run logs detection, patch-success, and acceptance
          metrics — exportable for your own evaluation.
        </p>
      </div>
    </section>
  );
}

/* ------------------------------- secondary --------------------------------- */

const secondaryFeatures = [
  {
    icon: KeyRound,
    title: "Secrets never leave",
    desc: ".env files, tokens, and credentials are stripped before any code reaches the LLM — and never land in logs.",
  },
  {
    icon: GitPullRequest,
    title: "One-click pull requests",
    desc: "Accepted patches push to an isolated branch and open a PR via the GitHub API.",
  },
  {
    icon: ListChecks,
    title: "Audit trail",
    desc: "Every accept, reject, and override is logged with its validation evidence.",
  },
  {
    icon: GraduationCap,
    title: "Education checks",
    desc: "Micro-quizzes tied to each vulnerability class keep the knowledge from the fix.",
  },
  {
    icon: FlaskConical,
    title: "Sample repo mode",
    desc: "Demo the whole loop on a bundled vulnerable fixture — no GitHub account needed.",
  },
  {
    icon: FileText,
    title: "PDF reports",
    desc: "Download a per-scan vulnerability report with findings, patches, and validation verdicts.",
  },
];

function Testimonials() {
  return (
    <section className="border-t border-border">
      <div className="mx-auto max-w-6xl px-6 py-24">
        <Eyebrow>05 // and everything around it</Eyebrow>
        <h2 className="mt-4 max-w-2xl font-display text-3xl font-semibold tracking-tight md:text-4xl">
          Built for real repos, not happy paths.
        </h2>
        <div className="mt-12 grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 lg:grid-cols-3">
          {secondaryFeatures.map((f) => (
            <div key={f.title} className="bg-elevated p-7">
              <f.icon className="size-5 text-accent" strokeWidth={1.5} />
              <h3 className="mt-5 font-mono text-sm font-semibold">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-subtle">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------------------------- faq ------------------------------------ */

const faqs = [
  {
    q: "How is this different from Copilot Autofix or Semgrep Autofix?",
    a: "Those tools generate patches and trust them. SecureLoop treats every LLM patch as a candidate: it is applied in an ephemeral sandbox, re-scanned with the rule that fired, checked for newly introduced findings, and run against your test suite. Only patches that pass all checks reach your review queue — rejected ones are shown with the exact failing check, never silently shipped.",
  },
  {
    q: "Do you train on my code?",
    a: "No. Code context is sent to the LLM only to generate an explanation or patch for that finding, with secrets and credentials stripped first. Nothing is retained for training, and every prompt is audit-logged.",
  },
  {
    q: "What languages and vulnerability classes are supported?",
    a: "Anything Semgrep can parse — JavaScript/TypeScript, Python, Go, Java, and more. At launch SecureLoop targets four classes end-to-end: SQL injection, XSS, CSRF, and insecure deserialization, each with its own patch strategy and education track.",
  },
  {
    q: "Is my repo ever sent anywhere insecure?",
    a: "Your repo is cloned into an ephemeral, isolated workspace that is destroyed after validation. Patches are never applied to your working copy. Web-facing repos get an OWASP ZAP baseline scan against the sandboxed instance, not your production deployment.",
  },
  {
    q: "What happens when a patch fails validation?",
    a: "It's labeled clearly with the failing condition — vulnerability still present, tests broken, or new findings introduced — and it can't be one-click accepted. An explicit override exists for transparency, and overrides are logged separately as their own metric.",
  },
];

function Faq() {
  const [open, setOpen] = useState<number | null>(0);
  return (
    <section id="faq" className="border-t border-border">
      <div className="mx-auto max-w-3xl px-6 py-24">
        <Eyebrow>06 // faq</Eyebrow>
        <h2 className="mt-4 font-display text-3xl font-semibold tracking-tight md:text-4xl">
          Frequently asked questions
        </h2>
        <div className="mt-10">
          {faqs.map((f, i) => (
            <div key={f.q} className="border-b border-border">
              <button
                onClick={() => setOpen(open === i ? null : i)}
                className="flex w-full cursor-pointer items-center justify-between py-5 text-left"
              >
                <span className="pr-6 text-sm font-medium">{f.q}</span>
                {open === i ? (
                  <Minus className="size-4 shrink-0 text-subtle" />
                ) : (
                  <Plus className="size-4 shrink-0 text-subtle" />
                )}
              </button>
              {open === i && (
                <p className="pb-6 text-sm leading-relaxed text-subtle">{f.a}</p>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------- footer cta -------------------------------- */

function FooterCta() {
  return (
    <section className="relative overflow-hidden border-t border-border">
      <div className="absolute inset-0 bg-dot-grid opacity-40 [mask-image:radial-gradient(ellipse_50%_60%_at_50%_50%,black,transparent)]" />
      <div className="relative mx-auto max-w-6xl px-6 py-28 text-center">
        <h2 className="font-display text-3xl font-semibold tracking-tight md:text-5xl">
          Try SecureLoop now.
        </h2>
        <p className="mx-auto mt-4 max-w-md text-sm leading-relaxed text-subtle">
          Run the full loop — scan, explain, patch, validate — on the bundled
          vulnerable sample repo. No account required.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <PillLink to="/dashboard">get started</PillLink>
          <PillLink to="/scan/demo" variant="outline">
            scan the sample repo
          </PillLink>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  const cols: { title: string; links: string[] }[] = [
    { title: "product", links: ["pipeline", "validation", "education", "pricing"] },
    { title: "resources", links: ["documentation", "sample repo", "owasp top 10", "changelog"] },
    { title: "company", links: ["about", "research notes", "contact"] },
    { title: "legal", links: ["privacy", "terms", "security"] },
  ];
  return (
    <footer className="border-t border-border">
      <div className="mx-auto max-w-6xl px-6 py-14">
        <div className="flex flex-col justify-between gap-10 md:flex-row">
          <div>
            <Logo />
            <p className="mt-4 max-w-xs font-mono text-[11px] leading-relaxed text-subtle">
              detect → explain → patch → validate → learn
            </p>
          </div>
          <div className="grid grid-cols-2 gap-10 sm:grid-cols-4">
            {cols.map((c) => (
              <div key={c.title}>
                <p className="font-mono text-[11px] uppercase tracking-wider text-subtle">
                  {c.title}
                </p>
                <ul className="mt-4 space-y-2.5">
                  {c.links.map((l) => (
                    <li key={l}>
                      <span className="cursor-pointer text-sm text-subtle transition-colors hover:text-foreground">
                        {l}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-12 flex items-center justify-between border-t border-border pt-6 font-mono text-[11px] text-subtle">
          <span>© 2026 secureloop</span>
          <span className="flex items-center gap-2">
            <ShieldCheck className="size-3.5" /> all systems validated
          </span>
        </div>
      </div>
    </footer>
  );
}
