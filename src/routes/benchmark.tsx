import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  XCircle,
  Download,
  Info,
  ExternalLink,
  RefreshCw,
  Check,
  ShieldCheck,
  Layers,
} from "lucide-react";
import { Logo } from "@/components/chrome";
import { runBenchmark, type BenchmarkSummary, type SampleResult } from "@/lib/benchmark-runner";
import { supabase } from "@/lib/supabase";

export const Route = createFileRoute("/benchmark")({
  head: () => ({
    meta: [
      { title: "Benchmark & Evaluation — SecureLoop" },
      {
        name: "description",
        content:
          "Empirical benchmark evaluation on 50 real OWASP datasets with honest metrics and confidence intervals.",
      },
    ],
  }),
  component: BenchmarkPage,
});

interface ManualComparisonRow {
  sampleId: string;
  name: string;
  vulnClass: string;
  cwe: string;
  secureloopDetected: boolean;
  secureloopPatchValid: boolean | null;
  copilotDetected: string;
  copilotPatchValid: string;
  copilotNotes: string;
  snykDetected: string;
  snykPatchValid: string;
  snykNotes: string;
}

function BenchmarkPage() {
  const [manualFPs, setManualFPs] = useState<Record<string, boolean>>({});
  const [lastRunTime, setLastRunTime] = useState<string>(new Date().toLocaleTimeString());
  const [activeTab, setActiveTab] = useState<"results" | "classes" | "comparison">("results");
  const [scopeFilter, setScopeFilter] = useState<"all" | "inScope">("all");
  const [dbSuppressionCount, setDbSuppressionCount] = useState<number | null>(null);
  const [runKey, setRunKey] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [runNotification, setRunNotification] = useState<string | null>(null);

  useEffect(() => {
    async function loadSuppressionStats() {
      const { count } = await supabase
        .from("false_positive_suppressions")
        .select("*", { count: "exact", head: true });
      if (typeof count === "number") {
        setDbSuppressionCount(count);
      }
    }
    loadSuppressionStats();
  }, []);

  // Run benchmark dynamically with current manual FP overrides and run trigger
  const summary: BenchmarkSummary = useMemo(() => {
    return runBenchmark(manualFPs);
  }, [manualFPs, runKey]);

  // Selected scope metrics based on filter (B5)
  const currentScope = scopeFilter === "inScope" ? summary.inScope : summary;

  // Comparison table state (loaded with default template placeholders)
  const [comparisonRows, setComparisonRows] = useState<ManualComparisonRow[]>(() =>
    summary.sampleResults.map((s) => ({
      sampleId: s.sampleId,
      name: s.name,
      vulnClass: s.vulnClass,
      cwe: s.cwe,
      secureloopDetected: s.detected,
      secureloopPatchValid: s.patchValid,
      copilotDetected: "Pending manual evaluation",
      copilotPatchValid: "Pending manual evaluation",
      copilotNotes: "Manual entry pending",
      snykDetected: "Pending manual evaluation",
      snykPatchValid: "Pending manual evaluation",
      snykNotes: "Manual entry pending",
    })),
  );

  function handleToggleFP(sampleId: string) {
    setManualFPs((prev) => ({
      ...prev,
      [sampleId]: !prev[sampleId],
    }));
  }

  async function handleReRun() {
    setIsRunning(true);
    setRunNotification(null);

    await new Promise((resolve) => setTimeout(resolve, 350));

    setRunKey((k) => k + 1);
    const now = new Date().toLocaleTimeString();
    setLastRunTime(now);
    setIsRunning(false);
    setRunNotification(
      `Benchmark re-run complete: ${summary.totalSamples} samples evaluated at ${now}`,
    );
    setTimeout(() => setRunNotification(null), 3500);
  }

  function handleDownloadCSV() {
    const headers =
      "sample_id,sample_name,vuln_class,cwe,language,label,source_repo_url,commit_sha,detected,matched_rule,patch_valid,runtime_ms,copilot_status,snyk_status\n";
    const rows = summary.sampleResults
      .map((s) => {
        const patchStr = s.patchValid === null ? "n/a" : s.patchValid ? "valid" : "rejected";
        return `"${s.sampleId}","${s.name}","${s.vulnClass}","${s.cwe}","${s.language}","${
          s.isVulnerable ? "vulnerable" : "safe_control"
        }","${s.source_repo_url || ""}","${s.commit_sha || ""}",${s.detected},"${
          s.matchedRule || ""
        }",${patchStr},${s.runtimeMs},"Pending manual evaluation","Pending manual evaluation"`;
      })
      .join("\n");

    const blob = new Blob([headers + rows], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `secureloop-benchmark-50samples-${summary.metadata.date}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  const displayedSamples = useMemo(() => {
    if (scopeFilter === "inScope") {
      return summary.sampleResults.filter(
        (s) => s.language === "javascript" || s.language === "typescript",
      );
    }
    return summary.sampleResults;
  }, [summary.sampleResults, scopeFilter]);

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
          <Logo />
          <div className="flex items-center gap-3">
            <Link
              to="/dashboard"
              className="flex items-center gap-2 font-mono text-xs text-subtle hover:text-foreground"
            >
              <ArrowLeft className="size-3" />
              dashboard
            </Link>
            <Link
              to="/learn"
              className="pill-hover inline-flex items-center gap-2 rounded-full border border-border bg-elevated px-3 py-1.5 font-mono text-[11px] text-subtle hover:text-foreground"
            >
              learning hub
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10 space-y-8">
        {/* Title & Metadata Line (B8) */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              Review 3 · Empirical Evaluation (Part B)
            </p>
            <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight text-foreground">
              SAST & Patch Validation Benchmark
            </h1>
            {/* Visible metadata line: N samples, commit SHA, date, provider/model */}
            <p className="mt-1.5 font-mono text-xs text-accent">
              <span className="font-semibold">{summary.metadata.sampleCount} real samples</span>
              <span className="text-subtle"> · </span>
              <span className="text-foreground/80">commit {summary.metadata.commitSha}</span>
              <span className="text-subtle"> · </span>
              <span className="text-foreground/80">{summary.metadata.date}</span>
              <span className="text-subtle"> · </span>
              <span className="text-subtle">{summary.metadata.model}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleReRun}
              disabled={isRunning}
              className="pill-hover flex items-center gap-2 rounded-full border border-border bg-elevated px-4 py-2 font-mono text-xs text-foreground cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`size-3 text-accent ${isRunning ? "animate-spin" : ""}`} />
              {isRunning ? "running benchmark…" : "re-run benchmark"}
            </button>
            <button
              onClick={handleDownloadCSV}
              className="pill-hover flex items-center gap-2 rounded-full border border-border bg-elevated px-4 py-2 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
            >
              <Download className="size-3" />
              export CSV
            </button>
          </div>
        </div>

        {/* Scope Selector Filter (B5) */}
        <div className="flex items-center justify-between border-b border-border/80 pb-3">
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-subtle">Scope Filter:</span>
            <button
              onClick={() => setScopeFilter("all")}
              className={`rounded-full px-3 py-1 cursor-pointer transition-colors ${
                scopeFilter === "all"
                  ? "bg-accent/20 border border-accent/40 text-accent font-semibold"
                  : "border border-border bg-elevated text-subtle hover:text-foreground"
              }`}
            >
              All Languages ({summary.totalSamples})
            </button>
            <button
              onClick={() => setScopeFilter("inScope")}
              className={`rounded-full px-3 py-1 cursor-pointer transition-colors ${
                scopeFilter === "inScope"
                  ? "bg-accent/20 border border-accent/40 text-accent font-semibold"
                  : "border border-border bg-elevated text-subtle hover:text-foreground"
              }`}
            >
              In-Scope JS/TS ({summary.inScope.totalSamples})
            </button>
            {scopeFilter === "all" && summary.outOfScope.totalSamples > 0 && (
              <span className="text-[11px] text-subtle">
                (includes {summary.outOfScope.totalSamples} Java/Python out-of-scope samples)
              </span>
            )}
          </div>
          <div className="font-mono text-[11px] text-subtle">
            {isRunning ? "evaluating samples…" : `last executed in ${summary.totalRuntimeMs}ms`}
          </div>
        </div>

        {/* Re-run Notification */}
        {runNotification && (
          <div className="rounded-lg border border-success/30 bg-success/10 px-4 py-2.5 font-mono text-xs text-success flex items-center gap-2 transition-all animate-fadeIn">
            <Check className="size-3.5 shrink-0" />
            <span>{runNotification}</span>
          </div>
        )}

        {/* Primary Metrics Cards with Wilson CIs (B7) */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Recall */}
          <div className="rounded-xl border border-border bg-elevated p-5">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              detection rate (recall)
            </p>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-display text-3xl font-bold text-foreground">
                {currentScope.recall}%
              </span>
              <span className="font-mono text-xs text-subtle">
                ({currentScope.truePositives}/{currentScope.vulnerableCount})
              </span>
            </div>
            <p className="mt-1 font-mono text-[10px] text-subtle/80">
              TP / (TP + FN) · 95% Wilson CI: [{currentScope.recallWilson.lower}% –{" "}
              {currentScope.recallWilson.upper}%]
            </p>
          </div>

          {/* Card 2: FPR */}
          <div className="rounded-xl border border-border bg-elevated p-5">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              false positive rate
            </p>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-display text-3xl font-bold text-warning">
                {currentScope.falsePositiveRate}%
              </span>
              <span className="font-mono text-xs text-subtle">
                ({currentScope.falsePositives}/{currentScope.safeControlCount})
              </span>
            </div>
            <p className="mt-1 font-mono text-[10px] text-subtle/80">
              FP / (FP + TN) · 95% Wilson CI: [{currentScope.fprWilson.lower}% –{" "}
              {currentScope.fprWilson.upper}%]
            </p>
            {dbSuppressionCount !== null && dbSuppressionCount > 0 && (
              <p className="mt-2 font-mono text-[10px] text-warning/90 border-t border-border/60 pt-1.5">
                + {dbSuppressionCount} real scan false-positive(s) suppressed in app
              </p>
            )}
          </div>

          {/* Card 3: Patch Pass Rate (Primary & Secondary) */}
          <div className="rounded-xl border border-border bg-elevated p-5">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              patch validation rate
            </p>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-display text-3xl font-bold text-success">
                {currentScope.patchPassRateDetected}%
              </span>
              <span className="font-mono text-[11px] text-subtle">on detected</span>
            </div>
            <p className="mt-1 font-mono text-[10px] text-subtle/80">
              Secondary: {currentScope.patchPassRateAll}% across all vulnerable samples
            </p>
          </div>

          {/* Card 4: Repair Progression */}
          <div className="rounded-xl border border-border bg-elevated p-5">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              repair progression
            </p>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-display text-3xl font-bold text-foreground">
                {summary.afterRepairPassRate}%
              </span>
              <span className="font-mono text-[11px] text-subtle">after repair</span>
            </div>
            <p className="mt-1 font-mono text-[10px] text-subtle/80">
              1st attempt: {summary.firstAttemptPassRate}% (max 2 retries)
            </p>
          </div>
        </div>

        {/* Confusion Matrix & Class Breakdown Section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Confusion Matrix Card (B7) */}
          <div className="rounded-xl border border-border bg-elevated p-5 space-y-3">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle flex items-center gap-1.5">
              <Layers className="size-3 text-accent" />
              Confusion Matrix ({summary.totalSamples} samples)
            </p>
            <div className="grid grid-cols-2 gap-2 text-center font-mono text-xs">
              <div className="rounded-lg border border-success/30 bg-success/10 p-2.5">
                <div className="text-[10px] text-success/80 font-medium">True Positives (TP)</div>
                <div className="text-xl font-bold text-success mt-0.5">
                  {summary.confusionMatrix.tp}
                </div>
              </div>
              <div className="rounded-lg border border-danger/30 bg-danger/10 p-2.5">
                <div className="text-[10px] text-danger/80 font-medium">False Negatives (FN)</div>
                <div className="text-xl font-bold text-danger mt-0.5">
                  {summary.confusionMatrix.fn}
                </div>
              </div>
              <div className="rounded-lg border border-warning/30 bg-warning/10 p-2.5">
                <div className="text-[10px] text-warning/80 font-medium">False Positives (FP)</div>
                <div className="text-xl font-bold text-warning mt-0.5">
                  {summary.confusionMatrix.fp}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-background p-2.5">
                <div className="text-[10px] text-subtle font-medium">True Negatives (TN)</div>
                <div className="text-xl font-bold text-foreground mt-0.5">
                  {summary.confusionMatrix.tn}
                </div>
              </div>
            </div>
          </div>

          {/* Dataset Balance Card */}
          <div className="md:col-span-2 rounded-xl border border-border bg-elevated p-5 space-y-3">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle flex items-center gap-1.5">
              <ShieldCheck className="size-3 text-accent" />
              Dataset Balance (B1: 30 Vulnerable + 20 Safe Controls)
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center font-mono text-xs">
              {Object.entries(summary.perClass).map(([className, m]) => (
                <div key={className} className="rounded-lg border border-border bg-background p-2">
                  <div className="text-[10px] text-subtle uppercase truncate">{className}</div>
                  <div className="text-base font-bold text-foreground mt-0.5">
                    {m.vulnerable}v / {m.safeControls}s
                  </div>
                  <div className="text-[10px] text-accent mt-0.5">Recall: {m.recall}%</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-border gap-6">
          <button
            onClick={() => setActiveTab("results")}
            className={`pb-3 font-mono text-xs cursor-pointer transition-colors border-b-2 -mb-px ${
              activeTab === "results"
                ? "border-accent text-foreground font-semibold"
                : "border-transparent text-subtle hover:text-foreground"
            }`}
          >
            Sample Results & Source Links ({displayedSamples.length})
          </button>
          <button
            onClick={() => setActiveTab("classes")}
            className={`pb-3 font-mono text-xs cursor-pointer transition-colors border-b-2 -mb-px ${
              activeTab === "classes"
                ? "border-accent text-foreground font-semibold"
                : "border-transparent text-subtle hover:text-foreground"
            }`}
          >
            Per-Class Breakdown Table
          </button>
          <button
            onClick={() => setActiveTab("comparison")}
            className={`pb-3 font-mono text-xs cursor-pointer transition-colors border-b-2 -mb-px ${
              activeTab === "comparison"
                ? "border-accent text-foreground font-semibold"
                : "border-transparent text-subtle hover:text-foreground"
            }`}
          >
            Copilot Autofix & Snyk Comparison Table
          </button>
        </div>

        {/* Tab 1: Benchmark Results Table */}
        {activeTab === "results" && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs font-mono text-subtle">
              <Info className="size-3.5 text-accent" />
              <span>
                All 50 samples are real code from public open-source projects. Click &ldquo;mark
                FP&rdquo; to test dynamic false-positive recalculation.
              </span>
            </div>

            <div className="overflow-x-auto rounded-xl border border-border bg-elevated">
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b border-border bg-background text-left text-subtle">
                    <th className="px-4 py-3 font-medium">sample & source</th>
                    <th className="px-4 py-3 font-medium">class</th>
                    <th className="px-4 py-3 font-medium">lang</th>
                    <th className="px-4 py-3 font-medium">truth</th>
                    <th className="px-4 py-3 font-medium">detected</th>
                    <th className="px-4 py-3 font-medium">patch valid</th>
                    <th className="px-4 py-3 font-medium">time</th>
                    <th className="px-4 py-3 font-medium text-right">action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {displayedSamples.map((s) => {
                    const isManual = manualFPs[s.sampleId] ?? false;
                    return (
                      <tr key={s.sampleId} className={isManual ? "bg-warning/5" : ""}>
                        <td className="px-4 py-3 max-w-sm">
                          <p className="font-semibold text-foreground">{s.name}</p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] text-subtle/70">{s.sampleId}</span>
                            {s.source_repo_url && (
                              <a
                                href={s.source_repo_url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-0.5 text-[10px] text-accent hover:underline"
                              >
                                source <ExternalLink className="size-2.5" />
                              </a>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-foreground uppercase">{s.vulnClass}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] ${
                              s.language === "javascript" || s.language === "typescript"
                                ? "bg-accent/10 text-accent border border-accent/20"
                                : "bg-warning/10 text-warning border border-warning/20"
                            }`}
                          >
                            {s.language}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {s.isVulnerable ? (
                            <span className="text-danger font-semibold">vulnerable</span>
                          ) : (
                            <span className="text-success font-medium">safe control</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {s.detected ? (
                            <span className="text-success inline-flex items-center gap-1 font-semibold">
                              <CheckCircle2 className="size-3" /> yes
                            </span>
                          ) : (
                            <span className="text-subtle inline-flex items-center gap-1">
                              <XCircle className="size-3" /> no
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {s.patchValid === null ? (
                            <span className="text-subtle/50">n/a</span>
                          ) : s.patchValid ? (
                            <span className="text-success font-semibold">PASS</span>
                          ) : (
                            <span className="text-danger font-semibold">FAIL</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-subtle">{s.runtimeMs}ms</td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => handleToggleFP(s.sampleId)}
                            className={`px-2.5 py-1 rounded text-[10px] font-mono border cursor-pointer transition-colors ${
                              isManual
                                ? "border-warning bg-warning/20 text-warning font-semibold"
                                : "border-border bg-background text-subtle hover:text-foreground"
                            }`}
                          >
                            {isManual ? "flagged FP ✓" : "mark FP"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 2: Per-Class Table (B7) */}
        {activeTab === "classes" && (
          <div className="overflow-x-auto rounded-xl border border-border bg-elevated">
            <table className="w-full font-mono text-xs">
              <thead>
                <tr className="border-b border-border bg-background text-left text-subtle">
                  <th className="px-4 py-3 font-medium">vulnerability class</th>
                  <th className="px-4 py-3 font-medium text-center">total</th>
                  <th className="px-4 py-3 font-medium text-center">vuln / safe</th>
                  <th className="px-4 py-3 font-medium text-center">TP</th>
                  <th className="px-4 py-3 font-medium text-center">FN</th>
                  <th className="px-4 py-3 font-medium text-center">FP</th>
                  <th className="px-4 py-3 font-medium text-center">TN</th>
                  <th className="px-4 py-3 font-medium text-right">recall</th>
                  <th className="px-4 py-3 font-medium text-right">FPR</th>
                  <th className="px-4 py-3 font-medium text-right">patch pass</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {Object.entries(summary.perClass).map(([className, m]) => (
                  <tr key={className}>
                    <td className="px-4 py-3 font-semibold text-foreground uppercase">
                      {className}
                    </td>
                    <td className="px-4 py-3 text-center">{m.total}</td>
                    <td className="px-4 py-3 text-center text-subtle">
                      {m.vulnerable} / {m.safeControls}
                    </td>
                    <td className="px-4 py-3 text-center text-success font-semibold">{m.truePositives}</td>
                    <td className="px-4 py-3 text-center text-danger">{m.falseNegatives}</td>
                    <td className="px-4 py-3 text-center text-warning">{m.falsePositives}</td>
                    <td className="px-4 py-3 text-center text-subtle">{m.trueNegatives}</td>
                    <td className="px-4 py-3 text-right font-semibold text-foreground">
                      {m.recall}%
                    </td>
                    <td className="px-4 py-3 text-right text-warning">{m.falsePositiveRate}%</td>
                    <td className="px-4 py-3 text-right text-success font-semibold">
                      {m.patchPassRate}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 3: Comparison with Copilot Autofix and Snyk (B8) */}
        {activeTab === "comparison" && (
          <div className="space-y-4">
            <div className="rounded-lg border border-border bg-elevated p-4 font-mono text-xs text-subtle leading-relaxed">
              <p className="font-semibold text-foreground mb-1">
                Note on Third-Party Tools (Copilot Autofix & Snyk Code):
              </p>
              <p>
                GitHub Copilot Autofix and Snyk Code cannot be invoked programmatically from
                external browser sessions. All fields remain marked as &ldquo;Pending manual
                evaluation&rdquo; to preserve measurement honesty. Export as CSV to record manual
                review results.
              </p>
            </div>

            <div className="overflow-x-auto rounded-xl border border-border bg-elevated">
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b border-border bg-background text-left text-subtle">
                    <th className="px-4 py-3 font-medium">sample</th>
                    <th className="px-4 py-3 font-medium">SecureLoop</th>
                    <th className="px-4 py-3 font-medium">Copilot Autofix</th>
                    <th className="px-4 py-3 font-medium">Snyk Code</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {comparisonRows.map((r, i) => (
                    <tr key={r.sampleId}>
                      <td className="px-4 py-3.5 max-w-xs">
                        <p className="font-semibold text-foreground">{r.name}</p>
                        <p className="text-[10px] text-subtle">
                          {r.vulnClass.toUpperCase()} · {r.cwe}
                        </p>
                      </td>
                      <td className="px-4 py-3.5">
                        <span
                          className={
                            r.secureloopDetected ? "text-success font-semibold" : "text-subtle"
                          }
                        >
                          Detected: {r.secureloopDetected ? "YES" : "NO"}
                        </span>
                        <div className="text-[10px] text-subtle mt-0.5">
                          Patch:{" "}
                          {r.secureloopPatchValid === null
                            ? "n/a"
                            : r.secureloopPatchValid
                              ? "VALIDATED"
                              : "REJECTED"}
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <input
                          type="text"
                          value={r.copilotDetected}
                          onChange={(e) => {
                            const val = e.target.value;
                            setComparisonRows((prev) =>
                              prev.map((row, idx) =>
                                idx === i ? { ...row, copilotDetected: val } : row,
                              ),
                            );
                          }}
                          className="w-full rounded border border-border bg-background px-2 py-1 text-[11px] text-subtle focus:text-foreground focus:border-accent/40 focus:outline-none"
                        />
                      </td>
                      <td className="px-4 py-3.5">
                        <input
                          type="text"
                          value={r.snykDetected}
                          onChange={(e) => {
                            const val = e.target.value;
                            setComparisonRows((prev) =>
                              prev.map((row, idx) =>
                                idx === i ? { ...row, snykDetected: val } : row,
                              ),
                            );
                          }}
                          className="w-full rounded border border-border bg-background px-2 py-1 text-[11px] text-subtle focus:text-foreground focus:border-accent/40 focus:outline-none"
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
