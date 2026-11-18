import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  ArrowLeft,
  Printer,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Brain,
  Clock,
  AlertTriangle,
} from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import {
  supabase,
  type DbFinding,
  type DbProject,
  type DbSecurityScore,
  type DbExplanation,
  type DbPatch,
} from "@/lib/supabase";
import { Logo, SeverityBadge, StatusBadge, DiffView, ScoreBadge } from "@/components/chrome";
import { parseDiff } from "@/lib/types";
import { getAllMasteryProfiles, type MasteryProfileRow } from "@/lib/mastery-db";
import { getRecurringMisconceptions } from "@/lib/misconception";
import { getMasteryLevel } from "@/lib/spaced-repetition";

export const Route = createFileRoute("/report/$projectId")({
  head: () => ({
    meta: [
      { title: "Security Audit & Learning Report — SecureLoop" },
      {
        name: "description",
        content: "Comprehensive security remediation and developer mastery report.",
      },
    ],
  }),
  component: ReportPage,
});

interface EnrichedFinding extends DbFinding {
  explanation?: DbExplanation;
  patch?: DbPatch;
}

function ReportPage() {
  const { projectId } = Route.useParams();
  const navigate = useNavigate();
  const { user, loading } = useAuth();

  const [project, setProject] = useState<DbProject | null>(null);
  const [findings, setFindings] = useState<EnrichedFinding[]>([]);
  const [score, setScore] = useState<DbSecurityScore | null>(null);
  const [mastery, setMastery] = useState<MasteryProfileRow[]>([]);
  const [misconceptions, setMisconceptions] = useState<any[]>([]);
  const [loadingData, setLoadingData] = useState(true);

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user && projectId) loadReportData();
  }, [user, projectId]);

  async function loadReportData() {
    if (!user) return;
    setLoadingData(true);

    try {
      // 1. Fetch project
      const { data: pData } = await supabase
        .from("projects")
        .select("*")
        .eq("id", projectId)
        .single();
      if (pData) setProject(pData);

      // 2. Fetch findings with explanations & patches
      const { data: fData } = await supabase
        .from("findings")
        .select("*, explanations(*), patches(*)")
        .eq("project_id", projectId)
        .order("severity", { ascending: false });

      if (fData) {
        const mapped: EnrichedFinding[] = fData.map((f: any) => ({
          ...f,
          explanation: f.explanations?.[0] ?? undefined,
          patch: f.patches?.[0] ?? undefined,
        }));
        setFindings(mapped);
      }

      // 3. Fetch latest score
      const { data: sData } = await supabase
        .from("security_scores")
        .select("*")
        .eq("project_id", projectId)
        .order("computed_at", { ascending: false })
        .limit(1);

      if (sData?.[0]) setScore(sData[0]);

      // 4. Fetch user mastery & recurring misconceptions
      const [mProfiles, miscData] = await Promise.all([
        getAllMasteryProfiles(user.id),
        getRecurringMisconceptions(user.id),
      ]);

      setMastery(mProfiles);
      setMisconceptions(miscData);
    } catch (err) {
      console.error("Failed to load report data:", err);
    } finally {
      setLoadingData(false);
    }
  }

  function handlePrint() {
    window.print();
  }

  if (loading || loadingData) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">
          generating audit report…
        </span>
      </div>
    );
  }

  const generatedDate = new Date().toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const acceptedCount = findings.filter((f) => f.status === "accepted").length;
  const validatedCount = findings.filter(
    (f) => f.patch?.validation_verdict === "accepted" || f.patch?.validation_vulnerability_gone,
  ).length;
  const suppressedCount = findings.filter(
    (f) =>
      f.status === "dismissed" ||
      f.status === "likely_false_positive" ||
      f.explanation?.likely_false_positive === true,
  ).length;
  const fpRate = findings.length > 0 ? Math.round((suppressedCount / findings.length) * 100) : 0;

  return (
    <div className="min-h-screen bg-background text-foreground print:bg-white print:text-black">
      {/* Top action bar (hidden during print) */}
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur print:hidden">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-6">
          <Logo />
          <div className="flex items-center gap-3">
            <Link
              to="/findings/$projectId"
              params={{ projectId }}
              className="flex items-center gap-1.5 font-mono text-xs text-subtle hover:text-foreground"
            >
              <ArrowLeft className="size-3" />
              back to findings
            </Link>
            <button
              onClick={handlePrint}
              className="pill-hover inline-flex items-center gap-2 rounded-full border border-border bg-elevated px-4 py-1.5 font-mono text-xs text-foreground cursor-pointer shadow-sm"
            >
              <Printer className="size-3 text-accent" />
              print / save as PDF
            </button>
          </div>
        </div>
      </header>

      {/* Main Report Document */}
      <main className="mx-auto max-w-5xl px-8 py-12 space-y-10 print:px-0 print:py-4">
        {/* Document Header */}
        <div className="border-b border-border pb-6 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="size-2 rounded-full bg-accent print:border print:border-black" />
              <span className="font-mono text-xs uppercase tracking-widest text-subtle">
                SecureLoop Security Audit & Remediation Report
              </span>
            </div>
            <h1 className="font-display text-3xl font-bold tracking-tight text-foreground print:text-black">
              {project?.name ?? "Repository Security Audit"}
            </h1>
            <p className="font-mono text-xs text-subtle mt-1 print:text-gray-600">
              Repository: {project?.repo_url || "GitHub Repository"} · Branch:{" "}
              {project?.default_branch || "main"}
            </p>
          </div>

          <div className="text-right font-mono text-xs text-subtle print:text-gray-600">
            <p>
              Auditor / User:{" "}
              <strong className="text-foreground print:text-black">{user?.email}</strong>
            </p>
            <p>
              Generated:{" "}
              <strong className="text-foreground print:text-black">{generatedDate}</strong>
            </p>
          </div>
        </div>

        {/* Executive Summary Metrics */}
        <div>
          <h2 className="font-display text-sm font-semibold uppercase tracking-wider text-subtle mb-3">
            Executive Summary
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="rounded-xl border border-border bg-elevated p-4 print:border-gray-300 print:bg-gray-50">
              <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                security score
              </p>
              <p className="mt-2 font-display text-3xl font-bold text-foreground print:text-black">
                {score?.overall ?? 0}/100
              </p>
            </div>
            <div className="rounded-xl border border-border bg-elevated p-4 print:border-gray-300 print:bg-gray-50">
              <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                total findings
              </p>
              <p className="mt-2 font-display text-3xl font-bold text-foreground print:text-black">
                {findings.length}
              </p>
            </div>
            <div className="rounded-xl border border-border bg-elevated p-4 print:border-gray-300 print:bg-gray-50">
              <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                validated fixes
              </p>
              <p className="mt-2 font-display text-3xl font-bold text-success print:text-black">
                {validatedCount}
              </p>
            </div>
            <div className="rounded-xl border border-border bg-elevated p-4 print:border-gray-300 print:bg-gray-50">
              <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                developer accepted
              </p>
              <p className="mt-2 font-display text-3xl font-bold text-foreground print:text-black">
                {acceptedCount}
              </p>
            </div>
            <div className="rounded-xl border border-border bg-elevated p-4 print:border-gray-300 print:bg-gray-50">
              <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                suppressed / fp rate
              </p>
              <p className="mt-2 font-display text-3xl font-bold text-warning print:text-black">
                {suppressedCount}{" "}
                <span className="text-sm font-normal text-subtle font-mono">({fpRate}%)</span>
              </p>
            </div>
          </div>
        </div>

        {/* Security Score Category Breakdown */}
        {score && (
          <div className="space-y-3">
            <h2 className="font-display text-sm font-semibold uppercase tracking-wider text-subtle">
              Security Score Breakdown
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
              <div className="rounded-lg border border-border bg-elevated p-3 print:border-gray-300 print:bg-gray-50">
                <span className="text-[10px] text-subtle uppercase">SQL Injection</span>
                <p className="font-bold text-base mt-1">{score.sqli}%</p>
              </div>
              <div className="rounded-lg border border-border bg-elevated p-3 print:border-gray-300 print:bg-gray-50">
                <span className="text-[10px] text-subtle uppercase">Cross-Site Scripting</span>
                <p className="font-bold text-base mt-1">{score.xss}%</p>
              </div>
              <div className="rounded-lg border border-border bg-elevated p-3 print:border-gray-300 print:bg-gray-50">
                <span className="text-[10px] text-subtle uppercase">CSRF</span>
                <p className="font-bold text-base mt-1">{score.csrf}%</p>
              </div>
              <div className="rounded-lg border border-border bg-elevated p-3 print:border-gray-300 print:bg-gray-50">
                <span className="text-[10px] text-subtle uppercase">Deserialization</span>
                <p className="font-bold text-base mt-1">{score.deserialization}%</p>
              </div>
            </div>
          </div>
        )}

        {/* Findings Detail List */}
        <div className="space-y-6">
          <h2 className="font-display text-sm font-semibold uppercase tracking-wider text-subtle">
            Vulnerability Findings & Remediations
          </h2>

          {findings.length === 0 ? (
            <div className="rounded-lg border border-border p-6 font-mono text-xs text-subtle">
              No findings recorded for this project.
            </div>
          ) : (
            <div className="space-y-6">
              {findings.map((f, i) => {
                const diffLines = f.patch?.diff ? parseDiff(f.patch.diff) : [];
                const displayStatus =
                  f.status === "accepted"
                    ? "accepted"
                    : f.status === "rejected"
                      ? "rejected"
                      : f.status === "dismissed"
                        ? "dismissed"
                        : f.status === "likely_false_positive"
                          ? "likely_false_positive"
                          : f.patch?.validation_verdict === "rejected"
                            ? "validation_rejected"
                            : f.patch?.validation_verdict === "accepted"
                              ? "validated"
                              : f.status;
                const isHeuristic =
                  f.tool === "gemini-llm-heuristic" || (f as any).source === "llm-heuristic";

                return (
                  <div
                    key={f.id}
                    className="rounded-xl border border-border bg-elevated p-6 space-y-4 print:border-gray-300 print:bg-white print:break-inside-avoid"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold">#{i + 1}</span>
                        <SeverityBadge severity={f.severity} />
                        <span className="font-mono text-xs uppercase tracking-wider text-foreground">
                          {f.vulnerability_class}
                        </span>
                        <span className="font-mono text-xs text-subtle">
                          ({f.cwe || "CWE-Unassigned"})
                        </span>
                      </div>
                      <StatusBadge status={displayStatus} />
                    </div>

                    {isHeuristic && (
                      <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 font-mono text-xs text-amber-300">
                        no deterministic rule, validation is limited
                      </div>
                    )}

                    <div className="font-mono text-xs space-y-1">
                      <p>
                        <span className="text-subtle">File Location:</span>{" "}
                        <strong className="text-foreground">
                          {f.file_path}:{f.line_start || 1}
                        </strong>
                      </p>
                      {f.raw_message && (
                        <p className="text-subtle/90 leading-relaxed mt-1">{f.raw_message}</p>
                      )}
                    </div>

                    {/* Explanation */}
                    {f.explanation && (
                      <div className="rounded-lg border border-border/60 bg-background/50 p-3.5 space-y-2 font-mono text-xs print:bg-gray-50">
                        <p className="text-accent text-[10px] uppercase tracking-wider font-semibold">
                          remoting explanation
                        </p>
                        {f.explanation.what_it_is && (
                          <p>
                            <span className="text-subtle">What it is:</span>{" "}
                            {f.explanation.what_it_is}
                          </p>
                        )}
                        {f.explanation.why_it_happened && (
                          <p>
                            <span className="text-subtle">Root cause:</span>{" "}
                            {f.explanation.why_it_happened}
                          </p>
                        )}
                        {f.explanation.how_fix_works && (
                          <p>
                            <span className="text-subtle">Fix strategy:</span>{" "}
                            {f.explanation.how_fix_works}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Patch & Validation */}
                    {f.patch && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-subtle">Validated Patch:</span>
                          <span
                            className={
                              f.patch.validation_verdict === "accepted"
                                ? "text-success font-semibold"
                                : "text-danger"
                            }
                          >
                            Sandbox Verdict:{" "}
                            {f.patch.validation_verdict?.toUpperCase() || "PENDING"}
                          </span>
                        </div>
                        {diffLines.length > 0 && (
                          <div className="rounded-lg border border-border bg-background p-3 overflow-x-auto print:border-gray-200">
                            <DiffView lines={diffLines} />
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Learning Hub & Misconception Diagnostics */}
        <div className="space-y-4 print:break-inside-avoid">
          <h2 className="font-display text-sm font-semibold uppercase tracking-wider text-subtle flex items-center gap-2">
            <Brain className="size-4 text-accent" />
            Developer Learning & Misconception Diagnostics
          </h2>

          {misconceptions.length > 0 ? (
            <div className="rounded-xl border border-warning/40 bg-warning/5 p-5 space-y-3 print:bg-white print:border-gray-300">
              <p className="font-mono text-xs font-semibold text-warning">
                Active Recurring Misconceptions:
              </p>
              {misconceptions.map((m) => (
                <div
                  key={m.id}
                  className="rounded-lg border border-border bg-elevated p-3 font-mono text-xs"
                >
                  <p className="text-foreground font-semibold">{m.misconception_label}</p>
                  <p className="text-subtle text-[11px] mt-1">
                    Triggered in {m.supporting_attempt_ids?.length ?? m.occurrences} of last 4 quiz
                    submissions for{" "}
                    <span className="uppercase text-foreground">{m.vuln_class}</span>.
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-border p-4 font-mono text-xs text-subtle">
              No recurring misconceptions detected. Quiz answers demonstrate clean conceptual
              comprehension.
            </div>
          )}
        </div>

        {/* Spaced Repetition Mastery Table */}
        <div className="space-y-4 print:break-inside-avoid">
          <h2 className="font-display text-sm font-semibold uppercase tracking-wider text-subtle flex items-center gap-2">
            <Clock className="size-4 text-accent" />
            Adaptive Spaced Repetition & Retention Schedule
          </h2>

          <div className="overflow-x-auto rounded-xl border border-border bg-elevated print:border-gray-300">
            <table className="w-full font-mono text-xs">
              <thead>
                <tr className="border-b border-border bg-background text-left text-subtle print:bg-gray-100">
                  <th className="px-4 py-3 font-medium">class</th>
                  <th className="px-4 py-3 font-medium">tier reached</th>
                  <th className="px-4 py-3 font-medium">mastery level</th>
                  <th className="px-4 py-3 font-medium">accuracy</th>
                  <th className="px-4 py-3 font-medium">next review</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[
                  { key: "sqli", label: "SQL Injection" },
                  { key: "xss", label: "Cross-Site Scripting" },
                  { key: "csrf", label: "CSRF" },
                  { key: "insecure_deserialization", label: "Insecure Deserialization" },
                ].map((c) => {
                  const prof = mastery.find((m) => m.vuln_class === c.key);
                  const attempts = prof?.attempts_count ?? 0;
                  const correct = prof?.correct_count ?? 0;
                  const tier = prof?.tier_reached ?? "easy";
                  const level = getMasteryLevel(attempts, correct, tier);
                  const accuracy = attempts > 0 ? Math.round((correct / attempts) * 100) : 0;
                  const nextReview = prof?.next_review_at
                    ? new Date(prof.next_review_at).toLocaleDateString()
                    : "Due for initialization";

                  return (
                    <tr key={c.key}>
                      <td className="px-4 py-3 text-foreground font-semibold">{c.label}</td>
                      <td className="px-4 py-3 uppercase text-subtle">{tier}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`uppercase text-[10px] px-2 py-0.5 rounded border ${
                            level === "mastered"
                              ? "text-success border-success/40"
                              : level === "learning"
                                ? "text-warning border-warning/40"
                                : "text-subtle border-border"
                          }`}
                        >
                          {level}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-foreground">
                        {accuracy}% ({correct}/{attempts})
                      </td>
                      <td className="px-4 py-3 text-subtle">{nextReview}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-border pt-6 flex items-center justify-between font-mono text-[10px] text-subtle print:border-gray-300">
          <span>SecureLoop Automated Verification Engine · Semgrep + Sandbox Execution</span>
          <span>Confidential Security Audit Report</span>
        </div>
      </main>
    </div>
  );
}
