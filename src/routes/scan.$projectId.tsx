import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { ArrowLeft, Play, AlertTriangle } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase } from "@/lib/supabase";
import { Logo, TerminalWindow } from "@/components/chrome";
import { Link } from "@tanstack/react-router";
import {
  analyzeCodeForVulnerabilities,
  generateExplanation,
  generatePatch,
  validatePatch,
} from "@/lib/gemini";
import { fetchRepoFiles, buildFileMap } from "@/lib/github";

export const Route = createFileRoute("/scan/$projectId")({
  head: () => ({
    meta: [{ title: "Scan — SecureLoop" }],
  }),
  component: ScanPage,
});

const STAGES = [
  "queued",
  "cloning",
  "scanning",
  "explaining",
  "patching",
  "validating",
  "done",
] as const;

type ScanStage = (typeof STAGES)[number];

interface LogLine {
  text: string;
  tone?: "ok" | "err" | "warn" | "dim";
}

function ScanPage() {
  const { projectId } = Route.useParams();
  const navigate = useNavigate();
  const { user, loading } = useAuth();
  const [project, setProject] = useState<{
    name: string;
    repo_url?: string;
  } | null>(null);
  const [scanRunId, setScanRunId] = useState<string | null>(null);
  const [stage, setStage] = useState<ScanStage>("queued");
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [scanning, setScanning] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [geminiKey, setGeminiKey] = useState<string>(
    (import.meta as any).env?.VITE_GEMINI_API_KEY ?? "",
  );
  const [githubToken, setGithubToken] = useState<string>("");
  const logEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef(false);

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user && projectId) fetchProject();
  }, [user, projectId]);

  useEffect(() => {
    if (user) fetchSettings();
  }, [user]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  async function fetchProject() {
    const { data } = await supabase
      .from("projects")
      .select("name, repo_url")
      .eq("id", projectId)
      .single();
    if (data) setProject(data);
  }

  async function fetchSettings() {
    const { data } = await supabase
      .from("profiles")
      .select("github_token, gemini_api_key")
      .eq("id", user!.id)
      .single();
    if (data) {
      if ((data as any).github_token) setGithubToken((data as any).github_token);
      if ((data as any).gemini_api_key) setGeminiKey((data as any).gemini_api_key);
    }
  }

  function addLog(line: string, tone?: LogLine["tone"]) {
    setLogs((prev): LogLine[] => [...prev, { text: line, ...(tone !== undefined ? { tone } : {}) }]);
  }

  async function startScan() {
    if (!user || !project) return;
    if (!geminiKey.trim()) {
      setError("Gemini API key is required. Add it in Settings or above.");
      return;
    }
    if (!project.repo_url) {
      setError("This project has no GitHub URL. Please add one in dashboard.");
      return;
    }

    setScanning(true);
    setLogs([]);
    setDone(false);
    setError(null);
    abortRef.current = false;

    // ── 1. Create scan run ────────────────────────────────────────────────────
    const { data: scanRun, error: scanErr } = await supabase
      .from("scan_runs")
      .insert({
        project_id: projectId,
        status: "queued",
        tools: ["gemini-security-scan"],
        started_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (scanErr || !scanRun) {
      setError("Failed to create scan run: " + scanErr?.message);
      setScanning(false);
      return;
    }
    setScanRunId(scanRun.id);
    await supabase
      .from("projects")
      .update({ last_scan_id: scanRun.id })
      .eq("id", projectId);

    addLog(`$ secureloop scan ${project.repo_url}`);
    await delay(300);

    // ── 2. Clone / fetch repo files ──────────────────────────────────────────
    setStage("cloning");
    await updateScanStatus(scanRun.id, "scanning");
    addLog("▸ fetching repo via GitHub API…", "warn");

    const { files, error: fetchErr, repoName } = await fetchRepoFiles(
      project.repo_url,
      githubToken || undefined,
    );

    if (fetchErr) {
      addLog(`✖ ${fetchErr}`, "err");
      await updateScanStatus(scanRun.id, "failed");
      setError(fetchErr);
      setScanning(false);
      return;
    }

    addLog(`  ✓ ${files.length} source files fetched from ${repoName}`, "ok");
    files.forEach((f) => addLog(`    · ${f.path}  (${(f.content.length / 1024).toFixed(1)} KB)`, "dim"));
    await delay(200);

    // ── 3. Gemini security scan ───────────────────────────────────────────────
    setStage("scanning");
    addLog("▸ gemini-2.0-flash: analyzing for vulnerabilities…", "warn");

    const fileMap = buildFileMap(files);

    // Send files in batches of 8 to avoid token limits
    const allFindings: any[] = [];
    const batches = [];
    for (let i = 0; i < files.length; i += 8) batches.push(files.slice(i, i + 8));

    for (let b = 0; b < batches.length; b++) {
      addLog(`  batch ${b + 1}/${batches.length}: scanning ${batches[b]!.length} files…`, "dim");
      const batchFindings = await analyzeCodeForVulnerabilities(batches[b]!, geminiKey);
      allFindings.push(...batchFindings);
      if (batchFindings.length > 0) {
        batchFindings.forEach((f) =>
          addLog(
            `  ✖ ${f.file_path}:${f.line_start}  [${f.vulnerability_class}]  ${f.cwe}  ${f.severity}`,
            "err",
          ),
        );
      }
    }

    if (allFindings.length === 0) {
      addLog("  ✓ no vulnerabilities found — clean repo!", "ok");
      await supabase
        .from("scan_runs")
        .update({
          status: "done",
          finished_at: new Date().toISOString(),
          findings_count: 0,
          patch_success_rate: 1,
          test_pass_rate: 1,
          vuln_removal_rate: 1,
          new_vulns_rate: 0,
          acceptance_rate: 1,
        })
        .eq("id", scanRun.id);
      setStage("done");
      setDone(true);
      setScanning(false);
      return;
    }

    addLog(`  scan complete · ${allFindings.length} finding(s)`, "ok");

    // Insert findings into DB
    const insertedFindingIds: string[] = [];
    for (const f of allFindings) {
      const { data: inserted } = await supabase
        .from("findings")
        .insert({
          scan_run_id: scanRun.id,
          project_id: projectId,
          tool: "gemini-security-scan",
          rule_id: f.rule_id,
          cwe: f.cwe,
          severity: f.severity,
          file_path: f.file_path,
          line_start: f.line_start,
          line_end: f.line_end,
          vulnerability_class: f.vulnerability_class,
          raw_message: f.raw_message,
          status: "open",
          code_lines: f.code_lines,
        })
        .select("id")
        .single();
      if (inserted) insertedFindingIds.push(inserted.id);
    }

    // ── 4. Generate explanations ──────────────────────────────────────────────
    setStage("explaining");
    await updateScanStatus(scanRun.id, "explaining");
    addLog("▸ gemini: generating plain-language explanations…", "warn");

    const { data: findingsData } = await supabase
      .from("findings")
      .select("*")
      .eq("scan_run_id", scanRun.id);

    const explanationMap = new Map<string, string>();
    for (const f of findingsData ?? []) {
      const explanation = await generateExplanation(f, geminiKey);
      const { data: expRow } = await supabase
        .from("explanations")
        .insert({
          finding_id: f.id,
          what_it_is: explanation.what_it_is,
          why_it_happened: explanation.why_it_happened,
          owasp_category: explanation.owasp_category,
          how_fix_works: explanation.how_fix_works,
          model: "gemini-2.0-flash",
          generated_at: new Date().toISOString(),
        })
        .select("id")
        .single();
      if (expRow) explanationMap.set(f.id, expRow.id);
      await supabase
        .from("findings")
        .update({ status: "explained" })
        .eq("id", f.id);
      addLog(`  ✓ explained: ${f.file_path}:${f.line_start}`, "ok");
    }

    // ── 5. Generate patches ───────────────────────────────────────────────────
    setStage("patching");
    await updateScanStatus(scanRun.id, "patching");
    addLog("▸ gemini: generating candidate patches…", "warn");

    const patchMap = new Map<string, string>();
    for (const f of findingsData ?? []) {
      const fileContent = fileMap.get(f.file_path);
      const patch = await generatePatch(f, fileContent, geminiKey);
      const expId = explanationMap.get(f.id);
      const { data: patchRow } = await supabase
        .from("patches")
        .insert({
          finding_id: f.id,
          diff: patch.diff,
          explanation_id: expId ?? null,
          model: "gemini-2.0-flash",
          generated_at: new Date().toISOString(),
          validation_new_issues: 0,
        })
        .select("id")
        .single();
      if (patchRow) patchMap.set(f.id, patchRow.id);
      await supabase
        .from("findings")
        .update({ status: "patched" })
        .eq("id", f.id);
      addLog(`  ✓ patch generated: ${f.file_path}`, "ok");
    }

    // ── 6. Validate patches ───────────────────────────────────────────────────
    setStage("validating");
    await updateScanStatus(scanRun.id, "validating");
    addLog("▸ gemini: sandbox validation (re-scan per patch)…", "warn");

    let accepted = 0;
    let totalFixTime = 0;

    for (const f of findingsData ?? []) {
      const patchId = patchMap.get(f.id);
      if (!patchId) continue;

      const { data: patchRow } = await supabase
        .from("patches")
        .select("diff")
        .eq("id", patchId)
        .single();

      const start = Date.now();
      const validation = await validatePatch(f, patchRow?.diff ?? "", geminiKey);
      totalFixTime += (Date.now() - start) / 1000;

      await supabase
        .from("patches")
        .update({
          validation_vulnerability_gone: validation.vulnerability_gone,
          validation_tests_passed: validation.tests_passed,
          validation_new_issues: validation.new_issues,
          validation_verdict: validation.verdict,
          validation_validated_at: new Date().toISOString(),
          validation_logs: validation.logs,
          validation_failed_check: validation.failed_check ?? null,
        })
        .eq("id", patchId);

      await supabase
        .from("findings")
        .update({ status: "validated" })
        .eq("id", f.id);

      if (validation.verdict === "accepted") accepted++;
      addLog(
        `  ${patchId.slice(0, 6)}  vuln_gone:${validation.vulnerability_gone ? "✓" : "✗"}  tests:${validation.tests_passed ? "✓" : "✗"}  new_issues:${validation.new_issues}  → ${validation.verdict.toUpperCase()}`,
        validation.verdict === "accepted" ? "ok" : "warn",
      );
    }

    // ── 7. Finalize scan run ──────────────────────────────────────────────────
    const total = (findingsData ?? []).length;
    const patchSuccessRate = total > 0 ? accepted / total : 1;

    await supabase
      .from("scan_runs")
      .update({
        status: "done",
        finished_at: new Date().toISOString(),
        findings_count: total,
        patch_success_rate: patchSuccessRate,
        test_pass_rate: patchSuccessRate,
        vuln_removal_rate: patchSuccessRate,
        new_vulns_rate: 0,
        acceptance_rate: patchSuccessRate,
        time_to_fix_seconds: Math.round(totalFixTime),
      })
      .eq("id", scanRun.id);

    // Compute security score based on findings and patches
    const score = computeScore(allFindings, accepted, total);
    await supabase.from("security_scores").insert({
      project_id: projectId,
      user_id: user.id,
      overall: score.overall,
      sqli: score.sqli,
      xss: score.xss,
      csrf: score.csrf,
      deserialization: score.deserialization,
      computed_at: new Date().toISOString(),
    });

    setStage("done");
    addLog(
      `done · ${total} findings · ${accepted}/${total} patches accepted · score: ${score.overall}`,
      "ok",
    );
    setDone(true);
    setScanning(false);
  }

  async function updateScanStatus(id: string, status: string) {
    await supabase.from("scan_runs").update({ status }).eq("id", id);
  }

  function delay(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">loading…</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-4xl items-center justify-between px-6">
          <Logo />
          <Link
            to="/dashboard"
            className="flex items-center gap-2 font-mono text-xs text-subtle hover:text-foreground"
          >
            <ArrowLeft className="size-3" />
            dashboard
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-10">
        <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
          scan pipeline
        </p>
        <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight">
          {project?.name ?? "…"}
        </h1>
        {project?.repo_url && (
          <p className="mt-1 font-mono text-xs text-subtle">{project.repo_url}</p>
        )}

        {/* API keys inline config (only before scanning) */}
        {!scanning && !done && (
          <div className="mt-6 rounded-lg border border-border bg-elevated p-4 space-y-3">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              pipeline configuration
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  Gemini API key
                </label>
                <input
                  type="password"
                  value={geminiKey}
                  onChange={(e) => setGeminiKey(e.target.value)}
                  placeholder="AIzaSy…"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  GitHub token <span className="text-subtle/50">(optional, for private repos)</span>
                </label>
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_…"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                />
              </div>
            </div>
            <p className="font-mono text-[10px] text-subtle/60 flex items-center gap-1.5">
              <AlertTriangle className="size-3" />
              Keys are used only in your browser and never stored server-side (unless you save them in Settings).
            </p>
          </div>
        )}

        {/* Stage pipeline indicators */}
        <div className="mt-6 flex flex-wrap items-center gap-2 font-mono text-[11px]">
          {STAGES.map((s, i) => (
            <span key={s} className="flex items-center gap-2">
              <span
                className={`rounded-full border px-3 py-1 transition-colors ${
                  s === stage
                    ? "border-accent/50 bg-accent/10 text-foreground"
                    : STAGES.indexOf(stage) > i
                      ? "border-success/30 text-success"
                      : "border-border text-subtle/40"
                }`}
              >
                {s}
              </span>
              {i < STAGES.length - 1 && (
                <span className="text-subtle/30">→</span>
              )}
            </span>
          ))}
        </div>

        {/* Terminal log */}
        <div className="mt-6">
          <TerminalWindow
            title={`pipeline · ${project?.name ?? projectId}`}
            bodyClassName="h-80 overflow-y-auto"
          >
            {logs.length === 0 && !scanning && (
              <span className="text-subtle/50">
                configure above and press "start scan" to run the real AI pipeline
              </span>
            )}
            {logs.map((l, i) => (
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
            <div ref={logEndRef} />
          </TerminalWindow>
        </div>

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/5 px-4 py-3">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-danger" />
            <p className="font-mono text-xs text-danger">{error}</p>
          </div>
        )}

        {/* Actions */}
        <div className="mt-6 flex items-center gap-3">
          {!scanning && !done && (
            <button
              onClick={startScan}
              className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-5 py-2.5 font-mono text-xs font-medium text-foreground"
            >
              <span className="size-1.5 rounded-full bg-accent" />
              <Play className="size-3" />
              start scan
            </button>
          )}
          {scanning && (
            <span className="font-mono text-xs text-accent animate-pulse">
              ⚡ ai pipeline running — this may take 1–3 minutes…
            </span>
          )}
          {done && (
            <Link
              to="/findings/$projectId"
              params={{ projectId }}
              className="pill-hover inline-flex items-center gap-2 rounded-full border border-success/40 bg-success/10 px-5 py-2.5 font-mono text-xs font-medium text-success"
            >
              <span className="size-1.5 rounded-full bg-success" />
              view findings →
            </Link>
          )}
          {done && (
            <button
              onClick={() => {
                setDone(false);
                setLogs([]);
                setStage("queued");
                setError(null);
              }}
              className="font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
            >
              run again
            </button>
          )}
        </div>
      </main>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Score computation from real findings                                         */
/* ─────────────────────────────────────────────────────────────────────────── */
function computeScore(
  findings: Array<{ vulnerability_class?: string; severity: string }>,
  accepted: number,
  total: number,
) {
  const categories = { sqli: 100, xss: 100, csrf: 100, deserialization: 100 };
  const deductions: Record<string, number> = {
    critical: 30,
    high: 18,
    medium: 10,
    low: 4,
  };

  for (const f of findings) {
    const cls = f.vulnerability_class;
    const ded = deductions[f.severity] ?? 5;
    if (cls === "sqli") categories.sqli = Math.max(0, categories.sqli - ded);
    else if (cls === "xss") categories.xss = Math.max(0, categories.xss - ded);
    else if (cls === "csrf") categories.csrf = Math.max(0, categories.csrf - ded);
    else if (cls === "insecure_deserialization")
      categories.deserialization = Math.max(0, categories.deserialization - ded);
  }

  // Bonus for patch acceptance rate
  const acceptBonus = total > 0 ? Math.round((accepted / total) * 10) : 0;

  const avg = Math.round(
    (categories.sqli + categories.xss + categories.csrf + categories.deserialization) / 4,
  );
  const overall = Math.min(100, avg + acceptBonus);

  return { overall, ...categories };
}
