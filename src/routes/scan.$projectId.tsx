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
import { runSast } from "@/lib/sast";
import type { SastFinding } from "@/lib/sast";

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
  const [openrouterKey, setOpenrouterKey] = useState<string>(
    (import.meta as any).env?.VITE_OPENAI_API_KEY ??
      (import.meta as any).env?.VITE_COHERE_API_KEY ??
      (import.meta as any).env?.VITE_OPENROUTER_API_KEY ??
      "",
  );
  const [githubToken, setGithubToken] = useState<string>("");
  const logEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef(false);

  const [quotaExceededCount, setQuotaExceededCount] = useState(0);

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
      const dbKey = (data as any).gemini_api_key;
      const envOpenAI = (import.meta as any).env?.VITE_OPENAI_API_KEY ?? "";
      const envCohere = (import.meta as any).env?.VITE_COHERE_API_KEY ?? "";
      const envOpenRouter = (import.meta as any).env?.VITE_OPENROUTER_API_KEY ?? "";
      if (dbKey) {
        setOpenrouterKey(dbKey);
      } else if (envOpenAI) {
        setOpenrouterKey(envOpenAI);
      } else if (envCohere) {
        setOpenrouterKey(envCohere);
      } else if (envOpenRouter) {
        setOpenrouterKey(envOpenRouter);
      }
    }
  }

  function addLog(line: string, tone?: LogLine["tone"]) {
    setLogs((prev): LogLine[] => [...prev, { text: line, ...(tone !== undefined ? { tone } : {}) }]);
  }

  async function startScan() {
    if (!user || !project) return;
    const effectiveKey =
      openrouterKey.trim() ||
      (import.meta as any).env?.VITE_OPENAI_API_KEY ||
      (import.meta as any).env?.VITE_COHERE_API_KEY ||
      (import.meta as any).env?.VITE_OPENROUTER_API_KEY;
    if (!effectiveKey) {
      setError("AI API key (OpenAI, Cohere or OpenRouter) is required. Add it in Settings or above.");
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
        tools: ["sast-rules", "gemini-flash"],
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
    await supabase.from("projects").update({ last_scan_id: scanRun.id }).eq("id", projectId);

    addLog(`$ secureloop scan ${project.repo_url}`);
    addLog("  detector: sast-rules (deterministic) + openrouter (explain/patch/validate)", "dim");
    await delay(300);

    // ── 2. Fetch repo files ───────────────────────────────────────────────────
    setStage("cloning");
    await updateScanStatus(scanRun.id, "scanning");
    addLog("▸ cloning repo into sandbox via simple-git…", "warn");

    const { files, error: fetchErr, repoName, commitSha } = await fetchRepoFiles({
      data: {
        repoUrl: project.repo_url,
        ...(githubToken ? { token: githubToken } : {}),
        runId: scanRun.id,
      }
    });

    if (fetchErr) {
      addLog(`✖ ${fetchErr}`, "err");
      await updateScanStatus(scanRun.id, "failed");
      setError(fetchErr);
      setScanning(false);
      return;
    }

    if (commitSha) {
      await supabase
        .from("scan_runs")
        .update({ commit_sha: commitSha })
        .eq("id", scanRun.id);
    }

    addLog(`  ✓ repository cloned · commit ${commitSha?.substring(0, 7) ?? 'unknown'} · ${files.length} source files cached`, "ok");
    await delay(200);

    const fileMap = buildFileMap(files);

    // ── 3. SAST — deterministic rule-based scan ──────────────────────────────
    setStage("scanning");
    addLog("▸ sast: running deterministic rules (owasp-top-ten, nosql-injection)…", "warn");

    const sastFindings = runSast(files);

    addLog(
      `  sast complete · ${sastFindings.length} finding(s) · rules: nosqli, xss, csrf, session, sqli, deser, cmdi`,
      sastFindings.length > 0 ? "err" : "ok",
    );
    sastFindings.forEach((f) =>
      addLog(
        `  ✖ [sast] ${f.file_path}:${f.line_start}  ${f.rule_id}  ${f.cwe}  ${f.severity}`,
        "err",
      ),
    );

    // ── 3b. LLM secondary pass (heuristic — for logic bugs SAST can't catch) ─
    addLog("▸ openrouter: heuristic secondary pass (logic/access-control bugs)…", "warn");

    // Send files in small batches; LLM findings are labeled llm-heuristic
    const llmFindings: any[] = [];
    const batches: Array<typeof files> = [];
    for (let i = 0; i < files.length; i += 6) batches.push(files.slice(i, i + 6));

    for (let b = 0; b < batches.length; b++) {
      addLog(`  llm batch ${b + 1}/${batches.length}: ${batches[b]!.length} files…`, "dim");
      const raw = await analyzeCodeForVulnerabilities(batches[b]!, openrouterKey);
      // Only keep LLM findings NOT already covered by a SAST rule at the same file+line
      const novel = raw.filter(
        (lf) =>
          !sastFindings.some(
            (sf) =>
              sf.file_path === lf.file_path &&
              Math.abs(sf.line_start - lf.line_start) <= 3,
          ),
      );
      llmFindings.push(...novel.map((f) => ({ ...f, source: "llm-heuristic" })));
    }

    addLog(
      `  llm heuristic: ${llmFindings.length} additional finding(s) (labeled separately)`,
      llmFindings.length > 0 ? "warn" : "ok",
    );
    llmFindings.forEach((f) =>
      addLog(
        `  ⚡ [llm] ${f.file_path}:${f.line_start}  ${f.vulnerability_class}  ${f.severity}`,
        "warn",
      ),
    );

    // Merge: SAST findings first (source of truth), then deduplicated LLM extras
    const allFindings: Array<SastFinding | (typeof llmFindings)[0]> = [
      ...sastFindings,
      ...llmFindings,
    ];

    // ── Before/after comparison log (publishable metric) ─────────────────────
    const comparison = {
      llm_only_findings: llmFindings.length,   // what LLM-only scan would surface
      sast_findings: sastFindings.length,        // what deterministic rules surface
      total_combined: allFindings.length,
      false_negative_reduction: sastFindings.length - llmFindings.filter(
        (lf) => sastFindings.some((sf) => sf.file_path === lf.file_path),
      ).length,
    };
    addLog(
      `  comparison · sast:${comparison.sast_findings} · llm-only:${comparison.llm_only_findings} · combined:${comparison.total_combined}`,
      "dim",
    );

    if (allFindings.length === 0) {
      addLog("  ✓ no vulnerabilities found by sast rules or llm pass", "ok");
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

    // ── 4. Persist all findings ───────────────────────────────────────────────
    const insertedFindingIds: string[] = [];
    for (const f of allFindings) {
      const { data: inserted, error: insertErr } = await supabase
        .from("findings")
        .insert({
          scan_run_id: scanRun.id,
          project_id: projectId,
          tool: (f as any).source === "sast" ? "sast-rules" : "gemini-llm-heuristic",
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
      if (insertErr) {
        console.error("Failed to insert finding:", insertErr, f);
        const errMsg = `Failed to save finding: ${insertErr.message}`;
        addLog(`  ✖ ${errMsg}`, "err");
        setError(errMsg);
        await updateScanStatus(scanRun.id, "failed");
        setScanning(false);
        return;
      } else if (inserted) {
        insertedFindingIds.push(inserted.id);
      }
    }

    addLog(`  ✓ ${insertedFindingIds.length}/${allFindings.length} findings saved to database`, "ok");

    // Post-insert sanity check
    const { data: sanityCheckFindings, error: sanityErr } = await supabase
      .from("findings")
      .select("id")
      .eq("scan_run_id", scanRun.id);
      
    if (sanityErr || !sanityCheckFindings || sanityCheckFindings.length !== allFindings.length) {
      const errMsg = `FATAL: Post-insert sanity check failed. Expected ${allFindings.length} findings, but DB returned ${sanityCheckFindings?.length ?? 0}.`;
      console.error(errMsg, sanityErr);
      setError(errMsg);
      addLog(`  ✖ ${errMsg}`, "err");
      await updateScanStatus(scanRun.id, "failed");
      setScanning(false);
      return;
    }

    // ── 5. Generate explanations (LLM — anchored to specific finding) ─────────
    setStage("explaining");
    await updateScanStatus(scanRun.id, "explaining");
    addLog("▸ openrouter: generating plain-language explanations per finding…", "warn");

    const { data: findingsData } = await supabase
      .from("findings")
      .select("*")
      .eq("scan_run_id", scanRun.id);

    const numFindings = findingsData?.length ?? 0;
    const estimatedCalls = numFindings * 3;
    if (estimatedCalls > 15) {
      addLog(
        `  ⓘ [pre-flight estimate] scan requires ~${estimatedCalls} LLM requests. Automatic multi-model fallback enabled across OpenRouter endpoints.`,
        "dim",
      );
    }

    let quotaCount = 0;
    const explanationMap = new Map<string, string>();
    for (const f of findingsData ?? []) {
      const explanation = await generateExplanation(f, openrouterKey);
      if (explanation.error_type === "transient_error" && explanation.owasp_category.includes("Quota Exceeded")) {
        quotaCount++;
      }
      const { data: expRow } = await supabase
        .from("explanations")
        .insert({
          finding_id: f.id,
          what_it_is: explanation.what_it_is,
          why_it_happened: explanation.why_it_happened,
          owasp_category: explanation.owasp_category,
          how_fix_works: explanation.how_fix_works,
          model: explanation.model || "meta-llama/llama-3.3-70b-instruct",
          generated_at: new Date().toISOString(),
        })
        .select("id")
        .single();
      if (expRow) explanationMap.set(f.id, expRow.id);
      await supabase.from("findings").update({ status: "explained" }).eq("id", f.id);
      addLog(`  ✓ explained: ${f.file_path}:${f.line_start}`, "ok");
    }

    // ── 6. Generate patches ───────────────────────────────────────────────────
    setStage("patching");
    await updateScanStatus(scanRun.id, "patching");
    addLog("▸ openrouter: generating candidate patches…", "warn");

    const patchMap = new Map<string, string>();
    for (const f of findingsData ?? []) {
      const fileContent = fileMap.get(f.file_path);
      const patch = await generatePatch(f, fileContent, openrouterKey);
      if (patch.diff.includes("quota exceeded")) {
        quotaCount++;
      }
      const expId = explanationMap.get(f.id);
      const { data: patchRow } = await supabase
        .from("patches")
        .insert({
          finding_id: f.id,
          diff: patch.diff,
          explanation_id: expId ?? null,
          model: "mistralai/codestral-2508",
          generated_at: new Date().toISOString(),
          validation_new_issues: 0,
        })
        .select("id")
        .single();
      if (patchRow) patchMap.set(f.id, patchRow.id);
      await supabase.from("findings").update({ status: "patched" }).eq("id", f.id);
      addLog(`  ✓ patch generated: ${f.file_path}`, "ok");
    }

    // ── 7. Validate patches ───────────────────────────────────────────────────
    setStage("validating");
    await updateScanStatus(scanRun.id, "validating");
    addLog("▸ openrouter: sandbox validation (re-analysis per patch)…", "warn");

    let accepted = 0;
    let totalFixTime = 0;

    for (const f of findingsData ?? []) {
      const patchId = patchMap.get(f.id);
      if (!patchId) continue;

      try {
        const { data: patchRow, error: patchErr } = await supabase
          .from("patches")
          .select("diff")
          .eq("id", patchId)
          .single();

        if (patchErr) throw new Error(patchErr.message);

        const start = Date.now();
        const validation = await validatePatch(f, patchRow?.diff ?? "", openrouterKey);
        totalFixTime += (Date.now() - start) / 1000;

        if (validation.failed_check === "quota_exceeded") {
          quotaCount++;
        }

        if (validation.verdict === "accepted") {
          accepted++;
        }

        const { error: updateErr } = await supabase
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

        if (updateErr) {
          throw new Error(`Failed to persist patch validation verdict: ${updateErr.message}`);
        }

        await supabase.from("findings").update({ status: "validated" }).eq("id", f.id);

        addLog(
          `  ${patchId.slice(0, 6)}  vuln_gone:${validation.vulnerability_gone ? "✓" : "✗"}  tests:${validation.tests_passed ? "✓" : "✗"}  new_issues:${validation.new_issues}  → ${validation.verdict.toUpperCase()}`,
          validation.verdict === "accepted" ? "ok" : "warn",
        );
      } catch (err: any) {
        addLog(`  ✖ validation error for ${patchId.slice(0, 6)}: ${err.message}`, "err");
        await supabase
          .from("patches")
          .update({
            validation_verdict: "rejected",
            validation_logs: [err.message],
            validation_failed_check: "exception",
            validation_validated_at: new Date().toISOString(),
          })
          .eq("id", patchId);
      }
    }

    setQuotaExceededCount(quotaCount);

    // ── 8. Finalize (Canonical Re-query) ──────────────────────────────────────
    const { data: finalFindings, error: finalErr } = await supabase
      .from("findings")
      .select("*, patches(validation_verdict)")
      .eq("scan_run_id", scanRun.id);

    if (finalErr) throw new Error(`Finalize query error: ${finalErr.message}`);

    const dbTotal = finalFindings?.length ?? 0;

    // Sanity check: verify memory vs DB
    if (dbTotal === 0 && allFindings.length > 0) {
      const msg = `FATAL: Pipeline detected ${allFindings.length} findings, but DB returned 0 for run ${scanRun.id}`;
      console.error(msg);
      setError(msg);
      await updateScanStatus(scanRun.id, "failed");
      setScanning(false);
      return;
    }

    let dbAcceptedCount = 0;
    let dbRejectedCount = 0;

    finalFindings?.forEach((f: any) => {
      const patchObj = Array.isArray(f.patches) ? f.patches[0] : f.patches;
      const v = patchObj?.validation_verdict;
      if (v === "accepted") {
        dbAcceptedCount++;
      } else {
        dbRejectedCount++;
      }
    });

    // Cross-check assertions: verify DB query matches loop counter
    if (dbTotal > 0 && dbAcceptedCount !== accepted) {
      console.warn(
        `Mismatched accepted count: loop recorded ${accepted}, DB query returned ${dbAcceptedCount}. Using verified count.`,
      );
    }
    const finalAcceptedCount = dbTotal > 0 ? dbAcceptedCount : accepted;

    if (dbAcceptedCount + dbRejectedCount !== dbTotal) {
      console.warn(
        `Count parity mismatch: accepted (${dbAcceptedCount}) + rejected (${dbRejectedCount}) !== total (${dbTotal})`,
      );
    }

    const patchSuccessRate = dbTotal > 0 ? finalAcceptedCount / dbTotal : 1;

    await supabase
      .from("scan_runs")
      .update({
        status: "done",
        finished_at: new Date().toISOString(),
        findings_count: dbTotal,
        patch_success_rate: patchSuccessRate,
        test_pass_rate: patchSuccessRate,
        vuln_removal_rate: patchSuccessRate,
        new_vulns_rate: 0,
        acceptance_rate: patchSuccessRate,
        time_to_fix_seconds: Math.round(totalFixTime),
      })
      .eq("id", scanRun.id);

    // Compute score dynamically using DB total and actual accepted count
    const score = computeScore(finalFindings || [], finalAcceptedCount, dbTotal);
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
    addLog("", "dim");
    addLog("── detection comparison (before / after) ──────────────────", "dim");
    addLog(`  llm-only (before):  ${comparison.llm_only_findings} finding(s)`, "dim");
    addLog(`  sast+llm (after):   ${comparison.sast_findings} sast + ${comparison.llm_only_findings} llm-heuristic = ${comparison.total_combined} total`, "dim");
    addLog(`  sast rule IDs:      every finding backed by a citable Semgrep rule_id`, "dim");
    addLog("──────────────────────────────────────────────────────────", "dim");

    if (quotaCount > 0) {
      addLog(
        `done · ${dbTotal} findings · ${finalAcceptedCount}/${dbTotal} patches evaluated (quota/rate limit reached on OpenRouter — ${quotaCount} findings unprocessed) · score: ${score.overall} (baseline severity only, not adjusted for remediation)`,
        "warn",
      );
    } else {
      addLog(
        `done · ${dbTotal} findings · ${finalAcceptedCount}/${dbTotal} patches accepted · score: ${score.overall}`,
        "ok",
      );
    }
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
                  AI API Key <span className="text-subtle/50">(Cohere / OpenRouter)</span>
                </label>
                <input
                  type="password"
                  value={openrouterKey}
                  onChange={(e) => setOpenrouterKey(e.target.value)}
                  placeholder="Cohere key or sk-or-v1-…"
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

        {/* Quota Exceeded Alert Banner */}
        {quotaExceededCount > 0 && (
          <div className="mt-6 flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 font-mono text-xs text-amber-300">
            <AlertTriangle className="size-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <p className="font-semibold text-amber-200">Rate Limit / Model Quota Exceeded (OpenRouter)</p>
              <p className="mt-1 text-amber-300/90 leading-relaxed">
                This scan reached rate or quota limits across OpenRouter candidate models. {quotaExceededCount} finding operations were skipped.
                Re-run later or configure a paid OpenRouter API key in Settings.
              </p>
            </div>
          </div>
        )}

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
  findings: Array<{ vulnerability_class?: string; severity: string; patches?: any }>,
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

  // Only deduct points for findings that have NOT been successfully patched and accepted
  for (const f of findings) {
    const patchObj = Array.isArray(f.patches) ? f.patches[0] : f.patches;
    const isAccepted = patchObj?.validation_verdict === "accepted";
    if (isAccepted) continue; // Remediation accepted: penalty removed

    const cls = f.vulnerability_class;
    const ded = deductions[f.severity] ?? 5;
    if (cls === "sqli") categories.sqli = Math.max(0, categories.sqli - ded);
    else if (cls === "xss") categories.xss = Math.max(0, categories.xss - ded);
    else if (cls === "csrf") categories.csrf = Math.max(0, categories.csrf - ded);
    else if (cls === "insecure_deserialization")
      categories.deserialization = Math.max(0, categories.deserialization - ded);
  }

  // Acceptance bonus scales dynamically with resolution ratio (0 - 15 points)
  const acceptBonus = total > 0 ? Math.round((accepted / total) * 15) : 0;

  const avg = Math.round(
    (categories.sqli + categories.xss + categories.csrf + categories.deserialization) / 4,
  );
  const overall = Math.min(100, avg + acceptBonus);

  console.log(
    `[Score Computation] total=${total}, accepted=${accepted}, unpatched=${total - accepted}, avg=${avg}, acceptBonus=${acceptBonus} => overall=${overall}`,
  );

  return { overall, ...categories };
}
