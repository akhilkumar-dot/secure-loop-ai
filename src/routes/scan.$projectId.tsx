import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { ArrowLeft, Play, AlertTriangle, RefreshCw, ShieldAlert, Check } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase } from "@/lib/supabase";
import { Logo, TerminalWindow } from "@/components/chrome";
import { Link } from "@tanstack/react-router";
import {
  analyzeCodeForVulnerabilities,
  generateExplanation,
  generatePatch,
  validatePatch,
} from "@/lib/ai-pipeline";
import { fetchRepoFiles, buildFileMap } from "@/lib/github";
import { runSast } from "@/lib/sast";
import { recomputeScore } from "@/lib/score";
import type { SastFinding } from "@/lib/sast";
import {
  detectProvider,
  validateEndpointUrl,
  formatKeyHint,
  redactKeys,
  PROVIDER_INFOS,
  type DetectedProvider,
} from "@/lib/ai-provider-detector";
import { isSameProviderBackup } from "@/lib/rate-limiter";
import { fetchCustomEndpointModels } from "@/lib/custom-openai";
import { preflightCheckProvider, type PreflightCheckResult } from "@/lib/preflight-checker";

function isIgnoredPathOrLiteral(filePath: string, matchedText?: string): boolean {
  if (!filePath) return false;
  const p = filePath.toLowerCase();
  if (
    p.includes("/test/") ||
    p.includes("/tests/") ||
    p.includes("/__tests__/") ||
    p.includes(".test.") ||
    p.includes(".spec.") ||
    p.includes("safe-control")
  ) {
    return true;
  }
  if (matchedText) {
    const trimmed = matchedText.trim();
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith("`") && trimmed.endsWith("`")) ||
      trimmed.startsWith("//") ||
      trimmed.startsWith("/*")
    ) {
      return true;
    }
  }
  return false;
}

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

const PROVIDER_OPTIONS: Array<{ value: "auto" | DetectedProvider; label: string }> = [
  { value: "auto", label: "Auto-detect from key format" },
  { value: "gemini", label: "Google Gemini" },
  { value: "groq", label: "Groq" },
  { value: "openrouter", label: "OpenRouter" },
  { value: "openai", label: "OpenAI" },
  { value: "cohere", label: "Cohere" },
  { value: "freellmapi", label: "FreeLLMAPI" },
  { value: "custom_openai", label: "Custom OpenAI-compatible endpoint" },
];

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
  const [aiApiKey, setAiApiKey] = useState<string>(() => {
    // Restore key from sessionStorage so users don't re-type it on every navigation
    // sessionStorage is cleared when the tab closes — never sent to any server.
    return sessionStorage.getItem("sl_ai_key") ?? "";
  });
  const [backupApiKey, setBackupApiKey] = useState<string>(() => {
    return sessionStorage.getItem("sl_ai_backup_key") ?? "";
  });
  const [primaryProviderChoice, setPrimaryProviderChoice] = useState<"auto" | DetectedProvider>(
    () => {
      return (
        (sessionStorage.getItem("sl_ai_provider_choice") as "auto" | DetectedProvider) ?? "auto"
      );
    },
  );
  const [backupProviderChoice, setBackupProviderChoice] = useState<"auto" | DetectedProvider>(
    () => {
      return (
        (sessionStorage.getItem("sl_ai_backup_provider_choice") as "auto" | DetectedProvider) ??
        "auto"
      );
    },
  );
  const [customBaseUrl, setCustomBaseUrl] = useState<string>(() => {
    return sessionStorage.getItem("sl_ai_custom_url") ?? "http://localhost:3001/v1";
  });
  const [customModel, setCustomModel] = useState<string>(() => {
    return sessionStorage.getItem("sl_ai_custom_model") ?? "freellmapi/auto";
  });
  const [customModels, setCustomModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [modelsError, setModelsError] = useState<string | null>(null);
  const [preflightError, setPreflightError] = useState<PreflightCheckResult | null>(null);
  const [checkingPreflight, setCheckingPreflight] = useState(false);
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
      .select("github_token")
      .eq("id", user!.id)
      .single();
    if (data) {
      const d = data as { github_token?: string };
      if (d.github_token) setGithubToken(d.github_token);
    }
  }

  function addLog(line: string, tone?: LogLine["tone"]) {
    setLogs((prev): LogLine[] => [
      ...prev,
      { text: line, ...(tone !== undefined ? { tone } : {}) },
    ]);
  }

  async function handleFetchCustomModels() {
    setLoadingModels(true);
    setModelsError(null);
    try {
      const models = await fetchCustomEndpointModels(customBaseUrl, aiApiKey);
      setCustomModels(models);
      if (models.length > 0 && !models.includes(customModel)) {
        setCustomModel(models[0]!);
        sessionStorage.setItem("sl_ai_custom_model", models[0]!);
      }
    } catch (err: any) {
      setModelsError(err?.message || "Failed to fetch models from endpoint.");
    } finally {
      setLoadingModels(false);
    }
  }

  async function handleRetryPreflight() {
    const effectiveKey = aiApiKey.trim();
    if (!effectiveKey) return;
    setCheckingPreflight(true);
    try {
      const res = await preflightCheckProvider(effectiveKey, {
        explicitProvider: primaryProviderChoice !== "auto" ? primaryProviderChoice : undefined,
        baseUrl: customBaseUrl,
      });
      if (res.ok) {
        setPreflightError(null);
        setError(null);
        addLog(`✓ ${res.providerName} pre-flight check succeeded (${res.keyHint})`, "ok");
      } else {
        setPreflightError(res);
        setError(res.errorMessage || "Pre-flight check failed.");
        addLog(`✖ ${res.errorMessage}`, "err");
        if (res.urlTried) addLog(`  url tried: ${res.urlTried}`, "dim");
        if (res.checklist && res.checklist.length > 0) {
          addLog("  checklist to verify:", "warn");
          res.checklist.forEach((item) => addLog(`   • ${item}`, "dim"));
        }
        if (res.workaround) addLog(`  workaround: ${res.workaround}`, "warn");
      }
    } catch (err: any) {
      setError(err?.message || "Failed to run preflight check.");
    } finally {
      setCheckingPreflight(false);
    }
  }

  function handleUseBackupProvider() {
    if (!backupApiKey) return;
    const newPrimary = backupApiKey;
    const newProviderChoice = backupProviderChoice;
    setAiApiKey(newPrimary);
    sessionStorage.setItem("sl_ai_key", newPrimary);
    setPrimaryProviderChoice(newProviderChoice);
    sessionStorage.setItem("sl_ai_provider_choice", newProviderChoice);

    setBackupApiKey("");
    sessionStorage.removeItem("sl_ai_backup_key");
    setBackupProviderChoice("auto");
    sessionStorage.setItem("sl_ai_backup_provider_choice", "auto");

    setPreflightError(null);
    setError(null);
    addLog("Switched primary provider to backup key.", "warn");
  }

  async function startScan() {
    if (!user || !project) return;
    const effectiveKey = aiApiKey.trim();
    const effectiveBackupKey = backupApiKey.trim();
    if (!effectiveKey) {
      setError("AI API key is required. Enter it in the Pipeline Configuration above.");
      return;
    }

    const detectedPrimary = detectProvider(
      effectiveKey,
      primaryProviderChoice !== "auto" ? primaryProviderChoice : undefined,
    );
    if (detectedPrimary === "unknown") {
      setError("Key format not recognized. Choose the provider manually from the dropdown.");
      return;
    }

    const detectedBackup = detectProvider(
      effectiveBackupKey,
      backupProviderChoice !== "auto" ? backupProviderChoice : undefined,
    );
    if (
      detectedPrimary === "freellmapi" ||
      detectedPrimary === "custom_openai" ||
      detectedBackup === "freellmapi" ||
      detectedBackup === "custom_openai"
    ) {
      const urlCheck = validateEndpointUrl(customBaseUrl);
      if (!urlCheck.isValid) {
        setError(urlCheck.error || "Invalid endpoint Base URL.");
        return;
      }
    }

    if (!project.repo_url) {
      setError("This project has no GitHub URL. Please add one in the dashboard.");
      return;
    }

    setScanning(true);
    setLogs([]);
    setDone(false);
    setError(null);
    setPreflightError(null);
    abortRef.current = false;

    const beforeUnloadHandler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue =
        "A scan is in progress. Leaving will not cancel it but you may lose progress.";
    };
    window.addEventListener("beforeunload", beforeUnloadHandler);

    let activeScanRunId: string | null = null;

    try {
      // Create scan run
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
        throw new Error("Failed to create scan run: " + scanErr?.message);
      }
      activeScanRunId = scanRun.id;
      setScanRunId(scanRun.id);
      await supabase.from("projects").update({ last_scan_id: scanRun.id }).eq("id", projectId);

      await runScanPipeline(scanRun, effectiveKey, effectiveBackupKey);
    } catch (err: unknown) {
      const msg = (err as Error)?.message ?? String(err);
      console.error("[scan] Unhandled pipeline error:", err);
      setError(msg);
      addLog(`✖ fatal: ${msg}`, "err");
      if (activeScanRunId) {
        await supabase
          .from("scan_runs")
          .update({ status: "failed", error_message: msg, finished_at: new Date().toISOString() })
          .eq("id", activeScanRunId);
      }
    } finally {
      window.removeEventListener("beforeunload", beforeUnloadHandler);
      setScanning(false);
    }
  }

  async function runScanPipeline(
    scanRun: { id: string },
    effectiveKey: string,
    effectiveBackupKey: string,
  ) {
    let quotaCount = 0;
    const detected = detectProvider(effectiveKey);
    const providerLabel = PROVIDER_INFOS[detected]?.name ?? "AI";

    addLog(`$ secureloop scan ${project!.repo_url}`);
    addLog(
      `  detector: sast-rules (deterministic) + ${providerLabel} (explain/patch/validate)`,
      "dim",
    );
    await delay(300);

    // Fetch repo files
    setStage("cloning");
    await updateScanStatus(scanRun.id, "scanning");
    addLog("▸ fetching repository files via GitHub API…", "warn");

    const {
      files,
      error: fetchErr,
      repoName,
      commitSha,
    } = await fetchRepoFiles({
      data: {
        repoUrl: project?.repo_url ?? "",
        ...(githubToken ? { token: githubToken } : {}),
        runId: scanRun.id,
      },
    });

    if (fetchErr) {
      addLog(`✖ ${fetchErr}`, "err");
      await updateScanStatus(scanRun.id, "failed");
      setError(fetchErr);
      setScanning(false);
      return;
    }

    if (commitSha) {
      await supabase.from("scan_runs").update({ commit_sha: commitSha }).eq("id", scanRun.id);
    }

    addLog(
      `  ✓ repository cloned · commit ${commitSha?.substring(0, 7) ?? "unknown"} · ${files.length} source files cached`,
      "ok",
    );
    await delay(200);

    const fileMap = buildFileMap(files);

    // ── 3. SAST — deterministic rule-based scan ──────────────────────────────
    setStage("scanning");
    addLog("▸ sast: running deterministic rules (owasp-top-ten, nosql-injection)…", "warn");

    const sastFindings = runSast(files);

    const ruleList = Array.from(new Set(sastFindings.map((f) => f.rule_id.split(".")[2]))).join(
      ", ",
    );
    addLog(
      `  sast complete · ${sastFindings.length} finding(s) · rules matched: ${ruleList || "none"}`,
      sastFindings.length > 0 ? "err" : "ok",
    );
    sastFindings.forEach((f) =>
      addLog(
        `  ✖ [sast] ${f.file_path}:${f.line_start}  ${f.rule_id}  ${f.cwe}  ${f.severity}`,
        "err",
      ),
    );

    // ── Pre-flight Key Check ──────────────────────────────────────────────────
    addLog(`▸ pre-flight: authenticating ${providerLabel}…`, "dim");
    const preflight = await preflightCheckProvider(effectiveKey, {
      explicitProvider: primaryProviderChoice !== "auto" ? primaryProviderChoice : undefined,
      baseUrl: customBaseUrl,
    });

    if (!preflight.ok) {
      if (preflight.isAuthError) {
        addLog(`✖ ${preflight.errorMessage}`, "err");
        if (effectiveBackupKey) {
          const backupDetected = detectProvider(
            effectiveBackupKey,
            backupProviderChoice !== "auto" ? backupProviderChoice : undefined,
          );
          const backupLabel = PROVIDER_INFOS[backupDetected]?.name ?? "Backup Provider";
          addLog(`▸ primary key rejected; testing backup provider (${backupLabel})…`, "warn");
          const backupPreflight = await preflightCheckProvider(effectiveBackupKey, {
            explicitProvider: backupProviderChoice !== "auto" ? backupProviderChoice : undefined,
            baseUrl: customBaseUrl,
          });

          if (backupPreflight.ok) {
            addLog(
              `✓ backup provider (${backupLabel}) authenticated successfully. Switched to backup key.`,
              "ok",
            );
            effectiveKey = effectiveBackupKey;
            effectiveBackupKey = "";
            setPreflightError(null);
          } else {
            const fullErr = `${preflight.errorMessage} Backup key also failed: ${backupPreflight.errorMessage}`;
            addLog(`✖ ${fullErr}`, "err");
            setError(fullErr);
            setPreflightError(backupPreflight);
            await updateScanStatus(scanRun.id, "failed");
            setScanning(false);
            return;
          }
        } else {
          setError(preflight.errorMessage || "API key rejected.");
          setPreflightError(preflight);
          await updateScanStatus(scanRun.id, "failed");
          setScanning(false);
          return;
        }
      } else {
        setError(preflight.errorMessage || "Pre-flight check failed.");
        setPreflightError(preflight);
        addLog(`✖ ${preflight.errorMessage}`, "err");
        if (preflight.urlTried) {
          addLog(`  url tried: ${preflight.urlTried}`, "dim");
        }
        if (preflight.checklist && preflight.checklist.length > 0) {
          addLog("  checklist to verify:", "warn");
          preflight.checklist.forEach((item) => addLog(`   • ${item}`, "dim"));
        }
        if (preflight.workaround) {
          addLog(`  workaround: ${preflight.workaround}`, "warn");
        }
        await updateScanStatus(scanRun.id, "failed");
        setScanning(false);
        return;
      }
    } else {
      setPreflightError(null);
      addLog(`  ✓ ${providerLabel} authenticated (${preflight.keyHint})`, "ok");
    }

    // ── 3b. LLM secondary pass (heuristic — for logic bugs SAST can't catch) ─
    addLog(`▸ ${providerLabel}: heuristic secondary pass (logic/access-control bugs)…`, "warn");

    // Send files in small batches; LLM findings are labeled llm-heuristic
    const llmFindings: any[] = [];
    const batches: Array<typeof files> = [];
    for (let i = 0; i < files.length; i += 6) batches.push(files.slice(i, i + 6));

    try {
      for (let b = 0; b < batches.length; b++) {
        addLog(`  llm batch ${b + 1}/${batches.length}: ${batches[b]!.length} files…`, "dim");
        const raw = await analyzeCodeForVulnerabilities(batches[b]!, effectiveKey);
        // Only keep LLM findings NOT already covered by a SAST rule at the same file+line
        const novel = raw.filter(
          (lf) =>
            !sastFindings.some(
              (sf) => sf.file_path === lf.file_path && Math.abs(sf.line_start - lf.line_start) <= 3,
            ),
        );
        llmFindings.push(...novel.map((f) => ({ ...f, source: "llm-heuristic" })));
      }
    } catch (err: any) {
      const errorMsg = redactKeys(err?.message || String(err), [effectiveKey, effectiveBackupKey]);
      const isAuthErr =
        err?.status === 401 ||
        err?.status === 403 ||
        err?.isAuthRejected ||
        errorMsg.includes("rejected your API key") ||
        errorMsg.includes("HTTP 401") ||
        errorMsg.includes("HTTP 403");

      if (isAuthErr) {
        addLog(`✖ Authentication error: ${errorMsg}`, "err");
        setError(errorMsg);
        await updateScanStatus(scanRun.id, "failed");
        setScanning(false);
        return;
      }
      addLog(`  ✖ llm heuristic pass error: ${errorMsg}`, "err");
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
      llm_only_findings: llmFindings.length, // what LLM-only scan would surface
      sast_findings: sastFindings.length, // what deterministic rules surface
      total_combined: allFindings.length,
      false_negative_reduction:
        sastFindings.length -
        llmFindings.filter((lf) => sastFindings.some((sf) => sf.file_path === lf.file_path)).length,
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

    // ── 4. Persist all findings (batched insert) ──────────────────────────────
    const insertPayload = allFindings.map((f) => ({
      scan_run_id: scanRun.id,
      project_id: projectId,
      tool: (f as { source?: string }).source === "sast" ? "sast-rules" : "gemini-llm-heuristic",
      rule_id: f.rule_id,
      cwe: f.cwe,
      severity: f.severity,
      file_path: f.file_path,
      line_start: f.line_start,
      line_end: f.line_end,
      vulnerability_class: f.vulnerability_class,
      raw_message: f.raw_message,
      matched_text: (f as any).matched_text ?? null,
      status: "open",
      code_lines: f.code_lines,
    }));

    const { data: insertedFindings, error: insertErr } = await supabase
      .from("findings")
      .insert(insertPayload)
      .select("id");

    if (insertErr || !insertedFindings) {
      throw new Error(`Failed to save findings: ${insertErr?.message}`);
    }

    const insertedFindingIds = insertedFindings.map((r: { id: string }) => r.id);
    addLog(
      `  ✓ ${insertedFindingIds.length}/${allFindings.length} findings saved to database`,
      "ok",
    );

    // Remove old post-insert sanity check block (now using batched insert which is atomic)

    // ── 5. Generate explanations (LLM — anchored to specific finding) ─────────
    setStage("explaining");
    await updateScanStatus(scanRun.id, "explaining");
    addLog(`▸ ${providerLabel}: generating plain-language explanations per finding…`, "warn");

    const { data: findingsData } = await supabase
      .from("findings")
      .select("*")
      .eq("scan_run_id", scanRun.id);

    const numFindings = findingsData?.length ?? 0;
    const estimatedCalls = numFindings * 3;
    if (estimatedCalls > 15) {
      addLog(
        `  ⓘ [pre-flight estimate] scan requires ~${estimatedCalls} LLM requests. Automatic multi-model fallback enabled across endpoints.`,
        "dim",
      );
    }

    const explanationMap = new Map<string, string>();
    const falsePositiveFindings = new Set<string>();

    for (const f of findingsData ?? []) {
      try {
        const fileContent = fileMap.get(f.file_path);
        const explanation = await generateExplanation(
          f,
          effectiveKey,
          effectiveBackupKey,
          user?.id,
          fileContent,
        );
        const isFp = explanation.likely_false_positive === true;
        if (isFp) {
          falsePositiveFindings.add(f.id);
        }

        const { data: expRow } = await supabase
          .from("explanations")
          .insert({
            finding_id: f.id,
            what_it_is: explanation.what_it_is,
            why_it_happened: explanation.why_it_happened,
            owasp_category: explanation.owasp_category,
            how_fix_works: explanation.how_fix_works,
            technical_explanation: explanation.technical_explanation,
            simplified_explanation: explanation.simplified_explanation,
            attack_idea: explanation.attack_idea ?? null,
            key_takeaway: explanation.key_takeaway ?? null,
            likely_false_positive: explanation.likely_false_positive ?? null,
            false_positive_reason: explanation.false_positive_reason ?? null,
            confidence_note: explanation.confidence_note ?? null,
            raw_explanation: (explanation.raw_explanation as any) ?? null,
            model: explanation.model || providerLabel,
            generated_at: new Date().toISOString(),
          })
          .select("id")
          .single();
        if (expRow) explanationMap.set(f.id, expRow.id);
        await supabase
          .from("findings")
          .update({ status: isFp ? "likely_false_positive" : "explained" })
          .eq("id", f.id);

        if (isFp) {
          addLog(
            `  ⚑ flagged likely false positive: ${f.file_path}:${f.line_start ?? 1} (${explanation.false_positive_reason || "safe code"})`,
            "warn",
          );
        } else {
          addLog(`  ✓ explained: ${f.file_path}:${f.line_start ?? 1}`, "ok");
        }
      } catch (err: any) {
        const errorMsg = redactKeys(err?.message || String(err), [
          effectiveKey,
          effectiveBackupKey,
        ]);
        const isAuthErr =
          err?.status === 401 ||
          err?.status === 403 ||
          err?.isAuthRejected ||
          errorMsg.includes("rejected your API key") ||
          errorMsg.includes("HTTP 401") ||
          errorMsg.includes("HTTP 403");

        if (isAuthErr) {
          addLog(`✖ Authentication error: ${errorMsg}`, "err");
          setError(errorMsg);
          await updateScanStatus(scanRun.id, "failed");
          setScanning(false);
          return;
        }

        addLog(`  ✖ explanation error (${f.file_path}:${f.line_start ?? 1}): ${errorMsg}`, "err");
      }
    }

    // ── 6. Generate patches ───────────────────────────────────────────────────
    setStage("patching");
    await updateScanStatus(scanRun.id, "patching");
    addLog(`▸ ${providerLabel}: generating candidate patches…`, "warn");

    const patchMap = new Map<string, string>();
    for (const f of findingsData ?? []) {
      const isFp =
        falsePositiveFindings.has(f.id) ||
        f.status === "likely_false_positive" ||
        f.status === "dismissed" ||
        isIgnoredPathOrLiteral(f.file_path, f.matched_text);

      if (isFp) {
        addLog(
          `  ⊘ skipping patch for false positive/suppressed: ${f.file_path}:${f.line_start ?? 1}`,
          "dim",
        );
        continue;
      }

      try {
        const fileContent = fileMap.get(f.file_path);
        const patch = await generatePatch(
          f,
          fileContent,
          effectiveKey,
          effectiveBackupKey,
          user?.id,
        );
        const expId = explanationMap.get(f.id);
        const { data: patchRow } = await supabase
          .from("patches")
          .insert({
            finding_id: f.id,
            diff: patch.diff,
            explanation_id: expId ?? null,
            model: providerLabel,
            generated_at: new Date().toISOString(),
            validation_new_issues: 0,
          })
          .select("id")
          .single();
        if (patchRow) patchMap.set(f.id, patchRow.id);
        await supabase.from("findings").update({ status: "patched" }).eq("id", f.id);
        addLog(`  ✓ patch generated: ${f.file_path}:${f.line_start ?? 1}`, "ok");
      } catch (err: any) {
        const errorMsg = redactKeys(err?.message || String(err), [
          effectiveKey,
          effectiveBackupKey,
        ]);
        const isAuthErr =
          err?.status === 401 ||
          err?.status === 403 ||
          err?.isAuthRejected ||
          errorMsg.includes("rejected your API key") ||
          errorMsg.includes("HTTP 401") ||
          errorMsg.includes("HTTP 403");

        if (isAuthErr) {
          addLog(`✖ Authentication error: ${errorMsg}`, "err");
          setError(errorMsg);
          await updateScanStatus(scanRun.id, "failed");
          setScanning(false);
          return;
        }

        addLog(`  ✖ patch error (${f.file_path}:${f.line_start ?? 1}): ${errorMsg}`, "err");
      }
    }

    // ── 7. Validate patches ───────────────────────────────────────────────────
    setStage("validating");
    await updateScanStatus(scanRun.id, "validating");
    addLog(`▸ ${providerLabel}: sandbox validation (re-analysis per patch)…`, "warn");

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
        // Pass original file content for deterministic diff-apply + SAST re-scan
        const fileContent = fileMap.get(f.file_path);
        const validation = await validatePatch(f, patchRow?.diff ?? "", fileContent, effectiveKey);
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
            validation_diff_applies: validation.diff_applies,
            validation_vulnerability_gone: validation.vulnerability_gone,
            validation_syntax_ok: validation.syntax_ok,
            validation_new_issues: validation.new_issues,
            validation_method: validation.validation_method,
            validation_llm_review: validation.llm_review ?? null,
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
          `  ${patchId.slice(0, 6)}  diff_applies:${validation.diff_applies ? "✓" : "✗"}  vuln_gone:${validation.vulnerability_gone === null ? "n/a" : validation.vulnerability_gone ? "✓" : "✗"}  new_issues:${validation.new_issues}  syntax:${validation.syntax_ok === null ? "n/a" : validation.syntax_ok ? "✓" : "✗"}  method:${validation.validation_method}  → ${validation.verdict.toUpperCase()}`,
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

    // ── 8. Finalize — compute real metrics from DB ────────────────────────────
    const { data: finalFindings, error: finalErr } = await supabase
      .from("findings")
      .select(
        "*, patches(validation_verdict, validation_diff_applies, validation_vulnerability_gone, validation_syntax_ok, validation_new_issues)",
      )
      .eq("scan_run_id", scanRun.id);

    if (finalErr) throw new Error(`Finalize query error: ${finalErr.message}`);

    const dbTotal = finalFindings?.length ?? 0;

    // Compute each metric independently from real data
    let diffsApplied = 0;
    let vulnRemoved = 0;
    let syntaxPassed = 0;
    let syntaxChecked = 0;
    let newVulnsCount = 0;

    finalFindings?.forEach(
      (f: {
        patches?: Array<{
          validation_diff_applies?: boolean;
          validation_vulnerability_gone?: boolean | null;
          validation_syntax_ok?: boolean | null;
          validation_new_issues?: number;
        }> | null;
      }) => {
        const patchObj = Array.isArray(f.patches) ? f.patches[0] : null;
        if (!patchObj) return;
        if (patchObj.validation_diff_applies === true) diffsApplied++;
        if (patchObj.validation_vulnerability_gone === true) vulnRemoved++;
        if (patchObj.validation_syntax_ok !== null && patchObj.validation_syntax_ok !== undefined) {
          syntaxChecked++;
          if (patchObj.validation_syntax_ok === true) syntaxPassed++;
        }
        if ((patchObj.validation_new_issues ?? 0) > 0) newVulnsCount++;
      },
    );

    const patchSuccessRate = dbTotal > 0 ? diffsApplied / dbTotal : 1;
    const vulnRemovalRate = dbTotal > 0 ? vulnRemoved / dbTotal : 1;
    const syntaxPassRate = syntaxChecked > 0 ? syntaxPassed / syntaxChecked : null;
    const newVulnsRate = dbTotal > 0 ? newVulnsCount / dbTotal : 0;
    const dbAcceptedCount =
      finalFindings?.filter((f: { patches?: Array<{ validation_verdict?: string }> | null }) => {
        const p = Array.isArray(f.patches) ? f.patches[0] : null;
        return p?.validation_verdict === "accepted";
      }).length ?? 0;

    await supabase
      .from("scan_runs")
      .update({
        status: "done",
        finished_at: new Date().toISOString(),
        findings_count: dbTotal,
        patch_success_rate: patchSuccessRate,
        syntax_pass_rate: syntaxPassRate,
        vuln_removal_rate: vulnRemovalRate,
        new_vulns_rate: newVulnsRate,
        acceptance_rate: 0, // Updated after developer decisions
        time_to_fix_seconds: Math.round(totalFixTime),
      })
      .eq("id", scanRun.id);

    // Compute and persist security score
    const score = await recomputeScore(projectId, user?.id ?? "");

    setStage("done");
    addLog("", "dim");
    addLog(
      `done · ${dbTotal} findings · ${dbAcceptedCount}/${dbTotal} patches validated-accepted · score: ${score.overall}`,
      "ok",
    );
    setDone(true);
  } // end runScanPipeline

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

  const primaryProvider = detectProvider(
    aiApiKey,
    primaryProviderChoice !== "auto" ? primaryProviderChoice : undefined,
  );
  const backupProvider = detectProvider(
    backupApiKey,
    backupProviderChoice !== "auto" ? backupProviderChoice : undefined,
  );
  const isCustomEndpointInUse =
    primaryProvider === "freellmapi" ||
    primaryProvider === "custom_openai" ||
    backupProvider === "freellmapi" ||
    backupProvider === "custom_openai";

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
        <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">scan pipeline</p>
        <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight">
          {project?.name ?? "…"}
        </h1>
        {project?.repo_url && (
          <p className="mt-1 font-mono text-xs text-subtle">{project.repo_url}</p>
        )}

        {/* API keys inline config (only before scanning) */}
        {!scanning && !done && (
          <div className="mt-6 rounded-lg border border-border bg-elevated p-4 space-y-4">
            <div className="flex items-center justify-between">
              <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                pipeline configuration
              </p>
              <span className="font-mono text-[10px] text-subtle/70">
                keys stay in browser sessionStorage only
              </span>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              {/* Primary Key & Provider */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                    Primary Provider
                  </label>
                  {aiApiKey && primaryProvider !== "unknown" && (
                    <span className="rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[9px] text-accent">
                      {PROVIDER_INFOS[primaryProvider].name}
                    </span>
                  )}
                </div>
                <select
                  value={primaryProviderChoice}
                  onChange={(e) => {
                    const val = e.target.value as "auto" | DetectedProvider;
                    setPrimaryProviderChoice(val);
                    sessionStorage.setItem("sl_ai_provider_choice", val);
                  }}
                  className="w-full rounded-lg border border-border bg-background px-3 py-1.5 font-mono text-xs text-foreground focus:border-accent/50 focus:outline-none"
                >
                  {PROVIDER_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>

                <div className="flex items-center justify-between">
                  <label className="block font-mono text-[10px] uppercase tracking-wider text-subtle">
                    Primary API Key
                  </label>
                  {aiApiKey.trim() && primaryProvider !== "unknown" && (
                    <button
                      type="button"
                      onClick={handleRetryPreflight}
                      disabled={checkingPreflight}
                      className="flex items-center gap-1 font-mono text-[9px] text-accent hover:underline disabled:opacity-50 cursor-pointer"
                    >
                      <RefreshCw
                        className={`size-2.5 ${checkingPreflight ? "animate-spin" : ""}`}
                      />
                      {checkingPreflight ? "testing…" : "test connection"}
                    </button>
                  )}
                </div>
                <input
                  type="password"
                  value={aiApiKey}
                  onChange={(e) => {
                    const val = e.target.value;
                    setAiApiKey(val);
                    if (val) {
                      sessionStorage.setItem("sl_ai_key", val);
                    } else {
                      sessionStorage.removeItem("sl_ai_key");
                    }
                  }}
                  placeholder="AQ.…, AIzaSy…, gsk_…, sk-or-…, freellmapi-…, or sk-…"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                />

                {aiApiKey && primaryProvider === "unknown" ? (
                  <div className="rounded border border-danger/30 bg-danger/10 p-2 font-mono text-[10px] text-danger flex items-start gap-1.5">
                    <AlertTriangle className="size-3.5 shrink-0 mt-0.5" />
                    <span>
                      Key format not recognized. Choose the provider manually from the dropdown
                      above.
                    </span>
                  </div>
                ) : aiApiKey ? (
                  <p className="font-mono text-[10px] text-success/80">
                    ✓ key remembered for this session ({PROVIDER_INFOS[primaryProvider]?.name})
                  </p>
                ) : (
                  <p className="font-mono text-[10px] text-danger/80">
                    ✗ required — paste your Gemini, Groq, OpenRouter, or FreeLLMAPI key
                  </p>
                )}
              </div>

              {/* Backup Key & Provider */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                    Backup Provider <span className="text-subtle/50">(failover)</span>
                  </label>
                  {backupApiKey && backupProvider !== "unknown" && (
                    <span className="rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[9px] text-accent">
                      {PROVIDER_INFOS[backupProvider].name}
                    </span>
                  )}
                </div>
                <select
                  value={backupProviderChoice}
                  onChange={(e) => {
                    const val = e.target.value as "auto" | DetectedProvider;
                    setBackupProviderChoice(val);
                    sessionStorage.setItem("sl_ai_backup_provider_choice", val);
                  }}
                  className="w-full rounded-lg border border-border bg-background px-3 py-1.5 font-mono text-xs text-foreground focus:border-accent/50 focus:outline-none"
                >
                  {PROVIDER_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>

                <label className="block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  Backup API Key <span className="text-subtle/50">(optional)</span>
                </label>
                <input
                  type="password"
                  value={backupApiKey}
                  onChange={(e) => {
                    const val = e.target.value;
                    setBackupApiKey(val);
                    if (val) {
                      sessionStorage.setItem("sl_ai_backup_key", val);
                    } else {
                      sessionStorage.removeItem("sl_ai_backup_key");
                    }
                  }}
                  placeholder="Secondary key (e.g. Groq gsk_… or OpenRouter sk-or-…)"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                />

                {backupApiKey && backupProvider === "unknown" ? (
                  <div className="rounded border border-danger/30 bg-danger/10 p-2 font-mono text-[10px] text-danger flex items-start gap-1.5">
                    <AlertTriangle className="size-3.5 shrink-0 mt-0.5" />
                    <span>
                      Backup key format not recognized. Choose the provider manually from the
                      dropdown.
                    </span>
                  </div>
                ) : backupApiKey && isSameProviderBackup(aiApiKey, backupApiKey) ? (
                  <div className="rounded border border-warning/30 bg-warning/10 p-2 font-mono text-[10px] text-warning flex items-start gap-1.5">
                    <AlertTriangle className="size-3.5 shrink-0 mt-0.5" />
                    <span>
                      Backup key is from the same provider ({PROVIDER_INFOS[backupProvider]?.name}).
                      Rate limits and quotas may be shared across the same organization. Use a
                      different provider (e.g. Gemini, Groq, OpenRouter) for true independent
                      failover.
                    </span>
                  </div>
                ) : backupApiKey ? (
                  <p className="font-mono text-[10px] text-success/80">
                    ✓ independent backup key active on rate limit failover
                  </p>
                ) : (
                  <p className="font-mono text-[10px] text-subtle/50">
                    Used automatically if primary key hits 429 quota
                  </p>
                )}
              </div>
            </div>

            {/* Custom Endpoint Settings (FreeLLMAPI / Custom OpenAI-compatible) */}
            {isCustomEndpointInUse && (
              <div className="mt-4 rounded border border-border/80 bg-background/50 p-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] font-medium text-foreground">
                    Custom OpenAI-compatible / FreeLLMAPI Endpoint
                  </span>
                  <span className="font-mono text-[9px] text-accent">OpenAI-Compatible</span>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                      Endpoint Base URL
                    </label>
                    <input
                      type="text"
                      value={customBaseUrl}
                      onChange={(e) => {
                        const val = e.target.value;
                        setCustomBaseUrl(val);
                        sessionStorage.setItem("sl_ai_custom_url", val);
                      }}
                      placeholder="http://localhost:3001/v1"
                      className="w-full rounded-lg border border-border bg-background px-3 py-1.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                    />
                    {!validateEndpointUrl(customBaseUrl).isValid && (
                      <p className="mt-1 font-mono text-[10px] text-danger">
                        {validateEndpointUrl(customBaseUrl).error}
                      </p>
                    )}
                  </div>

                  <div>
                    <div className="mb-1 flex items-center justify-between">
                      <label className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                        Model ID
                      </label>
                      <button
                        type="button"
                        onClick={handleFetchCustomModels}
                        disabled={loadingModels || !validateEndpointUrl(customBaseUrl).isValid}
                        className="flex items-center gap-1 font-mono text-[9px] text-accent hover:underline disabled:opacity-50"
                      >
                        <RefreshCw className={`size-2.5 ${loadingModels ? "animate-spin" : ""}`} />
                        {loadingModels ? "fetching…" : "fetch live models"}
                      </button>
                    </div>

                    {customModels.length > 0 ? (
                      <select
                        value={customModel}
                        onChange={(e) => {
                          setCustomModel(e.target.value);
                          sessionStorage.setItem("sl_ai_custom_model", e.target.value);
                        }}
                        className="w-full rounded-lg border border-border bg-background px-3 py-1.5 font-mono text-xs text-foreground focus:border-accent/50 focus:outline-none"
                      >
                        <option value="freellmapi/auto">freellmapi/auto (default)</option>
                        {customModels
                          .filter((m) => m !== "freellmapi/auto")
                          .map((m) => (
                            <option key={m} value={m}>
                              {m}
                            </option>
                          ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        value={customModel}
                        onChange={(e) => {
                          setCustomModel(e.target.value);
                          sessionStorage.setItem("sl_ai_custom_model", e.target.value);
                        }}
                        placeholder="freellmapi/auto"
                        className="w-full rounded-lg border border-border bg-background px-3 py-1.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                      />
                    )}

                    {modelsError && (
                      <p className="mt-1 font-mono text-[10px] text-danger">{modelsError}</p>
                    )}
                  </div>
                </div>

                {typeof window !== "undefined" &&
                  window.location.protocol === "https:" &&
                  customBaseUrl.startsWith("http://") && (
                    <div className="rounded border border-warning/30 bg-warning/5 p-2 font-mono text-[10px] text-warning/90">
                      <strong>Browser restriction:</strong> This frontend is loaded over HTTPS. Web
                      browsers block direct requests from HTTPS pages to unencrypted HTTP endpoints
                      (Mixed Content). For local endpoints like{" "}
                      <code>http://localhost:3001/v1</code>, run this app locally (
                      <code>npm run dev</code>) or expose your local endpoint through an HTTPS
                      tunnel (e.g. ngrok or Cloudflare tunnel).
                    </div>
                  )}

                <div className="rounded border border-accent/20 bg-accent/5 p-2 font-mono text-[10px] text-subtle/80 flex items-start gap-1.5">
                  <ShieldAlert className="size-3.5 shrink-0 text-accent mt-0.5" />
                  <span>
                    Requests go to the endpoint you entered, which routes them to free-tier
                    providers. Free tiers may use your code to improve their products. Don't scan
                    private code.
                  </span>
                </div>
              </div>
            )}

            <div className="mt-2">
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

            <p className="font-mono text-[10px] text-warning/80 flex items-center gap-1.5">
              <AlertTriangle className="size-3 shrink-0" />
              Note: Free-tier provider prompts may be used to improve AI models. Avoid scanning
              private confidential code.
            </p>
            <p className="font-mono text-[10px] text-subtle/60 flex items-center gap-1.5">
              <AlertTriangle className="size-3 shrink-0" />
              Keys stay in your browser only — never sent to our servers. The key is remembered for
              this tab session.
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
              {i < STAGES.length - 1 && <span className="text-subtle/30">→</span>}
            </span>
          ))}
        </div>

        {/* Quota Exceeded Alert Banner */}
        {quotaExceededCount > 0 && (
          <div className="mt-6 flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 font-mono text-xs text-amber-300">
            <AlertTriangle className="size-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <p className="font-semibold text-amber-200">Rate Limit / Model Quota Exceeded</p>
              <p className="mt-1 text-amber-300/90 leading-relaxed">
                This scan reached rate or quota limits across AI candidate models.{" "}
                {quotaExceededCount} finding operations were skipped. Add a valid AI API key in the
                Pipeline Configuration above, then re-run the scan.
              </p>
              <Link
                to="/scan/$projectId"
                params={{ projectId }}
                className="mt-2 inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-[11px] text-amber-200 hover:bg-amber-500/20 transition-colors"
              >
                Scroll up → update AI API key and re-run
              </Link>
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

        {preflightError ? (
          <div className="mt-4 rounded-lg border border-danger/40 bg-danger/10 p-4 space-y-3 font-mono text-xs">
            <div className="flex items-start gap-2.5">
              <AlertTriangle className="size-4 shrink-0 text-danger mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold text-danger">
                  {preflightError.providerName} Pre-Flight Check Failed
                </p>
                <p className="text-foreground/90">{preflightError.errorMessage}</p>
                {preflightError.urlTried && (
                  <p className="text-[11px] text-subtle">
                    URL tried: <code className="text-foreground">{preflightError.urlTried}</code>
                  </p>
                )}
              </div>
            </div>

            {preflightError.checklist && preflightError.checklist.length > 0 && (
              <div className="rounded border border-border/60 bg-background/60 p-3 space-y-1.5">
                <p className="font-semibold text-[11px] text-foreground">
                  Troubleshooting checklist:
                </p>
                <ul className="space-y-1 text-[11px] text-subtle">
                  {preflightError.checklist.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <span className="text-accent">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {preflightError.workaround && (
              <div className="rounded border border-accent/30 bg-accent/5 p-3 space-y-1">
                <p className="font-semibold text-[11px] text-accent">Recommended workaround:</p>
                <p className="text-[11px] text-foreground/80 leading-relaxed">
                  {preflightError.workaround}
                </p>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-1">
              <button
                type="button"
                onClick={handleRetryPreflight}
                disabled={checkingPreflight}
                className="inline-flex items-center gap-1.5 rounded-full border border-border bg-elevated px-3 py-1 text-[11px] text-foreground hover:bg-background transition-colors disabled:opacity-50 cursor-pointer"
              >
                <RefreshCw className={`size-3 ${checkingPreflight ? "animate-spin" : ""}`} />
                {checkingPreflight ? "checking…" : "retry check"}
              </button>

              {backupApiKey && (
                <button
                  type="button"
                  onClick={handleUseBackupProvider}
                  className="inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-[11px] text-accent hover:bg-accent/20 transition-colors cursor-pointer"
                >
                  use backup provider
                </button>
              )}
            </div>
          </div>
        ) : error ? (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/5 px-4 py-3">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-danger" />
            <p className="font-mono text-xs text-danger">{error}</p>
          </div>
        ) : null}

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
