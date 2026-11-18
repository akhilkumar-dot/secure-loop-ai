import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  ArrowLeft,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Lock,
  Sparkles,
  RefreshCw,
  Download,
  Copy,
  Check,
  AlertTriangle,
} from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import {
  supabase,
  type DbFinding,
  type DbExplanation,
  type DbPatch,
  type DbDeveloperDecision,
  type DbFalsePositiveSuppression,
} from "@/lib/supabase";
import { generateExplanation, generatePatch, validatePatch } from "@/lib/ai-pipeline";
import { generateRealExplanation, type ExplanationOutput } from "@/lib/explanation-service";
import { checkExplanationGrounding, type GroundingCheckResult } from "@/lib/grounding-checker";
import { detectProvider, PROVIDER_INFOS } from "@/lib/ai-provider-detector";
import {
  Logo,
  SeverityBadge,
  StatusBadge,
  TerminalWindow,
  CodeView,
  DiffView,
} from "@/components/chrome";
import { recomputeScore } from "@/lib/score";
import {
  pickQuestion,
  getMisconceptionId,
  getUnlockedTiers,
  type VulnClass,
  type Tier,
  type TieredQuestion,
} from "@/lib/quiz-bank";
import { detectAndSaveRecurringMisconceptions, MISCONCEPTION_LABELS } from "@/lib/misconception";
import { updateMasteryAfterAnswer } from "@/lib/mastery-db";
import { checkTierAllowed } from "@/lib/tier-progression";

export const Route = createFileRoute("/finding/$findingId")({
  head: () => ({
    meta: [{ title: "Finding Detail — SecureLoop" }],
  }),
  component: FindingDetailPage,
});

interface FullFinding extends DbFinding {
  explanation?: DbExplanation;
  patch?: DbPatch;
}

function FindingDetailPage() {
  const { findingId } = Route.useParams();
  const navigate = useNavigate();
  const { user, loading } = useAuth();
  const [finding, setFinding] = useState<FullFinding | null>(null);
  const [loadingData, setLoadingData] = useState(true);
  const [logsOpen, setLogsOpen] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const [decisionDone, setDecisionDone] = useState<"accept" | "reject" | null>(null);
  const [showQuiz, setShowQuiz] = useState(false);
  const [quizAnswer, setQuizAnswer] = useState<number | null>(null);
  const [quizSubmitted, setQuizSubmitted] = useState(false);

  // Remediation & decision states
  const [commitSha, setCommitSha] = useState<string | null>(null);
  const [existingDecision, setExistingDecision] = useState<DbDeveloperDecision | null>(null);
  const [suppression, setSuppression] = useState<DbFalsePositiveSuppression | null>(null);
  const [showOverrideConfirm, setShowOverrideConfirm] = useState(false);
  const [showRejectDialog, setShowRejectDialog] = useState(false);
  const [rejectionNote, setRejectionNote] = useState("");
  const [showDismissDialog, setShowDismissDialog] = useState(false);
  const [dismissReasonCode, setDismissReasonCode] = useState<string>("test_code");
  const [dismissReasonText, setDismissReasonText] = useState("");
  const [copiedDiff, setCopiedDiff] = useState(false);

  // Tiered quiz state
  const [activeQuestion, setActiveQuestion] = useState<TieredQuestion | null>(null);
  const [activeTier, setActiveTier] = useState<Tier>("easy");
  const [unlockedTiers, setUnlockedTiers] = useState<Set<Tier>>(new Set(["easy"]));
  const [attemptCount, setAttemptCount] = useState(0);
  const [loadingTier, setLoadingTier] = useState(false);
  const [explanationMode, setExplanationMode] = useState<"technical" | "simplified">("technical");

  // AI on-demand generation state
  const [regenerating, setRegenerating] = useState(false);
  const [regenKey, setRegenKey] = useState(() => {
    if (typeof window !== "undefined") {
      return sessionStorage.getItem("sl_ai_key") ?? "";
    }
    return "";
  });
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [regenError, setRegenError] = useState<string | null>(null);
  const [groundingResult, setGroundingResult] = useState<GroundingCheckResult | null>(null);

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user && findingId) fetchData();
  }, [user, findingId]);

  async function fetchData() {
    setLoadingData(true);

    const { data: f } = await supabase.from("findings").select("*").eq("id", findingId).single();

    if (!f) {
      setLoadingData(false);
      return;
    }

    // Resolve commit sha from scan_runs
    let sha: string | null = null;
    if (f.scan_run_id) {
      const { data: run } = await supabase
        .from("scan_runs")
        .select("commit_sha")
        .eq("id", f.scan_run_id)
        .maybeSingle();
      sha = run?.commit_sha ?? null;
    }
    setCommitSha(sha);

    const { data: explanation } = await supabase
      .from("explanations")
      .select("*")
      .eq("finding_id", findingId)
      .maybeSingle();

    const { data: patch } = await supabase
      .from("patches")
      .select("*")
      .eq("finding_id", findingId)
      .maybeSingle();

    // Check for existing decision (only if patch exists)
    if (patch?.id && user?.id) {
      const { data: decision } = await supabase
        .from("developer_decisions")
        .select("*")
        .eq("patch_id", patch.id)
        .eq("user_id", user.id)
        .order("decided_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (decision) {
        setDecisionDone(decision.action as "accept" | "reject");
        setExistingDecision(decision as DbDeveloperDecision);
        if (decision.rejection_note) {
          setRejectionNote(decision.rejection_note);
        }
      }
    }

    // Check for existing suppression record
    const { data: supp } = await supabase
      .from("false_positive_suppressions")
      .select("*")
      .eq("finding_id", findingId)
      .maybeSingle();

    if (supp) {
      setSuppression(supp as DbFalsePositiveSuppression);
    }

    if (explanation) {
      const exp = explanation as DbExplanation;
      if (f.code_lines && exp.raw_explanation) {
        const codeText = Array.isArray(f.code_lines)
          ? (f.code_lines as Array<{ code: string }>).map((c) => c.code).join("\n")
          : "";
        const gr = checkExplanationGrounding(exp.raw_explanation as any, codeText, f.file_path);
        setGroundingResult(gr);
      }
    }

    setFinding({
      ...(f as DbFinding),
      explanation: (explanation as DbExplanation) ?? undefined,
      patch: (patch as DbPatch) ?? undefined,
    });
    setLoadingData(false);
  }

  async function makeDecision(action: "accept" | "reject", override = false, customNote?: string) {
    if (!finding?.patch || !user) return;
    setDeciding(true);

    const isValidationRejected = finding.patch.validation_verdict === "rejected";
    const noteToSave = customNote !== undefined ? customNote : rejectionNote;

    const { data: decisionRecord } = await supabase
      .from("developer_decisions")
      .insert({
        patch_id: finding.patch.id,
        user_id: user.id,
        action,
        is_override: override,
        validation_was_rejected: isValidationRejected,
        rejection_note: action === "reject" ? noteToSave.trim() || null : null,
      })
      .select("*")
      .single();

    if (decisionRecord) {
      setExistingDecision(decisionRecord as DbDeveloperDecision);
    }

    // Update finding status
    await supabase
      .from("findings")
      .update({ status: action === "accept" ? "accepted" : "rejected" })
      .eq("id", findingId);

    // Recompute security score so dashboard reflects the decision immediately
    if (finding.project_id) {
      await recomputeScore(finding.project_id, user.id);
    }

    setFinding((prev) =>
      prev ? { ...prev, status: action === "accept" ? "accepted" : "rejected" } : null,
    );
    setDecisionDone(action);
    setShowOverrideConfirm(false);
    setShowRejectDialog(false);
    setDeciding(false);
    setShowQuiz(true);
    // Eagerly load the quiz question for this vuln class
    if (finding.vulnerability_class) {
      await loadQuizForFinding(finding.vulnerability_class as VulnClass);
    }
  }

  async function loadQuizForFinding(vulnClass: VulnClass) {
    if (!user) return;
    setLoadingTier(true);

    // Fetch user's attempt history for this vuln class (server-side tier check)
    const { data: pastAttempts } = await supabase
      .from("education_checks")
      .select("tier, correct, answered_at")
      .eq("user_id", user.id)
      .eq("vuln_class", vulnClass)
      .order("answered_at", { ascending: true });

    const attempts = (pastAttempts ?? []) as Array<{ tier: Tier; correct: boolean }>;
    const unlocked = getUnlockedTiers(attempts);
    setUnlockedTiers(unlocked);

    // Pick the highest unlocked tier
    const bestTier: Tier = unlocked.has("hard")
      ? "hard"
      : unlocked.has("medium")
        ? "medium"
        : "easy";
    setActiveTier(bestTier);

    // Count how many questions of this tier the user has already seen (for rotation)
    const tierAttempts = attempts.filter((a) => a.tier === bestTier);
    const count = tierAttempts.length;
    setAttemptCount(count);

    const question = pickQuestion(vulnClass, bestTier, count);
    setActiveQuestion(question);
    setLoadingTier(false);
  }

  async function handleRegenerateAi(
    apiKeyToUse?: string,
    feedbackContext?: { previousDiff?: string | undefined; rejectionNote?: string | undefined },
  ) {
    if (!finding || !user) return;
    const key = (
      apiKeyToUse ||
      regenKey ||
      (typeof window !== "undefined" ? sessionStorage.getItem("sl_ai_key") : "") ||
      ""
    ).trim();
    const backupKey =
      (typeof window !== "undefined" ? sessionStorage.getItem("sl_ai_backup_key") : "") || "";
    if (!key && !backupKey) {
      setShowKeyInput(true);
      return;
    }
    if (typeof window !== "undefined" && key) {
      sessionStorage.setItem("sl_ai_key", key);
    }

    setRegenerating(true);
    setRegenError(null);

    try {
      // 1. Resolve real file content (prefer GitHub repository fetch, fall back to scanned code lines)
      let fileContent: string | undefined;

      try {
        const { data: run } = await supabase
          .from("scan_runs")
          .select("commit_sha")
          .eq("id", finding.scan_run_id)
          .maybeSingle();

        const { data: proj } = await supabase
          .from("projects")
          .select("repo_url")
          .eq("id", finding.project_id)
          .maybeSingle();

        if (proj?.repo_url && run?.commit_sha && finding.file_path) {
          const rawUrl = proj.repo_url
            .replace(/^https?:\/\/github\.com\//, "https://raw.githubusercontent.com/")
            .replace(/\.git$/, "");
          const resp = await fetch(`${rawUrl}/${run.commit_sha}/${finding.file_path}`);
          if (resp.ok) {
            fileContent = await resp.text();
          }
        }
      } catch (fetchErr) {
        console.warn(
          "[finding-detail] GitHub raw file fetch failed, using scanned code lines:",
          fetchErr,
        );
      }

      if (!fileContent && Array.isArray(finding.code_lines) && finding.code_lines.length > 0) {
        const maxLine = Math.max(
          ...(finding.code_lines as Array<{ n: number; code: string }>).map((l) => l.n),
        );
        const fileLines: string[] = new Array(maxLine).fill("");
        for (const cl of finding.code_lines as Array<{ n: number; code: string }>) {
          fileLines[cl.n - 1] = cl.code;
        }
        fileContent = fileLines.join("\n");
      }

      if (!fileContent) {
        throw new Error(
          "Source code for this finding could not be retrieved from the repository or scan data. Please re-run the scan.",
        );
      }

      // 2. Generate real explanation
      const realExp = await generateRealExplanation({
        finding: {
          rule_id: finding.rule_id || "not provided",
          vuln_class: finding.vulnerability_class || "not provided",
          cwe: finding.cwe || "not provided",
          severity: finding.severity || "not provided",
          raw_message: finding.raw_message || "not provided",
          file_path: finding.file_path,
          line_start: finding.line_start ?? 1,
          matched_text: (finding as any).matched_text,
        },
        fileContent,
        primaryKey: key,
        backupKey: backupKey || undefined,
        userId: user.id,
        findingId: finding.id,
      });

      setGroundingResult(realExp.groundingResult);

      // 3. Persist real explanation
      const expPayload = {
        finding_id: finding.id,
        what_it_is: realExp.output.what_it_is.technical,
        why_it_happened: realExp.output.why_it_happened.technical,
        how_fix_works: realExp.output.how_fix_works.technical,
        technical_explanation: realExp.output.what_it_is.technical,
        simplified_explanation: realExp.output.what_it_is.simplified,
        attack_idea: realExp.output.attack_idea,
        key_takeaway: realExp.output.key_takeaway,
        likely_false_positive: realExp.output.likely_false_positive?.value ?? null,
        false_positive_reason: realExp.output.likely_false_positive?.reason ?? null,
        confidence_note: realExp.output.confidence_note ?? "",
        raw_explanation: realExp.output as any,
        model: realExp.modelUsed,
        generated_at: new Date().toISOString(),
      };

      let explanationId = finding.explanation?.id;
      if (explanationId) {
        await supabase.from("explanations").update(expPayload).eq("id", explanationId);
      } else {
        const { data: newExp } = await supabase
          .from("explanations")
          .insert(expPayload)
          .select("id")
          .single();
        if (newExp) explanationId = newExp.id;
      }

      // 4. Generate patch using real data (with optional rejection feedback)
      const baseFinding: {
        id?: string;
        file_path: string;
        vulnerability_class?: string;
        cwe?: string;
        raw_message?: string;
        line_start?: number;
        code_lines?: Array<{ n: number; code: string; vuln?: boolean }>;
      } = { id: finding.id, file_path: finding.file_path };
      if (finding.vulnerability_class)
        baseFinding.vulnerability_class = finding.vulnerability_class;
      if (finding.cwe) baseFinding.cwe = finding.cwe;
      if (finding.raw_message) baseFinding.raw_message = finding.raw_message;
      if (finding.line_start !== undefined) baseFinding.line_start = finding.line_start;
      if (Array.isArray(finding.code_lines)) baseFinding.code_lines = finding.code_lines as any;

      const patch = await generatePatch(
        baseFinding,
        fileContent,
        key,
        backupKey,
        user.id,
        feedbackContext,
      );

      // 5. Deterministic patch validation
      const valFinding: typeof baseFinding & { rule_id?: string; source?: string } = {
        ...baseFinding,
      };
      if (finding.rule_id) valFinding.rule_id = finding.rule_id;
      valFinding.source = finding.tool === "sast-rules" ? "sast" : "llm-heuristic";

      const validation = await validatePatch(valFinding, patch.diff, fileContent, key);

      // 6. Persist patch
      if (finding.patch?.id) {
        await supabase
          .from("patches")
          .update({
            diff: patch.diff,
            explanation_id: explanationId ?? null,
            model: realExp.modelUsed,
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
          .eq("id", finding.patch.id);
      } else {
        await supabase.from("patches").insert({
          finding_id: finding.id,
          diff: patch.diff,
          explanation_id: explanationId ?? null,
          model: realExp.modelUsed,
          generated_at: new Date().toISOString(),
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
        });
      }

      await supabase.from("findings").update({ status: "patched" }).eq("id", finding.id);

      // If we regenerated after rejection, reset decision state to allow reviewing the new patch
      if (feedbackContext?.previousDiff || feedbackContext?.rejectionNote) {
        setDecisionDone(null);
        setExistingDecision(null);
        setRejectionNote("");
        setShowRejectDialog(false);
      }

      // Reload finding data in place
      await fetchData();
    } catch (err: any) {
      console.error("[finding-regenerate] Error:", err);
      setRegenError(err?.message || "Failed to generate AI analysis. Check your API key.");
    } finally {
      setRegenerating(false);
    }
  }

  async function handleConfirmDismiss() {
    if (!finding || !user) return;
    if (dismissReasonCode === "other" && !dismissReasonText.trim()) {
      return;
    }
    setDeciding(true);

    const { data: supp } = await supabase
      .from("false_positive_suppressions")
      .insert({
        user_id: user.id,
        project_id: finding.project_id,
        finding_id: finding.id,
        rule_id: finding.rule_id || null,
        file_path: finding.file_path,
        line_start: finding.line_start ?? null,
        vulnerability_class: finding.vulnerability_class ?? null,
        reason_code: dismissReasonCode,
        reason_text: dismissReasonText.trim() || null,
      })
      .select("*")
      .single();

    if (supp) {
      setSuppression(supp as DbFalsePositiveSuppression);
    }

    await supabase.from("findings").update({ status: "dismissed" }).eq("id", findingId);

    // Recompute score so false-positive findings stop penalizing the score
    if (finding.project_id) {
      await recomputeScore(finding.project_id, user.id);
    }

    setFinding((prev) => (prev ? { ...prev, status: "dismissed" } : null));
    setShowDismissDialog(false);
    setDeciding(false);
  }

  function downloadPatchFile() {
    if (!finding?.patch?.diff) return;
    const cleanPath = (finding.file_path || "remediation").replace(/[^a-zA-Z0-9._-]/g, "_");
    const fileName = `${cleanPath}.patch`;
    const diff = finding.patch.diff;
    const header = `# SecureLoop Remediation Patch
# Target-File: ${finding.file_path}
# Target-Commit: ${commitSha || "HEAD"}
# Generated-At: ${finding.patch.generated_at || new Date().toISOString()}
# Validation-Status: ${finding.patch.validation_verdict || "unvalidated"}
# Accepted-By: ${user?.email || user?.id || "developer"}
# Override: ${existingDecision?.is_override ? "true (validation rejected)" : "false"}
#
# Apply with:
#   git apply ${fileName}
#   or: patch -p1 < ${fileName}
`;
    const fileContent =
      diff.startsWith("---") || diff.startsWith("@@")
        ? `${header}\n${diff}`
        : `${header}\n--- a/${finding.file_path}\n+++ b/${finding.file_path}\n${diff}`;
    const blob = new Blob([fileContent], { type: "text/x-diff;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function copyDiffToClipboard() {
    if (!finding?.patch?.diff) return;
    await navigator.clipboard.writeText(finding.patch.diff);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  }

  async function submitQuizAnswer() {
    if (quizAnswer === null || !finding || !user || !activeQuestion) return;

    const vulnClass = finding.vulnerability_class as VulnClass;
    const isCorrect = quizAnswer === activeQuestion.correctIndex;
    const misconceptionId = getMisconceptionId(activeQuestion, quizAnswer);

    // ── Server-side tier gate ──────────────────────────────────────────────
    // Re-verify the tier is unlocked (enforces server-side progression gate)
    const isAllowed = await checkTierAllowed(user.id, vulnClass, activeTier);
    if (!isAllowed) {
      console.warn("[quiz] Tier is locked for user, rejecting submission");
      return;
    }

    // ── Persist the answer ────────────────────────────────────────────────
    await supabase.from("education_checks").insert({
      finding_id: findingId,
      user_id: user.id,
      question_id: activeQuestion.id,
      vuln_class: vulnClass,
      tier: activeTier,
      question: activeQuestion.question,
      options: activeQuestion.options.map((o) => o.text),
      correct_index: activeQuestion.correctIndex,
      user_answer: quizAnswer,
      correct: isCorrect,
      misconception_id: misconceptionId,
      answered_at: new Date().toISOString(),
    });

    // ── Detect recurring misconceptions and persist flags ─────────────────
    const recurring = await detectAndSaveRecurringMisconceptions(user.id, vulnClass);

    // ── Update Mastery & Spaced Repetition ────────────────────────────────
    await updateMasteryAfterAnswer(user.id, vulnClass, activeTier, isCorrect, recurring.length > 0);

    setQuizSubmitted(true);
  }

  const validation = finding?.patch;
  const canAccept =
    validation?.validation_verdict === "accepted" || validation?.validation_vulnerability_gone;

  const displayStatus =
    finding?.status === "accepted"
      ? "accepted"
      : finding?.status === "rejected"
        ? "rejected"
        : finding?.status === "dismissed"
          ? "dismissed"
          : finding?.status === "likely_false_positive"
            ? "likely_false_positive"
            : finding?.patch?.validation_verdict === "rejected"
              ? "validation_rejected"
              : finding?.patch?.validation_verdict === "accepted"
                ? "validated"
                : (finding?.status ?? "open");

  // Use activeQuestion from the tiered quiz bank (loaded after decision)
  // Fall back to null if vuln class has no questions
  const quiz = activeQuestion;

  const isFalsePositive =
    finding?.status === "likely_false_positive" ||
    finding?.status === "dismissed" ||
    finding?.explanation?.likely_false_positive === true ||
    finding?.explanation?.error_type === "false_positive";

  const activeKey =
    regenKey || (typeof window !== "undefined" ? (sessionStorage.getItem("sl_ai_key") ?? "") : "");
  const detectedProvider = detectProvider(activeKey);
  const detectedProviderName = PROVIDER_INFOS[detectedProvider]?.name ?? "AI";

  if (loading || loadingData) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">loading…</span>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-danger">Finding not found.</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
          <Logo />
          <button
            onClick={() =>
              navigate({ to: "/findings/$projectId", params: { projectId: finding.project_id } })
            }
            className="flex items-center gap-1.5 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
          >
            <ArrowLeft className="size-3" />
            back to findings
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 sm:px-6 py-6 sm:py-10">
        {/* Finding header */}
        <div className="flex flex-wrap items-start gap-2.5 sm:gap-3">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={displayStatus} />
          <span className="font-mono text-xs text-subtle">{finding.cwe}</span>
          <span className="font-mono text-xs text-subtle uppercase">{finding.tool}</span>
        </div>

        {/* Heuristic warning if finding came from LLM pass */}
        {(finding.tool === "gemini-llm-heuristic" ||
          (finding as any).source === "llm-heuristic" ||
          (finding as any).source_type === "llm-heuristic") && (
          <div className="mt-3 flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3.5 py-2 font-mono text-xs text-amber-300">
            <AlertCircle className="size-4 shrink-0 text-amber-400" />
            <span>no deterministic rule, validation is limited</span>
          </div>
        )}
        <h1 className="mt-3 font-display text-lg sm:text-xl font-semibold tracking-tight break-all">
          {finding.file_path}
          {finding.line_start && <span className="text-subtle">:{finding.line_start}</span>}
        </h1>
        <p className="mt-1 font-mono text-xs text-subtle leading-relaxed">{finding.raw_message}</p>

        {/* Two-column split view */}
        <div className="mt-8 grid gap-6 md:grid-cols-2">
          {/* Left: Code */}
          <div>
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              vulnerable code
            </p>
            <TerminalWindow title={finding.file_path}>
              {finding.code_lines && finding.code_lines.length > 0 ? (
                <CodeView lines={finding.code_lines} />
              ) : (
                <span className="text-subtle/50 font-mono text-xs">no code context stored</span>
              )}
            </TerminalWindow>
          </div>

          {/* Right: Explanation */}
          <div>
            <div className="mb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5">
              <div className="flex items-center gap-2.5">
                <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
                  ai explanation
                </p>
                {finding.explanation && !isFalsePositive && (
                  <div className="inline-flex rounded-lg border border-border bg-background p-0.5 font-mono text-[10px]">
                    <button
                      onClick={() => setExplanationMode("technical")}
                      className={`rounded px-2.5 py-0.5 transition-colors ${
                        explanationMode === "technical"
                          ? "bg-accent/20 text-accent font-semibold"
                          : "text-subtle hover:text-foreground"
                      }`}
                    >
                      technical
                    </button>
                    <button
                      onClick={() => setExplanationMode("simplified")}
                      className={`rounded px-2.5 py-0.5 transition-colors ${
                        explanationMode === "simplified"
                          ? "bg-accent/20 text-accent font-semibold"
                          : "text-subtle hover:text-foreground"
                      }`}
                    >
                      simplified
                    </button>
                  </div>
                )}
              </div>
              <button
                onClick={() => handleRegenerateAi()}
                disabled={regenerating}
                className="pill-hover self-start sm:self-auto inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1 font-mono text-[11px] text-accent hover:bg-accent/20 transition-colors disabled:opacity-50"
              >
                <Sparkles className={`size-3 ${regenerating ? "animate-spin" : ""}`} />
                {regenerating
                  ? "generating…"
                  : `regenerate with ${detectedProviderName.toLowerCase()}`}
              </button>
            </div>

            {regenError && (
              <div className="mb-3 rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 font-mono text-xs text-danger flex items-center justify-between gap-3">
                <span>{regenError}</span>
                <button
                  onClick={() => handleRegenerateAi()}
                  disabled={regenerating}
                  className="shrink-0 rounded border border-danger/40 bg-danger/20 px-2.5 py-1 text-[11px] hover:bg-danger/30 transition-colors cursor-pointer"
                >
                  retry
                </button>
              </div>
            )}

            {showKeyInput && (
              <div className="mb-3 rounded-lg border border-border bg-elevated p-3 space-y-2">
                <label className="block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  Enter AI API key (Gemini, Groq, OpenRouter, or OpenAI)
                </label>
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={regenKey}
                    onChange={(e) => {
                      setRegenKey(e.target.value);
                      if (typeof window !== "undefined") {
                        sessionStorage.setItem("sl_ai_key", e.target.value);
                      }
                    }}
                    placeholder="AQ.…, AIzaSy…, gsk_…, sk-or-…, or sk-…"
                    className="flex-1 rounded-lg border border-border bg-background px-3 py-1.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                  />
                  <button
                    onClick={() => {
                      setShowKeyInput(false);
                      handleRegenerateAi(regenKey);
                    }}
                    className="pill-hover rounded-lg border border-accent/40 bg-accent/20 px-3 py-1.5 font-mono text-xs text-accent cursor-pointer"
                  >
                    run
                  </button>
                </div>
                <p className="font-mono text-[10px] text-warning/80">
                  Note: Free-tier Gemini prompts may be used by Google to improve its products, so
                  don't scan private code with a free key.
                </p>
              </div>
            )}

            {groundingResult?.warnings && groundingResult.warnings.length > 0 && (
              <div className="mb-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 font-mono text-xs text-amber-200 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-amber-300">
                  <AlertCircle className="size-4 shrink-0" />
                  <span>Grounding Warning</span>
                </div>
                <ul className="list-disc list-inside space-y-1 text-subtle text-[11px]">
                  {groundingResult.warnings.map((w, idx) => (
                    <li key={idx}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            {regenerating ? (
              <div className="rounded-lg border border-accent/40 bg-accent/5 p-5 text-center font-mono text-xs text-accent space-y-2">
                <div className="inline-flex items-center gap-2">
                  <Sparkles className="size-4 animate-spin text-accent" />
                  <span className="font-semibold">Generating real AI explanation…</span>
                </div>
                <p className="text-subtle text-[11px]">
                  Analyzing verified scanner snippet with {detectedProviderName}
                </p>
              </div>
            ) : isFalsePositive ? (
              <div className="rounded-lg border border-warning/40 bg-warning/10 p-5 font-mono text-xs text-warning space-y-3 break-words [overflow-wrap:anywhere]">
                <div className="flex items-center gap-2 font-semibold text-sm">
                  <AlertCircle className="size-4 shrink-0" />
                  <span>Likely False Positive</span>
                </div>
                <p className="text-foreground/90 leading-relaxed break-words [overflow-wrap:anywhere]">
                  {finding.explanation?.false_positive_reason || finding.explanation?.what_it_is}
                </p>
                {finding.status !== "dismissed" ? (
                  <button
                    onClick={() => setShowDismissDialog(true)}
                    disabled={deciding}
                    className="mt-2 inline-flex items-center gap-2 rounded-full border border-warning/40 bg-warning/20 px-4 py-1.5 font-mono text-xs font-medium text-warning hover:bg-warning/30 transition-colors cursor-pointer"
                  >
                    <XCircle className="size-3.5" />
                    dismiss as false positive
                  </button>
                ) : (
                  <span className="inline-block mt-2 font-mono text-xs text-subtle italic">
                    ✓ Dismissed as False Positive
                  </span>
                )}
              </div>
            ) : finding.explanation ? (
              <div className="rounded-lg border border-border bg-elevated p-5 space-y-4 font-mono text-xs">
                {explanationMode === "simplified" ? (
                  <div className="space-y-3">
                    <div className="rounded border border-accent/30 bg-accent/5 p-3">
                      <span className="text-accent text-[11px] font-semibold block mb-1">
                        Simplified Concept (for Beginners)
                      </span>
                      <p className="text-foreground leading-relaxed text-xs">
                        {(finding.explanation.raw_explanation as any)?.what_it_is?.simplified ||
                          finding.explanation.simplified_explanation ||
                          finding.explanation.what_it_is}
                      </p>
                    </div>
                    <div>
                      <span className="text-subtle text-[11px]">why it happened:</span>
                      <p className="mt-1 text-foreground/90 leading-relaxed">
                        {(finding.explanation.raw_explanation as any)?.why_it_happened
                          ?.simplified || finding.explanation.why_it_happened}
                      </p>
                    </div>
                    <div>
                      <span className="text-subtle text-[11px]">how the fix works:</span>
                      <p className="mt-1 text-foreground/90 leading-relaxed">
                        {(finding.explanation.raw_explanation as any)?.how_fix_works?.simplified ||
                          finding.explanation.how_fix_works}
                      </p>
                    </div>
                  </div>
                ) : (
                  <>
                    <div>
                      <span className="text-accent font-semibold">what it is</span>
                      <p className="mt-1 text-foreground leading-relaxed">
                        {(finding.explanation.raw_explanation as any)?.what_it_is?.technical ||
                          finding.explanation.what_it_is}
                      </p>
                    </div>
                    <div>
                      <span className="text-accent font-semibold">why it happened</span>
                      <p className="mt-1 text-subtle leading-relaxed">
                        {(finding.explanation.raw_explanation as any)?.why_it_happened?.technical ||
                          finding.explanation.why_it_happened}
                      </p>
                    </div>
                    <div>
                      <span className="text-accent font-semibold">how the fix works</span>
                      <p className="mt-1 text-subtle leading-relaxed">
                        {(finding.explanation.raw_explanation as any)?.how_fix_works?.technical ||
                          finding.explanation.how_fix_works}
                      </p>
                    </div>
                  </>
                )}

                {/* Attack Concept (words only) */}
                {finding.explanation.attack_idea && (
                  <div className="border-t border-border/60 pt-3">
                    <span className="text-accent font-semibold">attack concept (conceptual)</span>
                    <p className="mt-1 text-foreground/90 leading-relaxed text-[11px]">
                      {finding.explanation.attack_idea}
                    </p>
                  </div>
                )}

                {/* Key Takeaway */}
                {finding.explanation.key_takeaway && (
                  <div className="border-t border-border/60 pt-3">
                    <span className="text-accent font-semibold">key takeaway</span>
                    <p className="mt-1 text-foreground leading-relaxed text-[11px] font-medium">
                      💡 {finding.explanation.key_takeaway}
                    </p>
                  </div>
                )}

                {/* Confidence Note (if present) */}
                {finding.explanation.confidence_note && (
                  <div className="border-t border-border/60 pt-3">
                    <span className="text-warning text-[11px] font-semibold">
                      tutor confidence note
                    </span>
                    <p className="mt-1 text-subtle leading-relaxed text-[11px]">
                      {finding.explanation.confidence_note}
                    </p>
                  </div>
                )}

                {/* False positive assessment */}
                <div className="border-t border-border/60 pt-3 flex items-center justify-between text-xs font-mono">
                  <span className="text-subtle text-[11px]">false positive assessment:</span>
                  <span
                    className={
                      finding.explanation.likely_false_positive === true
                        ? "text-warning font-semibold text-[11px]"
                        : finding.explanation.likely_false_positive === false
                          ? "text-success text-[11px]"
                          : "text-subtle italic text-[11px]"
                    }
                  >
                    {finding.explanation.likely_false_positive === true
                      ? "likely false positive"
                      : finding.explanation.likely_false_positive === false
                        ? "verified finding (not false positive)"
                        : "not assessed"}
                  </span>
                </div>

                <div className="border-t border-border pt-3 text-subtle/50 text-[10px] flex items-center justify-between">
                  <span>
                    {finding.explanation.model
                      ? `provider: ${
                          finding.explanation.model.includes("gpt-oss") ||
                          finding.explanation.model.includes("qwen") ||
                          finding.explanation.model.includes("llama") ||
                          finding.explanation.model.includes("mixtral")
                            ? "Groq"
                            : finding.explanation.model.startsWith("gemini")
                              ? "Google Gemini"
                              : "AI"
                        } · model: ${finding.explanation.model}`
                      : ""}
                  </span>
                  <span className="capitalize text-accent/80 font-medium">
                    {explanationMode} view
                  </span>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-elevated p-5 flex items-center justify-between">
                <span className="font-mono text-xs text-subtle">explanation not yet generated</span>
                <button
                  onClick={() => handleRegenerateAi()}
                  disabled={regenerating}
                  className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1 font-mono text-xs text-accent hover:bg-accent/20 transition-colors disabled:opacity-50"
                >
                  <Sparkles className="size-3" />
                  generate with {detectedProviderName.toLowerCase()}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Patch diff */}
        {finding.patch?.diff ? (
          <div className="mt-8">
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              proposed patch
            </p>
            <TerminalWindow title={`diff — ${finding.file_path}`}>
              <DiffView lines={parseDiff(finding.patch.diff)} />
            </TerminalWindow>
          </div>
        ) : (
          <div className="mt-8 rounded-lg border border-border bg-elevated p-5">
            <p className="mb-2 font-mono text-[10px] uppercase tracking-wider text-subtle">
              proposed patch
            </p>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="font-mono text-xs text-subtle">No patch generated yet.</span>
              <button
                onClick={() => handleRegenerateAi()}
                disabled={regenerating}
                className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-4 py-1.5 font-mono text-xs font-medium text-accent hover:bg-accent/20 transition-colors disabled:opacity-50"
              >
                <Sparkles className={`size-3.5 ${regenerating ? "animate-spin" : ""}`} />
                {regenerating
                  ? "generating patch…"
                  : `generate patch with ${detectedProviderName.toLowerCase()}`}
              </button>
            </div>
          </div>
        )}

        {/* Validation result */}
        {finding.patch && (
          <div className="mt-8">
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              validation result
            </p>
            <div className="rounded-lg border border-border bg-elevated overflow-hidden">
              <div className="grid grid-cols-3 divide-x divide-border border-b border-border">
                <ValidationCheck
                  label="vulnerability removed"
                  pass={finding.patch.validation_vulnerability_gone ?? false}
                />
                <ValidationCheck
                  label="syntax valid"
                  pass={finding.patch.validation_syntax_ok ?? false}
                  na={finding.patch.validation_syntax_ok === null}
                />
                <ValidationCheck
                  label="new issues"
                  pass={(finding.patch.validation_new_issues ?? 0) === 0}
                  count={finding.patch.validation_new_issues ?? 0}
                />
              </div>

              {finding.patch.validation_verdict && (
                <div
                  className={`px-5 py-3 font-mono text-xs font-semibold ${
                    finding.patch.validation_verdict === "accepted" ? "text-success" : "text-danger"
                  }`}
                >
                  verdict: {finding.patch.validation_verdict?.toUpperCase()}
                  {finding.patch.validation_failed_check && (
                    <span className="ml-2 text-subtle font-normal">
                      (failed: {finding.patch.validation_failed_check})
                    </span>
                  )}
                </div>
              )}

              {/* Logs collapsible */}
              {finding.patch.validation_logs && finding.patch.validation_logs.length > 0 && (
                <div className="border-t border-border">
                  <button
                    onClick={() => setLogsOpen(!logsOpen)}
                    className="flex w-full cursor-pointer items-center justify-between px-5 py-2.5 font-mono text-[11px] text-subtle hover:text-foreground"
                  >
                    validation log
                    {logsOpen ? (
                      <ChevronUp className="size-3" />
                    ) : (
                      <ChevronDown className="size-3" />
                    )}
                  </button>
                  {logsOpen && (
                    <div className="border-t border-border bg-background px-5 py-3 font-mono text-[11px] leading-relaxed">
                      {finding.patch.validation_logs.map((l, i) => (
                        <div
                          key={i}
                          className={
                            l.includes("✓") || l.includes("ACCEPTED")
                              ? "text-success"
                              : l.includes("✖") || l.includes("REJECTED")
                                ? "text-danger"
                                : l.startsWith("▸")
                                  ? "text-accent"
                                  : "text-subtle"
                          }
                        >
                          {l}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Decision Forms: Override Confirmation */}
        {showOverrideConfirm && (
          <div className="mt-6 rounded-lg border border-warning/40 bg-warning/10 p-5 font-mono text-xs space-y-3">
            <div className="flex items-center gap-2 font-semibold text-sm text-warning">
              <AlertTriangle className="size-4 shrink-0" />
              <span>Confirm Patch Override</span>
            </div>
            <p className="text-foreground/90 leading-relaxed text-xs">
              The automatic validation rejected this patch (e.g. syntax check failed, original
              vulnerability still detected, or new issues introduced). Are you sure you want to
              override the automated checks and accept this patch for manual developer review?
            </p>
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={() => makeDecision("accept", true)}
                disabled={deciding}
                className="pill-hover rounded-full border border-warning/60 bg-warning/20 px-4 py-2 font-mono text-xs font-semibold text-warning hover:bg-warning/30 transition-colors cursor-pointer disabled:opacity-50"
              >
                confirm override & accept
              </button>
              <button
                onClick={() => setShowOverrideConfirm(false)}
                className="rounded-full border border-border px-3.5 py-2 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
              >
                cancel
              </button>
            </div>
          </div>
        )}

        {/* Decision Forms: Rejection Note Form */}
        {showRejectDialog && (
          <div className="mt-6 rounded-lg border border-danger/40 bg-danger/10 p-5 font-mono text-xs space-y-3">
            <div className="flex items-center gap-2 font-semibold text-sm text-danger">
              <XCircle className="size-4 shrink-0" />
              <span>Reject Proposed Patch</span>
            </div>
            <p className="text-subtle text-[11px] leading-relaxed">
              Provide an optional developer note explaining why this patch is being rejected. This
              note will be recorded and can be fed back to generate an alternative remediation
              attempt.
            </p>
            <textarea
              value={rejectionNote}
              onChange={(e) => setRejectionNote(e.target.value)}
              placeholder="e.g. Breaks backward compatibility with existing API; use parameterized query via pool.query(sql, [params]) instead..."
              rows={3}
              className="w-full rounded border border-border bg-background p-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
            />
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={() => makeDecision("reject", false, rejectionNote)}
                disabled={deciding}
                className="pill-hover rounded-full border border-danger/60 bg-danger/20 px-4 py-2 font-mono text-xs font-semibold text-danger hover:bg-danger/30 transition-colors cursor-pointer disabled:opacity-50"
              >
                confirm rejection
              </button>
              <button
                onClick={() => setShowRejectDialog(false)}
                className="rounded-full border border-border px-3.5 py-2 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
              >
                cancel
              </button>
            </div>
          </div>
        )}

        {/* Decision Forms: Dismiss False Positive Form */}
        {showDismissDialog && (
          <div className="mt-6 rounded-lg border border-border bg-elevated p-5 font-mono text-xs space-y-4">
            <div className="flex items-center gap-2 font-semibold text-sm text-foreground">
              <AlertCircle className="size-4 shrink-0 text-warning" />
              <span>Dismiss Finding as False Positive</span>
            </div>
            <p className="text-subtle text-[11px] leading-relaxed">
              Dismissing suppresses this finding for your project and commit lineage, preventing it
              from blocking future scans and tracking it accurately in false-positive metrics.
            </p>
            <div>
              <label className="block text-[11px] uppercase tracking-wider text-subtle mb-1.5">
                Reason category:
              </label>
              <select
                value={dismissReasonCode}
                onChange={(e) => setDismissReasonCode(e.target.value)}
                className="w-full rounded border border-border bg-background px-3 py-2 font-mono text-xs text-foreground focus:border-accent/50 focus:outline-none cursor-pointer"
              >
                <option value="test_code">Test / benchmark / mock code (not production)</option>
                <option value="not_exploitable">
                  Not exploitable in this architecture / context
                </option>
                <option value="accepted_risk">
                  Accepted business risk / mitigated by external controls
                </option>
                <option value="wrong_detection">False detection / scanner rule mismatch</option>
                <option value="other">Other reason (requires explanation below)</option>
              </select>
            </div>
            <div>
              <label className="block text-[11px] uppercase tracking-wider text-subtle mb-1.5">
                Explanation / developer notes{" "}
                {dismissReasonCode === "other" && <span className="text-danger">*</span>}:
              </label>
              <textarea
                value={dismissReasonText}
                onChange={(e) => setDismissReasonText(e.target.value)}
                placeholder={
                  dismissReasonCode === "other"
                    ? "Detailed explanation of why this detection is a false positive..."
                    : "Optional context or notes regarding this dismissal..."
                }
                rows={2}
                className="w-full rounded border border-border bg-background p-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleConfirmDismiss}
                disabled={deciding || (dismissReasonCode === "other" && !dismissReasonText.trim())}
                className="pill-hover rounded-full border border-warning/60 bg-warning/20 px-4 py-2 font-mono text-xs font-semibold text-warning hover:bg-warning/30 transition-colors disabled:opacity-50 cursor-pointer"
              >
                confirm dismissal
              </button>
              <button
                onClick={() => setShowDismissDialog(false)}
                className="rounded-full border border-border px-3.5 py-2 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
              >
                cancel
              </button>
            </div>
          </div>
        )}

        {/* Accept / Reject / Dismiss Action Buttons */}
        {finding.patch &&
          !decisionDone &&
          finding.status !== "dismissed" &&
          !showOverrideConfirm &&
          !showRejectDialog &&
          !showDismissDialog && (
            <div className="mt-6 flex flex-wrap items-center gap-2.5 sm:gap-3">
              {canAccept ? (
                <button
                  onClick={() => makeDecision("accept")}
                  disabled={deciding}
                  className="pill-hover inline-flex cursor-pointer items-center justify-center gap-2 rounded-full border border-success/40 bg-success/10 px-4 sm:px-5 py-2 sm:py-2.5 font-mono text-xs font-medium text-success disabled:opacity-50"
                >
                  <CheckCircle2 className="size-3.5" />
                  accept patch
                </button>
              ) : (
                <button
                  onClick={() => setShowOverrideConfirm(true)}
                  disabled={deciding}
                  className="pill-hover inline-flex cursor-pointer items-center justify-center gap-2 rounded-full border border-warning/40 bg-warning/10 px-4 sm:px-5 py-2 sm:py-2.5 font-mono text-xs font-medium text-warning disabled:opacity-50"
                >
                  <AlertCircle className="size-3.5" />
                  override & accept
                </button>
              )}
              <button
                onClick={() => setShowRejectDialog(true)}
                disabled={deciding}
                className="pill-hover inline-flex cursor-pointer items-center justify-center gap-2 rounded-full border border-danger/40 bg-danger/10 px-4 sm:px-5 py-2 sm:py-2.5 font-mono text-xs font-medium text-danger disabled:opacity-50"
              >
                <XCircle className="size-3.5" />
                reject
              </button>
              <button
                onClick={() => setShowDismissDialog(true)}
                disabled={deciding}
                className="pill-hover inline-flex cursor-pointer items-center justify-center gap-2 rounded-full border border-border bg-elevated px-4 sm:px-5 py-2 sm:py-2.5 font-mono text-xs font-medium text-subtle hover:text-foreground disabled:opacity-50"
              >
                <XCircle className="size-3.5 text-warning" />
                dismiss false positive
              </button>
            </div>
          )}

        {/* Decision Result: Accepted State */}
        {decisionDone === "accept" && (
          <div className="mt-6 rounded-lg border border-success/30 bg-success/5 p-4 sm:p-5 font-mono text-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-success font-semibold text-sm">
                <CheckCircle2 className="size-4 shrink-0" />
                <span>
                  {existingDecision?.is_override
                    ? "Patch Accepted via Developer Override"
                    : "Patch Validated & Accepted"}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={downloadPatchFile}
                  className="inline-flex items-center gap-1.5 rounded-full border border-success/40 bg-success/15 px-3.5 py-1.5 font-mono text-[11px] text-success hover:bg-success/25 transition-colors cursor-pointer"
                >
                  <Download className="size-3.5" />
                  download .patch file
                </button>
                <button
                  onClick={copyDiffToClipboard}
                  className="inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-3.5 py-1.5 font-mono text-[11px] text-foreground hover:bg-elevated transition-colors cursor-pointer"
                >
                  {copiedDiff ? (
                    <Check className="size-3.5 text-success" />
                  ) : (
                    <Copy className="size-3.5" />
                  )}
                  {copiedDiff ? "copied diff!" : "copy diff"}
                </button>
              </div>
            </div>

            <div className="rounded border border-border/80 bg-background/60 p-3 text-[11px] text-subtle space-y-1">
              <p className="text-warning/90 font-medium">
                {existingDecision?.is_override
                  ? "⚠ Note: The automatic validation had rejected this patch. It has NOT been applied to your git repository."
                  : "ⓘ Note: This patch has NOT been applied directly to your git repository."}
              </p>
              <p className="text-foreground/80">
                Apply manually using{" "}
                <code className="text-accent bg-accent/10 px-1 py-0.5 rounded font-mono">
                  git apply &lt;file&gt;.patch
                </code>{" "}
                or create a pull request.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-subtle border-t border-border/60 pt-3">
              <div>
                <span className="text-subtle/70">Target file:</span>{" "}
                <span className="text-foreground">{finding.file_path}</span>
              </div>
              <div>
                <span className="text-subtle/70">Target commit:</span>{" "}
                <span className="text-foreground font-mono">
                  {commitSha ? commitSha.slice(0, 8) : "HEAD"}
                </span>
              </div>
              <div>
                <span className="text-subtle/70">Accepted by:</span>{" "}
                <span className="text-foreground">{user?.email || user?.id}</span>
              </div>
              <div>
                <span className="text-subtle/70">Validation record:</span>{" "}
                <span className={existingDecision?.is_override ? "text-warning" : "text-success"}>
                  {existingDecision?.is_override
                    ? "Rejected by validation (Overridden)"
                    : "Passed validation"}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Decision Result: Rejected State with Regenerate Offer */}
        {decisionDone === "reject" && (
          <div className="mt-6 rounded-lg border border-danger/30 bg-danger/5 p-4 sm:p-5 font-mono text-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-danger font-semibold text-sm">
                <XCircle className="size-4 shrink-0" />
                <span>Patch Rejected by Developer</span>
              </div>
              <button
                onClick={() =>
                  handleRegenerateAi(undefined, {
                    previousDiff: finding.patch?.diff,
                    rejectionNote: existingDecision?.rejection_note || rejectionNote,
                  })
                }
                disabled={regenerating}
                className="inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/15 px-4 py-1.5 font-mono text-xs font-medium text-accent hover:bg-accent/25 transition-colors disabled:opacity-50 cursor-pointer"
              >
                <Sparkles className={`size-3.5 ${regenerating ? "animate-spin" : ""}`} />
                {regenerating ? "generating alternative fix…" : "generate another patch"}
              </button>
            </div>

            {(existingDecision?.rejection_note || rejectionNote) && (
              <div className="rounded border border-border/80 bg-background/60 p-3 text-[11px] space-y-1">
                <span className="text-subtle block uppercase tracking-wider text-[10px]">
                  Developer rejection note:
                </span>
                <p className="text-foreground/90 italic">
                  "{existingDecision?.rejection_note || rejectionNote}"
                </p>
              </div>
            )}

            <p className="text-[11px] text-subtle">
              Clicking "generate another patch" sends this rejected diff and your feedback to the AI
              to produce an alternative remediation.
            </p>
          </div>
        )}

        {/* Suppressed Finding State */}
        {finding.status === "dismissed" && (
          <div className="mt-6 rounded-lg border border-border bg-elevated p-4 sm:p-5 font-mono text-xs space-y-2">
            <div className="flex items-center gap-2 text-warning font-medium">
              <CheckCircle2 className="size-4 text-warning" />
              <span>Finding Dismissed & Suppressed as False Positive</span>
            </div>
            {suppression && (
              <div className="text-[11px] text-subtle space-y-1 pt-1">
                <div>
                  <span className="text-subtle/70">Reason:</span>{" "}
                  <span className="text-foreground">
                    {suppression.reason_code === "test_code"
                      ? "Test / benchmark / mock code (not production)"
                      : suppression.reason_code === "not_exploitable"
                        ? "Not exploitable in this architecture / context"
                        : suppression.reason_code === "accepted_risk"
                          ? "Accepted business risk / mitigated by external controls"
                          : suppression.reason_code === "wrong_detection"
                            ? "False detection / rule mismatch"
                            : suppression.reason_code}
                  </span>
                </div>
                {suppression.reason_text && (
                  <div>
                    <span className="text-subtle/70">Note:</span>{" "}
                    <span className="text-foreground italic">"{suppression.reason_text}"</span>
                  </div>
                )}
              </div>
            )}
            <p className="text-[10px] text-subtle/60 pt-1">
              This finding will be suppressed on future scans of this project commit lineage.
            </p>
          </div>
        )}

        {/* Post-decision quiz */}
        {showQuiz && (
          <div className="mt-8">
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              education check
            </p>
            {loadingTier ? (
              <div className="rounded-lg border border-border bg-elevated p-6 font-mono text-xs text-subtle animate-pulse">
                loading question…
              </div>
            ) : quiz ? (
              <TerminalWindow title={`quiz — ${finding.vulnerability_class} · ${activeTier}`}>
                {/* Tier badge */}
                <div className="flex items-center gap-2 mb-3">
                  <span className="font-mono text-[10px] text-subtle">// tier:</span>
                  <span
                    className={`font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border ${
                      activeTier === "hard"
                        ? "border-danger/40 text-danger"
                        : activeTier === "medium"
                          ? "border-warning/40 text-warning"
                          : "border-subtle/40 text-subtle"
                    }`}
                  >
                    {activeTier}
                  </span>
                  {activeTier !== "easy" && (
                    <span className="font-mono text-[10px] text-success">unlocked</span>
                  )}
                </div>
                <div className="text-foreground mb-4">{quiz.question}</div>
                <div className="space-y-2">
                  {quiz.options.map((opt, i) => (
                    <button
                      key={i}
                      disabled={quizSubmitted}
                      onClick={() => setQuizAnswer(i)}
                      className={`block w-full cursor-pointer text-left px-3 py-1.5 rounded transition-colors font-mono text-[11px] ${
                        quizSubmitted
                          ? i === quiz.correctIndex
                            ? "text-success"
                            : i === quizAnswer && i !== quiz.correctIndex
                              ? "text-danger"
                              : "text-subtle/50"
                          : quizAnswer === i
                            ? "text-foreground bg-accent/10"
                            : "text-subtle hover:text-foreground"
                      }`}
                    >
                      {String.fromCharCode(97 + i)}){" "}
                      {typeof opt === "string" ? opt : (opt as any).text}
                      {quizSubmitted && i === quiz.correctIndex && " ✓ correct"}
                      {quizSubmitted && i === quizAnswer && i !== quiz.correctIndex && " ✗"}
                    </button>
                  ))}
                </div>
                {!quizSubmitted ? (
                  <button
                    onClick={submitQuizAnswer}
                    disabled={quizAnswer === null}
                    className="mt-4 pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border px-4 py-2 font-mono text-[11px] text-subtle hover:text-foreground disabled:opacity-40"
                  >
                    submit answer
                  </button>
                ) : (
                  <div className="mt-4 border-t border-border pt-3 space-y-2">
                    <span
                      className={quizAnswer === quiz.correctIndex ? "text-success" : "text-danger"}
                    >
                      {quizAnswer === quiz.correctIndex ? "✓ correct!" : "✗ not quite"}
                    </span>
                    {quizAnswer !== quiz.correctIndex && (
                      <p className="font-mono text-[10px] text-subtle mt-1">
                        correct answer: {String.fromCharCode(97 + quiz.correctIndex)})
                      </p>
                    )}
                    {quizAnswer !== null &&
                      quizAnswer !== quiz.correctIndex &&
                      quiz.options[quizAnswer]?.misconceptionId && (
                        <div className="rounded bg-warning/10 border border-warning/20 p-2 text-warning text-[10px]">
                          <span className="font-semibold block uppercase tracking-wider mb-0.5">
                            Diagnosed Misconception:
                          </span>
                          {MISCONCEPTION_LABELS[quiz.options[quizAnswer]!.misconceptionId!] ||
                            "Common security misconception."}
                        </div>
                      )}
                    {quiz.source && (
                      <div className="text-subtle/80 text-[10px] flex items-center gap-1.5 pt-1">
                        <span>Source:</span>
                        <a
                          href={quiz.source.match(/https?:\/\/[^\s)]+/)?.[0] || "#"}
                          target="_blank"
                          rel="noreferrer"
                          className="text-accent underline hover:text-accent/80"
                        >
                          {quiz.source}
                        </a>
                      </div>
                    )}
                    <div className="flex items-center gap-4 mt-2">
                      <Link
                        to="/learn"
                        search={{ class: finding.vulnerability_class as VulnClass }}
                        className="text-accent hover:underline font-mono text-[11px]"
                      >
                        practice more in learning hub →
                      </Link>
                    </div>
                  </div>
                )}
              </TerminalWindow>
            ) : (
              <div className="rounded-lg border border-border bg-elevated p-6 font-mono text-xs text-subtle">
                no quiz available for this vulnerability class
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function ValidationCheck({
  label,
  pass,
  na,
  count,
}: {
  label: string;
  pass: boolean;
  na?: boolean;
  count?: number;
}) {
  return (
    <div className="p-2.5 sm:p-4 flex flex-col gap-1">
      <span className="font-mono text-[9px] sm:text-[10px] uppercase tracking-wider text-subtle leading-tight">
        {label}
      </span>
      {na ? (
        <span className="font-mono text-xs text-subtle">n/a</span>
      ) : (
        <span
          className={`font-mono text-xs sm:text-sm font-semibold ${pass ? "text-success" : "text-danger"}`}
        >
          {count !== undefined ? count : pass ? "✓" : "✗"}
        </span>
      )}
    </div>
  );
}

// Simple diff parser: line-by-line
function parseDiff(diff: string) {
  return diff.split("\n").map((line) => {
    if (line.startsWith("@@")) return { type: "hunk" as const, code: line };
    if (line.startsWith("+")) return { type: "add" as const, code: line };
    if (line.startsWith("-")) return { type: "del" as const, code: line };
    return { type: "ctx" as const, code: line };
  });
}
