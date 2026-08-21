import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { ArrowLeft, ChevronDown, ChevronUp, CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase, type DbFinding, type DbExplanation, type DbPatch } from "@/lib/supabase";
import { Logo, SeverityBadge, StatusBadge, TerminalWindow, CodeView, DiffView } from "@/components/chrome";

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

  const quizData = {
    sqli: {
      question: "Why do parameterized queries prevent SQL injection?",
      options: [
        "They encrypt the input before reaching the database",
        "The query structure is parsed before user data is bound — input can never become SQL syntax",
        "They strip all quotes from user input",
        "They run queries in a read-only transaction",
      ],
      correctIndex: 1,
    },
    xss: {
      question: "What is the safest default way to render user text in React?",
      options: [
        "dangerouslySetInnerHTML with a regex filter",
        "Plain JSX interpolation — React escapes output by default",
        "innerHTML after replacing <script> tags",
        "Base64-encoding the text first",
      ],
      correctIndex: 1,
    },
    csrf: {
      question: "Why doesn't SameSite=Lax cookie alone fully replace CSRF tokens?",
      options: [
        "SameSite is ignored by mobile browsers",
        "Legacy clients, top-level GET navigations, and subdomains still send cookies — a token proves intent",
        "CSRF tokens are encrypted, cookies are not",
        "SameSite only works over HTTP/2",
      ],
      correctIndex: 1,
    },
    insecure_deserialization: {
      question: "Why is JSON preferred over pickle for untrusted input in Python?",
      options: [
        "JSON is faster to parse",
        "JSON describes data only — it has no mechanism to construct objects or execute code during parsing",
        "pickle is deprecated since Python 3.10",
        "JSON automatically validates types",
      ],
      correctIndex: 1,
    },
  };

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user && findingId) fetchData();
  }, [user, findingId]);

  async function fetchData() {
    setLoadingData(true);

    const { data: f } = await supabase
      .from("findings")
      .select("*")
      .eq("id", findingId)
      .single();

    if (!f) {
      setLoadingData(false);
      return;
    }

    const { data: explanation } = await supabase
      .from("explanations")
      .select("*")
      .eq("finding_id", findingId)
      .single();

    const { data: patch } = await supabase
      .from("patches")
      .select("*")
      .eq("finding_id", findingId)
      .single();

    // Check for existing decision
    const { data: decision } = await supabase
      .from("developer_decisions")
      .select("action")
      .eq("patch_id", patch?.id ?? "")
      .eq("user_id", user!.id)
      .single();

    if (decision) {
      setDecisionDone(decision.action as "accept" | "reject");
    }

    setFinding({
      ...(f as DbFinding),
      explanation: explanation as DbExplanation ?? undefined,
      patch: patch as DbPatch ?? undefined,
    });
    setLoadingData(false);
  }

  async function makeDecision(action: "accept" | "reject", override = false) {
    if (!finding?.patch || !user) return;
    setDeciding(true);

    await supabase.from("developer_decisions").insert({
      patch_id: finding.patch.id,
      user_id: user.id,
      action,
      is_override: override,
    });

    // Update finding status
    await supabase
      .from("findings")
      .update({ status: action === "accept" ? "accepted" : "rejected" })
      .eq("id", findingId);

    setDecisionDone(action);
    setDeciding(false);
    setShowQuiz(true);
  }

  async function submitQuizAnswer() {
    if (quizAnswer === null || !finding || !user) return;
    const vulnClass = finding.vulnerability_class as keyof typeof quizData;
    const quiz = quizData[vulnClass];
    if (!quiz) return;

    const isCorrect = quizAnswer === quiz.correctIndex;

    await supabase.from("education_checks").insert({
      finding_id: findingId,
      user_id: user.id,
      question: quiz.question,
      options: quiz.options,
      correct_index: quiz.correctIndex,
      user_answer: quizAnswer,
      correct: isCorrect,
      answered_at: new Date().toISOString(),
    });

    setQuizSubmitted(true);
  }

  const validation = finding?.patch;
  const canAccept =
    validation?.validation_verdict === "accepted" ||
    validation?.validation_vulnerability_gone;

  const quiz = finding?.vulnerability_class
    ? quizData[finding.vulnerability_class as keyof typeof quizData]
    : null;

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
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
          <Logo />
          <button
            onClick={() => navigate({ to: "/findings/$projectId", params: { projectId: finding.project_id } })}
            className="flex items-center gap-2 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
          >
            <ArrowLeft className="size-3" />
            back to findings
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10">
        {/* Finding header */}
        <div className="flex flex-wrap items-start gap-3">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status as any} />
          <span className="font-mono text-xs text-subtle">{finding.cwe}</span>
          <span className="font-mono text-xs text-subtle uppercase">{finding.tool}</span>
        </div>
        <h1 className="mt-3 font-display text-xl font-semibold tracking-tight">
          {finding.file_path}
          {finding.line_start && (
            <span className="text-subtle">:{finding.line_start}</span>
          )}
        </h1>
        <p className="mt-1 font-mono text-xs text-subtle">{finding.raw_message}</p>

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
                <span className="text-subtle/50 font-mono text-xs">
                  no code context stored
                </span>
              )}
            </TerminalWindow>
          </div>

          {/* Right: Explanation */}
          <div>
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              ai explanation
            </p>
            {finding.explanation ? (
              <div className="rounded-lg border border-border bg-elevated p-5 space-y-4 font-mono text-xs">
                <div>
                  <span className="text-accent">what it is</span>
                  <p className="mt-1 text-subtle leading-relaxed">{finding.explanation.what_it_is}</p>
                </div>
                <div>
                  <span className="text-accent">why it happened</span>
                  <p className="mt-1 text-subtle leading-relaxed">{finding.explanation.why_it_happened}</p>
                </div>
                <div>
                  <span className="text-accent">owasp category</span>
                  <p className="mt-1 text-foreground">{finding.explanation.owasp_category}</p>
                </div>
                <div>
                  <span className="text-accent">how the fix works</span>
                  <p className="mt-1 text-subtle leading-relaxed">{finding.explanation.how_fix_works}</p>
                </div>
                <div className="border-t border-border pt-3 text-subtle/50 text-[10px]">
                  model: {finding.explanation.model}
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-elevated p-5">
                <span className="font-mono text-xs text-subtle">
                  explanation not yet generated
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Patch diff */}
        {finding.patch?.diff && (
          <div className="mt-8">
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              proposed patch
            </p>
            <TerminalWindow title={`diff — ${finding.file_path}`}>
              <DiffView
                lines={parseDiff(finding.patch.diff)}
              />
            </TerminalWindow>
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
                  label="tests passed"
                  pass={finding.patch.validation_tests_passed ?? false}
                  na={finding.patch.validation_tests_passed === null}
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
                    finding.patch.validation_verdict === "accepted"
                      ? "text-success"
                      : "text-danger"
                  }`}
                >
                  verdict:{" "}
                  {finding.patch.validation_verdict?.toUpperCase()}
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

        {/* Accept / Reject */}
        {finding.patch && !decisionDone && (
          <div className="mt-6 flex items-center gap-3">
            {canAccept ? (
              <button
                onClick={() => makeDecision("accept")}
                disabled={deciding}
                className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-success/40 bg-success/10 px-5 py-2.5 font-mono text-xs font-medium text-success disabled:opacity-50"
              >
                <CheckCircle2 className="size-3.5" />
                accept patch
              </button>
            ) : (
              <button
                onClick={() => makeDecision("accept", true)}
                disabled={deciding}
                className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-warning/40 bg-warning/10 px-5 py-2.5 font-mono text-xs font-medium text-warning disabled:opacity-50"
              >
                <AlertCircle className="size-3.5" />
                override & accept
              </button>
            )}
            <button
              onClick={() => makeDecision("reject")}
              disabled={deciding}
              className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-danger/40 bg-danger/10 px-5 py-2.5 font-mono text-xs font-medium text-danger disabled:opacity-50"
            >
              <XCircle className="size-3.5" />
              reject
            </button>
          </div>
        )}

        {decisionDone && !showQuiz && (
          <div
            className={`mt-6 inline-flex items-center gap-2 rounded-full border px-4 py-2 font-mono text-xs font-medium ${
              decisionDone === "accept"
                ? "border-success/40 text-success"
                : "border-danger/40 text-danger"
            }`}
          >
            {decisionDone === "accept" ? (
              <CheckCircle2 className="size-3.5" />
            ) : (
              <XCircle className="size-3.5" />
            )}
            {decisionDone === "accept" ? "patch accepted" : "patch rejected"}
          </div>
        )}

        {/* Post-decision quiz */}
        {showQuiz && quiz && (
          <div className="mt-8">
            <p className="mb-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
              education check
            </p>
            <TerminalWindow title={`quiz — ${finding.vulnerability_class}`}>
              <div className="text-subtle text-xs mb-3">
                // quick check before the fix lands
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
                    {String.fromCharCode(97 + i)}) {opt}
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
                <div className="mt-4 border-t border-border pt-3">
                  <span
                    className={
                      quizAnswer === quiz.correctIndex
                        ? "text-success"
                        : "text-danger"
                    }
                  >
                    {quizAnswer === quiz.correctIndex
                      ? "✓ correct!"
                      : "✗ not quite"}
                  </span>
                  <Link
                    to="/score"
                    className="ml-4 text-accent hover:underline font-mono text-[11px]"
                  >
                    view your security score →
                  </Link>
                </div>
              )}
            </TerminalWindow>
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
    <div className="p-4 flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-wider text-subtle">
        {label}
      </span>
      {na ? (
        <span className="font-mono text-xs text-subtle">n/a</span>
      ) : (
        <span
          className={`font-mono text-sm font-semibold ${pass ? "text-success" : "text-danger"}`}
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
