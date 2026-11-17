import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  ArrowLeft,
  Brain,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  ShieldAlert,
  Award,
  RefreshCw,
  BookOpen,
  ChevronRight,
  Target,
  Lock,
} from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase } from "@/lib/supabase";
import { Logo, TerminalWindow } from "@/components/chrome";
import {
  getAllMasteryProfiles,
  updateMasteryAfterAnswer,
  type MasteryProfileRow,
} from "@/lib/mastery-db";
import { daysUntilReview, getMasteryLevel, type MasteryLevel } from "@/lib/spaced-repetition";
import {
  pickQuestion,
  getMisconceptionId,
  getUnlockedTiers,
  type VulnClass,
  type Tier,
  type TieredQuestion,
} from "@/lib/quiz-bank";
import {
  detectAndSaveRecurringMisconceptions,
  getRecurringMisconceptions,
  MISCONCEPTION_LABELS,
} from "@/lib/misconception";
import { checkTierAllowed } from "@/lib/tier-progression";

export const Route = createFileRoute("/learn")({
  validateSearch: (search: Record<string, unknown>): { class?: VulnClass | undefined } => {
    return {
      class: (search["class"] as VulnClass) || undefined,
    };
  },
  head: () => ({
    meta: [
      { title: "Learning Hub — SecureLoop" },
      { name: "description", content: "Master secure coding concepts with spaced repetition." },
    ],
  }),
  component: LearnPage,
});

const CLASSES: Array<{ key: VulnClass; label: string; desc: string }> = [
  {
    key: "sqli",
    label: "SQL Injection",
    desc: "Parameterized queries, ORM safety, dynamic queries",
  },
  {
    key: "xss",
    label: "Cross-Site Scripting",
    desc: "Contextual encoding, JSX safety, CSP, DOM-XSS",
  },
  {
    key: "csrf",
    label: "Cross-Site Request Forgery",
    desc: "SameSite cookies, anti-CSRF tokens, API protection",
  },
  {
    key: "insecure_deserialization",
    label: "Insecure Deserialization",
    desc: "Safe serialization, gadget chains, object validation",
  },
];

interface RecentAttempt {
  id: string;
  vuln_class: VulnClass;
  tier: Tier;
  question: string;
  correct: boolean;
  answered_at: string;
}

function LearnPage() {
  const navigate = useNavigate();
  const search = Route.useSearch();
  const targetClass = search.class;
  const { user, loading } = useAuth();

  const [profiles, setProfiles] = useState<Record<VulnClass, MasteryProfileRow | null>>({
    sqli: null,
    xss: null,
    csrf: null,
    insecure_deserialization: null,
  });
  const [recurringMisconceptions, setRecurringMisconceptions] = useState<any[]>([]);
  const [recentAttempts, setRecentAttempts] = useState<RecentAttempt[]>([]);
  const [loadingData, setLoadingData] = useState(true);

  // Practice / Quiz State
  const [selectedClass, setSelectedClass] = useState<VulnClass | null>(null);
  const [activeQuestion, setActiveQuestion] = useState<TieredQuestion | null>(null);
  const [activeTier, setActiveTier] = useState<Tier>("easy");
  const [unlockedTiers, setUnlockedTiers] = useState<Set<Tier>>(new Set(["easy"]));
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [quizSubmitted, setQuizSubmitted] = useState(false);
  const [submittingQuiz, setSubmittingQuiz] = useState(false);
  const [justUnlockedTier, setJustUnlockedTier] = useState<Tier | null>(null);

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user) loadAllData();
  }, [user]);

  // Handle URL search parameter targeting a specific vulnerability class
  useEffect(() => {
    if (user && targetClass && CLASSES.some((c) => c.key === targetClass)) {
      startPractice(targetClass);
    }
  }, [user, targetClass]);

  async function loadAllData() {
    if (!user) return;
    setLoadingData(true);

    try {
      const [profilesList, miscList, attemptsRes] = await Promise.all([
        getAllMasteryProfiles(user.id),
        getRecurringMisconceptions(user.id),
        supabase
          .from("education_checks")
          .select("id, vuln_class, tier, question, correct, answered_at")
          .eq("user_id", user.id)
          .order("answered_at", { ascending: false })
          .limit(10),
      ]);

      const profMap: Record<VulnClass, MasteryProfileRow | null> = {
        sqli: null,
        xss: null,
        csrf: null,
        insecure_deserialization: null,
      };

      for (const p of profilesList) {
        if (p.vuln_class && p.vuln_class in profMap) {
          profMap[p.vuln_class as VulnClass] = p;
        }
      }

      setProfiles(profMap);
      setRecurringMisconceptions(miscList);
      setRecentAttempts((attemptsRes.data as RecentAttempt[]) ?? []);
    } catch (err) {
      console.error("Failed to load learning data:", err);
    } finally {
      setLoadingData(false);
    }
  }

  async function startPractice(vulnClass: VulnClass, requestedTier?: Tier) {
    if (!user) return;
    setSelectedClass(vulnClass);
    setSelectedAnswer(null);
    setQuizSubmitted(false);
    setJustUnlockedTier(null);

    // Get attempts to check unlocked tier and calculate rotating question offset
    const { data: pastAttempts } = await supabase
      .from("education_checks")
      .select("tier, correct, answered_at")
      .eq("user_id", user.id)
      .eq("vuln_class", vulnClass)
      .order("answered_at", { ascending: true });

    const attempts = (pastAttempts ?? []) as Array<{ tier: Tier; correct: boolean }>;
    const unlocked = getUnlockedTiers(attempts);
    setUnlockedTiers(unlocked);

    let chosenTier: Tier;
    if (requestedTier && unlocked.has(requestedTier)) {
      chosenTier = requestedTier;
    } else {
      chosenTier = unlocked.has("hard") ? "hard" : unlocked.has("medium") ? "medium" : "easy";
    }

    setActiveTier(chosenTier);
    const count = attempts.filter((a) => a.tier === chosenTier).length;
    const q = pickQuestion(vulnClass, chosenTier, count);
    setActiveQuestion(q);
  }

  async function switchPracticeTier(tier: Tier) {
    if (!selectedClass || !unlockedTiers.has(tier)) return;
    await startPractice(selectedClass, tier);
  }

  async function handleSubmitPractice() {
    if (selectedAnswer === null || !activeQuestion || !selectedClass || !user) return;
    setSubmittingQuiz(true);

    // 1. Server-side tier verification
    const isAllowed = await checkTierAllowed(user.id, selectedClass, activeTier);
    if (!isAllowed) {
      console.warn("[quiz] Tier is locked for user, rejecting submission");
      setSubmittingQuiz(false);
      return;
    }

    const isCorrect = selectedAnswer === activeQuestion.correctIndex;
    const misconceptionId = getMisconceptionId(activeQuestion, selectedAnswer);

    // 2. Persist education check
    await supabase.from("education_checks").insert({
      user_id: user.id,
      question_id: activeQuestion.id,
      vuln_class: selectedClass,
      tier: activeTier,
      question: activeQuestion.question,
      options: activeQuestion.options.map((o) => o.text),
      correct_index: activeQuestion.correctIndex,
      user_answer: selectedAnswer,
      correct: isCorrect,
      misconception_id: misconceptionId,
      answered_at: new Date().toISOString(),
    });

    // 3. Detect recurring misconceptions & resolve cleared ones
    const recurring = await detectAndSaveRecurringMisconceptions(user.id, selectedClass);

    // 4. Update SM-2 mastery profile
    await updateMasteryAfterAnswer(
      user.id,
      selectedClass,
      activeTier,
      isCorrect,
      recurring.length > 0,
    );

    // 5. Instantly refresh unlocked tiers so unlocking happens without page reload
    const { data: updatedAttempts } = await supabase
      .from("education_checks")
      .select("tier, correct")
      .eq("user_id", user.id)
      .eq("vuln_class", selectedClass);

    if (updatedAttempts) {
      const newUnlocked = getUnlockedTiers(
        updatedAttempts as Array<{ tier: Tier; correct: boolean }>,
      );
      if (!unlockedTiers.has("medium") && newUnlocked.has("medium")) {
        setJustUnlockedTier("medium");
      } else if (!unlockedTiers.has("hard") && newUnlocked.has("hard")) {
        setJustUnlockedTier("hard");
      }
      setUnlockedTiers(newUnlocked);
    }

    setQuizSubmitted(true);
    setSubmittingQuiz(false);
    loadAllData();
  }

  if (loading || loadingData) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">loading learning hub…</span>
      </div>
    );
  }

  // Summary counts
  const totalAttempts = Object.values(profiles).reduce(
    (acc, p) => acc + (p?.attempts_count ?? 0),
    0,
  );
  const totalCorrect = Object.values(profiles).reduce((acc, p) => acc + (p?.correct_count ?? 0), 0);
  const overallAccuracy = totalAttempts > 0 ? Math.round((totalCorrect / totalAttempts) * 100) : 0;

  // Real dueCount: only count classes that have been started (attempts > 0) AND review date is reached
  const dueCount = CLASSES.filter((c) => {
    const prof = profiles[c.key];
    if (!prof || prof.attempts_count === 0 || !prof.next_review_at) return false;
    const days = daysUntilReview(prof.next_review_at);
    return days !== null && days <= 0;
  }).length;

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
              to="/score"
              className="pill-hover inline-flex items-center gap-2 rounded-full border border-border bg-elevated px-3 py-1.5 font-mono text-[11px] text-subtle hover:text-foreground"
            >
              <Award className="size-3 text-accent" />
              security score
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10 space-y-8">
        {/* Header */}
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-accent flex items-center gap-1.5">
            <Brain className="size-3.5" />
            Adaptive Learning & Spaced Repetition
          </p>
          <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight text-foreground">
            Learning Hub
          </h1>
          <p className="mt-1 text-xs text-subtle max-w-2xl">
            Retain secure coding intuition through spaced practice. Correct answers expand review
            intervals, while detected misconceptions automatically pull topics closer for
            reinforcement.
          </p>
        </div>

        {/* Honest Empty State for New Learners */}
        {totalAttempts === 0 && (
          <div className="rounded-xl border border-accent/40 bg-accent/5 p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Sparkles className="size-4 text-accent" />
                <h3 className="font-display font-semibold text-foreground text-sm">
                  No attempts yet — start with SQL Injection, easy tier
                </h3>
              </div>
              <p className="mt-1 text-xs text-subtle font-mono">
                Build intuition through real tiered questions grounded in OWASP and MITRE CWE
                authoritative sources.
              </p>
            </div>
            <button
              onClick={() => startPractice("sqli")}
              className="pill-hover shrink-0 rounded-full border border-accent/50 bg-accent/20 px-4 py-2 font-mono text-xs text-accent font-semibold cursor-pointer"
            >
              start practice →
            </button>
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="rounded-xl border border-border bg-elevated p-4">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              total attempts
            </p>
            <p className="mt-2 font-display text-2xl font-bold text-foreground">{totalAttempts}</p>
          </div>
          <div className="rounded-xl border border-border bg-elevated p-4">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">accuracy</p>
            <p className="mt-2 font-display text-2xl font-bold text-foreground">
              {overallAccuracy}%
            </p>
          </div>
          <div className="rounded-xl border border-border bg-elevated p-4">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              due reviews
            </p>
            <p
              className={`mt-2 font-display text-2xl font-bold ${dueCount > 0 ? "text-warning" : "text-success"}`}
            >
              {dueCount}
            </p>
          </div>
          <div className="rounded-xl border border-border bg-elevated p-4">
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              active misconceptions
            </p>
            <p
              className={`mt-2 font-display text-2xl font-bold ${recurringMisconceptions.length > 0 ? "text-danger" : "text-subtle"}`}
            >
              {recurringMisconceptions.length}
            </p>
          </div>
        </div>

        {/* Active Misconception Warning Banner if any */}
        {recurringMisconceptions.length > 0 && (
          <div className="rounded-xl border border-warning/40 bg-warning/5 p-4 space-y-2">
            <div className="flex items-center gap-2 text-warning">
              <ShieldAlert className="size-4" />
              <h3 className="font-mono text-xs uppercase font-semibold">
                Active Misconception Diagnosis
              </h3>
            </div>
            <div className="space-y-1">
              {recurringMisconceptions.map((m) => (
                <div
                  key={m.id}
                  className="font-mono text-xs text-foreground flex items-center justify-between"
                >
                  <span>
                    • {m.misconception_label} ({m.vuln_class.toUpperCase()})
                  </span>
                  <button
                    onClick={() => startPractice(m.vuln_class)}
                    className="text-accent underline hover:text-accent/80 text-[11px]"
                  >
                    practice targeted quiz →
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Interactive Practice / Review Box */}
        {selectedClass && activeQuestion && (
          <div className="rounded-xl border border-accent/40 bg-accent/5 p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="size-2 rounded-full bg-accent animate-ping" />
                <h3 className="font-mono text-xs uppercase tracking-wider font-semibold text-foreground">
                  Reviewing: {CLASSES.find((c) => c.key === selectedClass)?.label}
                </h3>
              </div>

              {/* Tier Selection Pills */}
              <div className="flex items-center gap-1.5 font-mono text-xs">
                {(["easy", "medium", "hard"] as Tier[]).map((t) => {
                  const isUnlocked = unlockedTiers.has(t);
                  return (
                    <button
                      key={t}
                      disabled={!isUnlocked}
                      onClick={() => switchPracticeTier(t)}
                      title={
                        isUnlocked
                          ? `Switch to ${t}`
                          : `Locked: pass 2 of last 3 attempts at previous tier`
                      }
                      className={`px-3 py-1 rounded-md text-[11px] uppercase transition-colors flex items-center gap-1.5 ${
                        activeTier === t
                          ? "bg-accent/20 text-accent font-semibold border border-accent/40"
                          : isUnlocked
                            ? "bg-elevated text-subtle hover:text-foreground border border-border"
                            : "bg-elevated/30 text-subtle/40 border border-border/30 cursor-not-allowed"
                      }`}
                    >
                      {!isUnlocked && <Lock className="size-2.5" />}
                      {t}
                    </button>
                  );
                })}
              </div>

              <button
                onClick={() => setSelectedClass(null)}
                className="font-mono text-[11px] text-subtle hover:text-foreground cursor-pointer"
              >
                close
              </button>
            </div>

            {/* Notification when tier newly unlocked */}
            {justUnlockedTier && (
              <div className="rounded-lg border border-success/40 bg-success/10 px-4 py-2 font-mono text-xs text-success flex items-center gap-2">
                <Sparkles className="size-3.5 text-success" />
                <span>
                  Congratulations! <strong>{justUnlockedTier.toUpperCase()}</strong> tier unlocked
                  for {selectedClass.toUpperCase()}!
                </span>
              </div>
            )}

            <TerminalWindow title={`interactive review — ${selectedClass} · ${activeTier}`}>
              <div className="text-foreground text-sm mb-4 leading-relaxed font-mono">
                {activeQuestion.question}
              </div>
              <div className="space-y-2">
                {activeQuestion.options.map((opt, i) => (
                  <button
                    key={i}
                    disabled={quizSubmitted}
                    onClick={() => setSelectedAnswer(i)}
                    className={`block w-full cursor-pointer text-left px-3 py-2 rounded transition-colors font-mono text-xs ${
                      quizSubmitted
                        ? i === activeQuestion.correctIndex
                          ? "bg-success/15 text-success border border-success/30 font-semibold"
                          : i === selectedAnswer && i !== activeQuestion.correctIndex
                            ? "bg-danger/15 text-danger border border-danger/30"
                            : "text-subtle/50"
                        : selectedAnswer === i
                          ? "text-foreground bg-accent/20 border border-accent/40"
                          : "text-subtle hover:text-foreground hover:bg-elevated/50 border border-transparent"
                    }`}
                  >
                    <span className="font-bold mr-2">{String.fromCharCode(65 + i)}.</span>
                    {opt.text}
                    {quizSubmitted && i === activeQuestion.correctIndex && " ✓ (correct)"}
                    {quizSubmitted &&
                      i === selectedAnswer &&
                      i !== activeQuestion.correctIndex &&
                      " ✗"}
                  </button>
                ))}
              </div>

              {!quizSubmitted ? (
                <div className="mt-5 flex items-center justify-between">
                  <button
                    onClick={handleSubmitPractice}
                    disabled={selectedAnswer === null || submittingQuiz}
                    className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-5 py-2 font-mono text-xs text-foreground disabled:opacity-40"
                  >
                    <span className="size-1.5 rounded-full bg-accent" />
                    {submittingQuiz ? "submitting…" : "submit answer"}
                  </button>
                  <span className="font-mono text-[10px] text-subtle">
                    tier: {activeTier.toUpperCase()} · pass threshold: 2/3 correct
                  </span>
                </div>
              ) : (
                <div className="mt-5 border-t border-border pt-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span
                        className={`font-mono text-xs font-semibold ${selectedAnswer === activeQuestion.correctIndex ? "text-success" : "text-danger"}`}
                      >
                        {selectedAnswer === activeQuestion.correctIndex
                          ? "✓ Correct! Next review pushed out."
                          : "✗ Incorrect. Review scheduled sooner."}
                      </span>
                    </div>
                    <button
                      onClick={() => startPractice(selectedClass, activeTier)}
                      className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-4 py-1.5 font-mono text-xs text-subtle hover:text-foreground"
                    >
                      <RefreshCw className="size-3" />
                      next question
                    </button>
                  </div>

                  {/* Misconception diagnosis if answered wrong */}
                  {selectedAnswer !== null &&
                    selectedAnswer !== activeQuestion.correctIndex &&
                    activeQuestion.options[selectedAnswer]?.misconceptionId && (
                      <div className="rounded bg-warning/10 border border-warning/20 p-2.5 font-mono text-xs text-warning">
                        <span className="font-semibold block text-[10px] uppercase tracking-wider text-warning mb-0.5">
                          Diagnosed Misconception:
                        </span>
                        {MISCONCEPTION_LABELS[
                          activeQuestion.options[selectedAnswer]!.misconceptionId!
                        ] || "Common security misconception."}
                      </div>
                    )}

                  {/* Authoritative Source Reference */}
                  {activeQuestion.source && (
                    <div className="font-mono text-[10px] text-subtle flex items-center gap-1.5 pt-1">
                      <BookOpen className="size-3 text-accent" />
                      <span>Source:</span>
                      <a
                        href={activeQuestion.source.match(/https?:\/\/[^\s)]+/)?.[0] || "#"}
                        target="_blank"
                        rel="noreferrer"
                        className="text-accent underline hover:text-accent/80"
                      >
                        {activeQuestion.source}
                      </a>
                    </div>
                  )}
                </div>
              )}
            </TerminalWindow>
          </div>
        )}

        {/* 4 Vulnerability Class Mastery Profiles */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-lg font-semibold text-foreground">
              Vulnerability Mastery Profiles
            </h2>
            <span className="font-mono text-[10px] text-subtle">
              SM-2 intervals: 1d → 3d → 7d → 14d+
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {CLASSES.map((cls) => {
              const prof = profiles[cls.key];
              const attempts = prof?.attempts_count ?? 0;
              const correct = prof?.correct_count ?? 0;
              const accuracy = attempts > 0 ? Math.round((correct / attempts) * 100) : 0;
              const tier = prof?.tier_reached ?? "easy";
              const days = prof?.next_review_at ? daysUntilReview(prof.next_review_at) : null;
              const isDue = attempts > 0 && (days === null || days <= 0);
              const level: MasteryLevel = getMasteryLevel(
                attempts,
                correct,
                tier,
                prof?.ease_factor ?? 2.5,
                isDue,
              );

              return (
                <div
                  key={cls.key}
                  className="rounded-xl border border-border bg-elevated p-5 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-display font-semibold text-foreground">
                            {cls.label}
                          </h3>
                          <span
                            className={`font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border ${
                              level === "mastered"
                                ? "border-success/40 text-success bg-success/10"
                                : level === "learning"
                                  ? "border-warning/40 text-warning bg-warning/10"
                                  : level === "reviewing"
                                    ? "border-amber-500/40 text-amber-400 bg-amber-500/10"
                                    : "border-border text-subtle bg-background"
                            }`}
                          >
                            {level}
                          </span>
                        </div>
                        <p className="mt-1 font-mono text-[11px] text-subtle">{cls.desc}</p>
                      </div>

                      <span
                        className={`font-mono text-[10px] uppercase px-2 py-0.5 rounded border ${
                          tier === "hard"
                            ? "border-danger/40 text-danger"
                            : tier === "medium"
                              ? "border-warning/40 text-warning"
                              : "border-border text-subtle"
                        }`}
                      >
                        tier: {tier}
                      </span>
                    </div>

                    {/* Stats metrics */}
                    <div className="mt-4 grid grid-cols-3 gap-2 border-y border-border/60 py-3 font-mono text-xs">
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-subtle">attempts</p>
                        <p className="mt-0.5 text-foreground font-semibold">{attempts}</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-subtle">accuracy</p>
                        <p className="mt-0.5 text-foreground font-semibold">{accuracy}%</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-subtle">interval</p>
                        <p className="mt-0.5 text-foreground font-semibold">
                          {prof ? `${prof.interval_days}d` : "1d"}
                        </p>
                      </div>
                    </div>

                    {/* Review Schedule Indicator */}
                    <div className="mt-3 flex items-center justify-between font-mono text-xs">
                      <div className="flex items-center gap-1.5 text-subtle">
                        <Clock className="size-3 text-subtle" />
                        <span>
                          {attempts === 0 ? (
                            <span className="text-subtle">No attempts yet</span>
                          ) : isDue ? (
                            <span className="text-warning font-semibold">● Review due now</span>
                          ) : (
                            <span>
                              Next review in <strong className="text-foreground">{days}</strong> day
                              {days === 1 ? "" : "s"}
                            </span>
                          )}
                        </span>
                      </div>
                      {prof?.last_reviewed_at && (
                        <span className="text-[10px] text-subtle/60">
                          last: {new Date(prof.last_reviewed_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mt-5">
                    <button
                      onClick={() => startPractice(cls.key)}
                      className={`w-full pill-hover flex items-center justify-center gap-2 rounded-lg border py-2 font-mono text-xs cursor-pointer transition-colors ${
                        isDue
                          ? "border-warning/50 bg-warning/10 text-foreground font-semibold hover:border-warning"
                          : "border-border bg-background text-subtle hover:text-foreground"
                      }`}
                    >
                      <Target className="size-3.5" />
                      {attempts === 0
                        ? "Start practice (Easy)"
                        : isDue
                          ? "Practice due review"
                          : "Practice now"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Attempts History */}
        {recentAttempts.length > 0 && (
          <div className="rounded-xl border border-border bg-elevated p-5">
            <h3 className="font-display text-sm font-semibold text-foreground mb-4">
              Recent Review History
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b border-border text-subtle text-left">
                    <th className="pb-2">date</th>
                    <th className="pb-2">class</th>
                    <th className="pb-2">tier</th>
                    <th className="pb-2">result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {recentAttempts.map((att) => (
                    <tr key={att.id} className="py-2">
                      <td className="py-2 text-subtle">
                        {new Date(att.answered_at).toLocaleDateString()}
                      </td>
                      <td className="py-2 text-foreground uppercase">{att.vuln_class}</td>
                      <td className="py-2 text-subtle capitalize">{att.tier}</td>
                      <td className="py-2">
                        {att.correct ? (
                          <span className="text-success inline-flex items-center gap-1">
                            <CheckCircle2 className="size-3" /> correct
                          </span>
                        ) : (
                          <span className="text-danger inline-flex items-center gap-1">
                            <XCircle className="size-3" /> incorrect
                          </span>
                        )}
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
