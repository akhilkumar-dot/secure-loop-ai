import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { ArrowLeft } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase, type DbSecurityScore } from "@/lib/supabase";
import { Logo, ScoreBadge } from "@/components/chrome";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

export const Route = createFileRoute("/score")({
  head: () => ({
    meta: [
      { title: "Security Score — SecureLoop" },
      { name: "description", content: "Your security score dashboard." },
    ],
  }),
  component: ScorePage,
});

const CATEGORIES = [
  { key: "sqli", label: "SQL Injection", color: "#FF5C33" },
  { key: "xss", label: "XSS", color: "#3ECF8E" },
  { key: "csrf", label: "CSRF", color: "#8C8C87" },
  { key: "deserialization", label: "Deserialization", color: "#FF5C5C" },
] as const;

function ScorePage() {
  const navigate = useNavigate();
  const { user, loading } = useAuth();
  const [scores, setScores] = useState<DbSecurityScore[]>([]);
  const [loadingScores, setLoadingScores] = useState(true);

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user) fetchScores();
  }, [user]);

  async function fetchScores() {
    setLoadingScores(true);
    const { data } = await supabase
      .from("security_scores")
      .select("*")
      .eq("user_id", user!.id)
      .order("computed_at", { ascending: true });
    setScores((data as DbSecurityScore[]) ?? []);
    setLoadingScores(false);
  }

  const latest = scores[scores.length - 1];

  // Build chart data
  const chartData = scores.map((s) => ({
    date: new Date(s.computed_at).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    }),
    overall: s.overall,
    sqli: s.sqli,
    xss: s.xss,
    csrf: s.csrf,
    deserialization: s.deserialization,
  }));

  if (loading || loadingScores) {
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
          security score
        </p>
        <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight">
          Your Progress
        </h1>

        {scores.length === 0 ? (
          <div className="mt-12 rounded-lg border border-border bg-elevated p-10 text-center">
            <p className="font-mono text-sm text-subtle">
              no score data yet — accept or reject some findings to generate scores
            </p>
            <Link
              to="/dashboard"
              className="pill-hover mt-6 inline-flex items-center gap-2 rounded-full border border-border bg-background px-4 py-2 font-mono text-xs text-foreground"
            >
              <span className="size-1.5 rounded-full bg-accent" />
              go to dashboard
            </Link>
          </div>
        ) : (
          <>
            {/* Current scores */}
            <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-5">
              <div className="col-span-2 sm:col-span-1 flex flex-col items-center justify-center rounded-lg border border-border bg-elevated p-5">
                <span className="font-mono text-[10px] uppercase tracking-wider text-subtle mb-2">
                  overall
                </span>
                <ScoreBadge score={latest?.overall ?? 0} />
              </div>
              {CATEGORIES.map((c) => (
                <div
                  key={c.key}
                  className="flex flex-col items-center justify-center rounded-lg border border-border bg-elevated p-4"
                >
                  <span className="font-mono text-[10px] uppercase tracking-wider text-subtle mb-2 text-center">
                    {c.label}
                  </span>
                  <ScoreBadge score={latest?.[c.key as keyof DbSecurityScore] as number ?? 0} size="sm" />
                </div>
              ))}
            </div>

            {/* Chart */}
            {chartData.length > 1 && (
              <div className="mt-8 rounded-lg border border-border bg-elevated p-5">
                <p className="mb-5 font-mono text-[10px] uppercase tracking-wider text-subtle">
                  score history
                </p>
                <ResponsiveContainer width="100%" height={260}>
                  <LineChart data={chartData}>
                    <XAxis
                      dataKey="date"
                      tick={{ fontFamily: "JetBrains Mono", fontSize: 10, fill: "#8C8C87" }}
                      axisLine={{ stroke: "#262626" }}
                      tickLine={false}
                    />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fontFamily: "JetBrains Mono", fontSize: 10, fill: "#8C8C87" }}
                      axisLine={{ stroke: "#262626" }}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#121212",
                        border: "1px solid #262626",
                        fontFamily: "JetBrains Mono",
                        fontSize: 11,
                        color: "#F2F1EC",
                      }}
                    />
                    <Legend
                      wrapperStyle={{
                        fontFamily: "JetBrains Mono",
                        fontSize: 10,
                        color: "#8C8C87",
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="overall"
                      stroke="#F2F1EC"
                      strokeWidth={2}
                      dot={false}
                    />
                    {CATEGORIES.map((c) => (
                      <Line
                        key={c.key}
                        type="monotone"
                        dataKey={c.key}
                        stroke={c.color}
                        strokeWidth={1.5}
                        dot={false}
                        strokeDasharray="4 2"
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Category breakdown table */}
            <div className="mt-6 overflow-hidden rounded-lg border border-border">
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b border-border bg-elevated text-left text-subtle">
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">category</th>
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">score</th>
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">status</th>
                  </tr>
                </thead>
                <tbody>
                  {CATEGORIES.map((c) => {
                    const score = (latest?.[c.key as keyof DbSecurityScore] as number) ?? 0;
                    return (
                      <tr key={c.key} className="border-b border-border">
                        <td className="px-5 py-3.5 text-foreground">{c.label}</td>
                        <td className="px-5 py-3.5">
                          <div className="flex items-center gap-3">
                            <div className="h-1.5 w-32 rounded-full bg-border overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${score}%`,
                                  background: c.color,
                                }}
                              />
                            </div>
                            <span
                              className={
                                score >= 80
                                  ? "text-success"
                                  : score >= 60
                                    ? "text-warning"
                                    : "text-danger"
                              }
                            >
                              {score}
                            </span>
                          </div>
                        </td>
                        <td className="px-5 py-3.5 text-subtle">
                          {score >= 80 ? "secure" : score >= 60 ? "fair" : "needs attention"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
