import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { ArrowLeft, Filter } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase, type DbFinding } from "@/lib/supabase";
import { Logo, SeverityBadge, StatusBadge } from "@/components/chrome";

export const Route = createFileRoute("/findings/$projectId")({
  head: () => ({
    meta: [{ title: "Findings — SecureLoop" }],
  }),
  component: FindingsPage,
});

type VulnClass = "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";
type FindingStatus =
  | "open"
  | "explained"
  | "patched"
  | "validated"
  | "accepted"
  | "rejected"
  | "likely_false_positive"
  | "dismissed";

const vulnClassLabels: Record<string, string> = {
  sqli: "SQL Injection",
  xss: "XSS",
  csrf: "CSRF",
  insecure_deserialization: "Insecure Deserialization",
  other: "Other",
};

function FindingsPage() {
  const { projectId } = Route.useParams();
  const navigate = useNavigate();
  const { user, loading } = useAuth();
  const [project, setProject] = useState<{ name: string } | null>(null);
  const [findings, setFindings] = useState<DbFinding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(true);
  const [filterClass, setFilterClass] = useState<VulnClass | "all">("all");
  const [filterStatus, setFilterStatus] = useState<FindingStatus | "all">("all");

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user && projectId) {
      fetchProject();
      fetchFindings();
    }
  }, [user, projectId]);

  async function fetchProject() {
    const { data } = await supabase.from("projects").select("name").eq("id", projectId).single();
    if (data) setProject(data);
  }

  async function fetchFindings() {
    setLoadingFindings(true);
    const { data } = await supabase
      .from("findings")
      .select("*")
      .eq("project_id", projectId)
      .order("created_at", { ascending: false });
    setFindings((data as DbFinding[]) ?? []);
    setLoadingFindings(false);
  }

  const filtered = findings.filter((f) => {
    if (filterClass !== "all" && f.vulnerability_class !== filterClass) return false;
    if (filterStatus !== "all" && f.status !== filterStatus) return false;
    return true;
  });

  if (loading || loadingFindings) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">loading…</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
          <Logo />
          <Link
            to="/dashboard"
            className="flex items-center gap-1.5 font-mono text-xs text-subtle hover:text-foreground"
          >
            <ArrowLeft className="size-3" />
            dashboard
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 sm:px-6 py-6 sm:py-10">
        <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
          vulnerability findings
        </p>
        <div className="mt-1 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <h1 className="font-display text-2xl font-semibold tracking-tight">
            {project?.name ?? "…"}
          </h1>
          <div className="flex items-center gap-2">
            <Link
              to="/report/$projectId"
              params={{ projectId }}
              className="pill-hover inline-flex items-center gap-1.5 sm:gap-2 rounded-full border border-border bg-elevated px-3 sm:px-4 py-1.5 sm:py-2 font-mono text-[11px] sm:text-xs text-subtle hover:text-foreground"
            >
              export PDF report
            </Link>
            <Link
              to="/scan/$projectId"
              params={{ projectId }}
              className="pill-hover inline-flex items-center gap-1.5 sm:gap-2 rounded-full border border-border bg-elevated px-3 sm:px-4 py-1.5 sm:py-2 font-mono text-[11px] sm:text-xs text-subtle hover:text-foreground"
            >
              <span className="size-1.5 rounded-full bg-accent" />
              new scan
            </Link>
          </div>
        </div>

        {/* Filters */}
        <div className="mt-6 flex items-center gap-1.5 sm:gap-2 overflow-x-auto no-scrollbar pb-1 -mx-4 px-4 sm:mx-0 sm:px-0 flex-nowrap sm:flex-wrap">
          <Filter className="size-3 text-subtle shrink-0" />
          <span className="font-mono text-[10px] uppercase tracking-wider text-subtle mr-1 shrink-0">
            filter:
          </span>
          {(["all", "sqli", "xss", "csrf", "insecure_deserialization"] as const).map((cls) => (
            <button
              key={cls}
              onClick={() => setFilterClass(cls as VulnClass | "all")}
              className={`rounded-full border px-2.5 sm:px-3 py-1 font-mono text-[10px] sm:text-[11px] cursor-pointer transition-colors shrink-0 ${
                filterClass === cls
                  ? "border-accent/50 bg-accent/10 text-foreground"
                  : "border-border text-subtle hover:text-foreground"
              }`}
            >
              {cls === "all" ? "all classes" : vulnClassLabels[cls]}
            </button>
          ))}
          <span className="mx-1 text-border shrink-0">|</span>
          {(
            ["all", "open", "validated", "accepted", "rejected", "likely_false_positive"] as const
          ).map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st as FindingStatus | "all")}
              className={`rounded-full border px-2.5 sm:px-3 py-1 font-mono text-[10px] sm:text-[11px] cursor-pointer transition-colors shrink-0 ${
                filterStatus === st
                  ? "border-accent/50 bg-accent/10 text-foreground"
                  : "border-border text-subtle hover:text-foreground"
              }`}
            >
              {st === "likely_false_positive" ? "false positives" : st}
            </button>
          ))}
        </div>

        {/* Findings table */}
        <div className="mt-6">
          {filtered.length === 0 ? (
            <div className="rounded-lg border border-border bg-elevated p-8 sm:p-10 text-center">
              <p className="font-mono text-sm text-subtle">
                {findings.length === 0
                  ? "no findings yet — run a scan first"
                  : "no findings match your filters"}
              </p>
              {findings.length === 0 && (
                <Link
                  to="/scan/$projectId"
                  params={{ projectId }}
                  className="pill-hover mt-4 inline-flex items-center gap-2 rounded-full border border-border bg-background px-4 py-2 font-mono text-xs text-foreground"
                >
                  <span className="size-1.5 rounded-full bg-accent" />
                  start a scan
                </Link>
              )}
            </div>
          ) : (
            <>
              {/* Desktop Table View */}
              <div className="hidden md:block overflow-x-auto rounded-lg border border-border">
                <table className="w-full font-mono text-xs">
                  <thead>
                    <tr className="border-b border-border bg-elevated text-left text-subtle">
                      <th className="px-5 py-3 font-medium uppercase tracking-wider">severity</th>
                      <th className="px-5 py-3 font-medium uppercase tracking-wider">class</th>
                      <th className="px-5 py-3 font-medium uppercase tracking-wider">file</th>
                      <th className="px-5 py-3 font-medium uppercase tracking-wider">cwe</th>
                      <th className="px-5 py-3 font-medium uppercase tracking-wider">status</th>
                      <th className="px-5 py-3 font-medium uppercase tracking-wider">tool</th>
                      <th className="px-5 py-3 font-medium uppercase tracking-wider" />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((f) => (
                      <tr
                        key={f.id}
                        className="border-b border-border transition-colors hover:bg-elevated/50 cursor-pointer"
                        onClick={() =>
                          navigate({
                            to: "/finding/$findingId",
                            params: { findingId: f.id },
                          })
                        }
                      >
                        <td className="px-5 py-3.5">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-5 py-3.5 text-subtle">
                          {f.vulnerability_class ? vulnClassLabels[f.vulnerability_class] : "—"}
                        </td>
                        <td className="px-5 py-3.5 text-foreground/80">
                          {f.file_path}
                          {f.line_start && <span className="text-subtle">:{f.line_start}</span>}
                        </td>
                        <td className="px-5 py-3.5 text-subtle">{f.cwe ?? "—"}</td>
                        <td className="px-5 py-3.5">
                          <StatusBadge status={f.status as any} />
                        </td>
                        <td className="px-5 py-3.5 text-subtle uppercase">{f.tool}</td>
                        <td className="px-5 py-3.5 text-right text-accent hover:underline">
                          review →
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Card View */}
              <div className="md:hidden space-y-3">
                {filtered.map((f) => (
                  <div
                    key={f.id}
                    onClick={() =>
                      navigate({
                        to: "/finding/$findingId",
                        params: { findingId: f.id },
                      })
                    }
                    className="rounded-lg border border-border bg-elevated p-4 space-y-2.5 cursor-pointer transition-colors hover:border-accent/40"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <SeverityBadge severity={f.severity} />
                      <StatusBadge status={f.status as any} />
                    </div>

                    <div>
                      <p className="font-mono text-xs font-semibold text-foreground break-all">
                        {f.file_path}
                        {f.line_start && <span className="text-subtle">:{f.line_start}</span>}
                      </p>
                      <p className="font-mono text-[11px] text-subtle mt-0.5">
                        {f.vulnerability_class ? vulnClassLabels[f.vulnerability_class] : "—"}
                        {f.cwe && <span className="ml-1.5 text-subtle/70">({f.cwe})</span>}
                      </p>
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-border/50 font-mono text-[11px]">
                      <span className="text-subtle uppercase text-[10px]">{f.tool}</span>
                      <span className="text-accent font-medium hover:underline flex items-center gap-1">
                        review →
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
