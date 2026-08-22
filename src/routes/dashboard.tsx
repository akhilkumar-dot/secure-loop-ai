import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  Plus,
  Github,
  Upload,
  LogOut,
  Settings,
  ChevronRight,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase, type DbProject, type DbScanRun } from "@/lib/supabase";
import { fetchUserGitHubRepos, type GitHubRepoItem } from "@/lib/github";
import { Logo, ScoreBadge } from "@/components/chrome";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "Dashboard — SecureLoop" },
      {
        name: "description",
        content: "Manage your SecureLoop projects and scans.",
      },
    ],
  }),
  component: DashboardPage,
});

type ProjectWithScore = DbProject & {
  score: number;
  lastScanStatus: string;
  lastScanAt: string;
  findingsCount: number;
};

function DashboardPage() {
  const navigate = useNavigate();
  const { user, loading, signOut, providerToken, isGitHubAuth, githubUser } = useAuth();
  const [projects, setProjects] = useState<ProjectWithScore[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [showNewProject, setShowNewProject] = useState(false);
  const [newRepoUrl, setNewRepoUrl] = useState("");
  const [newProjectName, setNewProjectName] = useState("");
  const [sourceType, setSourceType] = useState<"git" | "zip">("git");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [userRepos, setUserRepos] = useState<GitHubRepoItem[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [activeGithubToken, setActiveGithubToken] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && !user) {
      navigate({ to: "/login" });
    }
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user) {
      loadProjects();
      loadUserTokenAndRepos();
    }
  }, [user]);

  async function loadUserTokenAndRepos() {
    if (!user) return;
    setLoadingRepos(true);
    let token = providerToken;

    if (!token) {
      const { data } = await supabase
        .from("profiles")
        .select("github_token")
        .eq("id", user.id)
        .single();
      if (data?.github_token) {
        token = data.github_token;
      }
    }

    setActiveGithubToken(token);
    if (token) {
      const repos = await fetchUserGitHubRepos(token);
      setUserRepos(repos);
    }
    setLoadingRepos(false);
  }

  async function loadProjects() {
    setLoadingProjects(true);
    const { data: projectData } = await supabase
      .from("projects")
      .select("*")
      .order("created_at", { ascending: false });

    if (!projectData) {
      setLoadingProjects(false);
      return;
    }

    // Fetch scan runs and scores for each project
    const enriched: ProjectWithScore[] = await Promise.all(
      projectData.map(async (p) => {
        const { data: scans } = await supabase
          .from("scan_runs")
          .select("*")
          .eq("project_id", p.id)
          .order("created_at", { ascending: false })
          .limit(1);

        const { data: scores } = await supabase
          .from("security_scores")
          .select("overall")
          .eq("project_id", p.id)
          .order("computed_at", { ascending: false })
          .limit(1);

        const { count: findingsCount } = await supabase
          .from("findings")
          .select("*", { count: "exact", head: true })
          .eq("project_id", p.id)
          .eq("status", "open");

        const lastScan = scans?.[0] as DbScanRun | undefined;
        const lastScanAt = lastScan?.started_at
          ? new Date(lastScan.started_at).toLocaleDateString()
          : "—";

        return {
          ...p,
          score: scores?.[0]?.overall ?? 0,
          lastScanStatus: lastScan?.status ?? "—",
          lastScanAt,
          findingsCount: findingsCount ?? 0,
        };
      }),
    );

    setProjects(enriched);
    setLoadingProjects(false);
  }

  async function createProject() {
    if (!user) return;
    setCreateError(null);
    if (!newProjectName.trim()) {
      setCreateError("Project name is required.");
      return;
    }
    setCreating(true);

    const { data, error } = await supabase
      .from("projects")
      .insert({
        owner_id: user.id,
        name: newProjectName.trim(),
        source_type: sourceType,
        repo_url: sourceType === "git" ? newRepoUrl.trim() || null : null,
        default_branch: "main",
      })
      .select()
      .single();

    if (error) {
      setCreateError(error.message);
      setCreating(false);
      return;
    }

    setCreating(false);
    setShowNewProject(false);
    setNewProjectName("");
    setNewRepoUrl("");
    // Navigate to the new project's scan page
    navigate({ to: "/scan/$projectId", params: { projectId: data.id } });
  }

  if (loading || loadingProjects) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">
          loading…
        </span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
          <Logo />
          <div className="flex items-center gap-3">
            {(githubUser as Record<string, any>)?.[
              "avatar_url"
            ] && (
              <img
                src={(githubUser as Record<string, any>)["avatar_url"]}
                alt="GitHub"
                className="size-5 rounded-full border border-border"
              />
            )}
            <span className="hidden font-mono text-xs text-subtle sm:block">
              {(githubUser as Record<string, any>)?.[
                "preferred_username"
              ]
                ? `@${(githubUser as Record<string, any>)["preferred_username"]}`
                : user?.email}
            </span>
            <Link
              to="/score"
              className="pill-hover inline-flex items-center gap-2 rounded-full border border-border bg-elevated px-3 py-1.5 font-mono text-[11px] text-subtle hover:text-foreground"
            >
              <ShieldCheck className="size-3 text-accent" />
              score
            </Link>
            <Link
              to="/settings"
              className="pill-hover inline-flex items-center gap-2 rounded-full border border-border bg-elevated px-3 py-1.5 font-mono text-[11px] text-subtle hover:text-foreground"
            >
              <Settings className="size-3" />
              settings
            </Link>
            <button
              onClick={signOut}
              className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-3 py-1.5 font-mono text-[11px] text-subtle hover:text-foreground"
            >
              <LogOut className="size-3" />
              sign out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10">
        {/* Header row */}
        <div className="flex items-center justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              your projects
            </p>
            <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight">
              Dashboard
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={loadProjects}
              className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-4 py-2 font-mono text-xs text-subtle hover:text-foreground"
            >
              <RefreshCw className="size-3" />
              refresh
            </button>
            <button
              onClick={() => setShowNewProject(!showNewProject)}
              className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-4 py-2 font-mono text-xs text-foreground"
            >
              <span className="size-1.5 rounded-full bg-accent" />
              <Plus className="size-3" />
              new scan
            </button>
          </div>
        </div>

        {/* New project form */}
        {showNewProject && (
          <div className="mt-6 rounded-lg border border-border bg-elevated p-5">
            <div className="flex items-center justify-between mb-4">
              <p className="font-mono text-xs font-semibold">
                connect a repository
              </p>
              {activeGithubToken && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-success/30 bg-success/10 px-2.5 py-0.5 font-mono text-[10px] text-success">
                  <Github className="size-3" /> GitHub Authenticated
                </span>
              )}
            </div>

            <div className="flex gap-2 mb-3">
              <button
                onClick={() => setSourceType("git")}
                className={`flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono text-[11px] cursor-pointer transition-colors ${sourceType === "git" ? "border-accent/50 text-foreground bg-accent/10" : "border-border text-subtle hover:text-foreground"}`}
              >
                <Github className="size-3" />
                github url
              </button>
              <button
                onClick={() => setSourceType("zip")}
                className={`flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono text-[11px] cursor-pointer transition-colors ${sourceType === "zip" ? "border-accent/50 text-foreground bg-accent/10" : "border-border text-subtle hover:text-foreground"}`}
              >
                <Upload className="size-3" />
                zip upload
              </button>
            </div>

            {sourceType === "git" && userRepos.length > 0 && (
              <div className="mb-4 rounded-lg border border-border bg-background p-3">
                <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  Import from your GitHub repositories (1-click)
                </label>
                <select
                  onChange={(e) => {
                    const selected = userRepos.find((r) => r.clone_url === e.target.value);
                    if (selected) {
                      setNewProjectName(selected.name);
                      setNewRepoUrl(selected.html_url);
                    }
                  }}
                  className="w-full rounded-lg border border-border bg-elevated px-3 py-2 font-mono text-xs text-foreground focus:border-accent/50 focus:outline-none"
                >
                  <option value="">-- Select a repository --</option>
                  {userRepos.map((r) => (
                    <option key={r.id} value={r.clone_url}>
                      {r.full_name} {r.private ? "(private)" : ""} {r.language ? `• ${r.language}` : ""}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  project name
                </label>
                <input
                  type="text"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                  placeholder="my-api"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                />
              </div>
              {sourceType === "git" && (
                <div>
                  <label className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                    repo url
                  </label>
                  <input
                    type="text"
                    value={newRepoUrl}
                    onChange={(e) => setNewRepoUrl(e.target.value)}
                    placeholder="github.com/you/repo"
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
                  />
                </div>
              )}
            </div>
            {createError && (
              <p className="mt-2 font-mono text-[11px] text-danger">
                {createError}
              </p>
            )}
            <div className="mt-4 flex gap-2">
              <button
                onClick={createProject}
                disabled={creating}
                className="pill-hover flex cursor-pointer items-center gap-2 rounded-full border border-border bg-background px-4 py-2 font-mono text-xs text-foreground disabled:opacity-50"
              >
                <span className="size-1.5 rounded-full bg-accent" />
                {creating ? "creating…" : "create & scan"}
              </button>
              <button
                onClick={() => setShowNewProject(false)}
                className="rounded-full border border-border px-4 py-2 font-mono text-xs text-subtle hover:text-foreground cursor-pointer"
              >
                cancel
              </button>
            </div>
          </div>
        )}

        {/* Projects list */}
        <div className="mt-8">
          {projects.length === 0 ? (
            <div className="rounded-lg border border-border bg-elevated p-12 text-center">
              <ShieldCheck
                className="mx-auto size-8 text-subtle/30"
                strokeWidth={1}
              />
              <p className="mt-4 font-mono text-sm text-subtle">
                no projects yet
              </p>
              <p className="mt-1 font-mono text-xs text-subtle/60">
                connect a GitHub repo or upload a zip to start scanning
              </p>
              <button
                onClick={() => setShowNewProject(true)}
                className="pill-hover mt-6 inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-background px-4 py-2 font-mono text-xs text-foreground"
              >
                <span className="size-1.5 rounded-full bg-accent" />
                connect your first repo
              </button>
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b border-border bg-elevated text-left text-subtle">
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">
                      project
                    </th>
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">
                      last scan
                    </th>
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">
                      open findings
                    </th>
                    <th className="px-5 py-3 font-medium uppercase tracking-wider">
                      score
                    </th>
                    <th className="px-5 py-3 font-medium uppercase tracking-wider" />
                  </tr>
                </thead>
                <tbody>
                  {projects.map((p) => (
                    <tr
                      key={p.id}
                      className="border-b border-border transition-colors hover:bg-elevated/50 cursor-pointer"
                      onClick={() =>
                        navigate({
                          to: "/findings/$projectId",
                          params: { projectId: p.id },
                        })
                      }
                    >
                      <td className="px-5 py-4">
                        <div className="flex flex-col gap-0.5">
                          <span className="font-semibold text-foreground">
                            {p.name}
                          </span>
                          {p.repo_url && (
                            <span className="text-[10px] text-subtle/60">
                              {p.repo_url}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <span
                          className={
                            p.lastScanStatus === "done"
                              ? "text-success"
                              : p.lastScanStatus === "failed"
                                ? "text-danger"
                                : p.lastScanStatus === "—"
                                  ? "text-subtle"
                                  : "text-accent"
                          }
                        >
                          {p.lastScanStatus}
                        </span>
                        <span className="ml-2 text-subtle">{p.lastScanAt}</span>
                      </td>
                      <td className="px-5 py-4 text-foreground">
                        {p.findingsCount}
                      </td>
                      <td className="px-5 py-4">
                        <ScoreBadge score={p.score} size="sm" />
                      </td>
                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <Link
                            to="/scan/$projectId"
                            params={{ projectId: p.id }}
                            onClick={(e) => e.stopPropagation()}
                            className="text-accent hover:underline"
                          >
                            scan
                          </Link>
                          <ChevronRight className="size-3 text-subtle/40" />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
