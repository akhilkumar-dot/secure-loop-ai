import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { ArrowLeft, Save } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { supabase } from "@/lib/supabase";
import { Logo } from "@/components/chrome";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [{ title: "Settings — SecureLoop" }],
  }),
  component: SettingsPage,
});

function SettingsPage() {
  const navigate = useNavigate();
  const { user, loading, signOut } = useAuth();
  const [displayName, setDisplayName] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [geminiKey, setGeminiKey] = useState("");
  const [llmProvider, setLlmProvider] = useState("gemini");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingProfile, setLoadingProfile] = useState(true);

  useEffect(() => {
    if (!loading && !user) navigate({ to: "/login" });
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user) fetchProfile();
  }, [user]);

  async function fetchProfile() {
    setLoadingProfile(true);
    const { data } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user!.id)
      .single();
    if (data) {
      setDisplayName((data as any).display_name ?? "");
      setGithubToken((data as any).github_token ?? "");
      setGeminiKey((data as any).gemini_api_key ?? "");
      setLlmProvider((data as any).llm_provider ?? "gemini");
    }
    setLoadingProfile(false);
  }

  async function saveSettings() {
    if (!user) return;
    setSaving(true);
    setError(null);

    const { error } = await supabase
      .from("profiles")
      .upsert({
        id: user.id,
        display_name: displayName,
        github_token: githubToken || null,
        gemini_api_key: geminiKey || null,
        llm_provider: llmProvider,
        updated_at: new Date().toISOString(),
      });

    if (error) {
      setError(error.message);
    } else {
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    }
    setSaving(false);
  }

  if (loading || loadingProfile) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">loading…</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-3xl items-center justify-between px-6">
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

      <main className="mx-auto max-w-3xl px-6 py-10">
        <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
          account settings
        </p>
        <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight">
          Settings
        </h1>

        <div className="mt-8 space-y-6">
          {/* Account */}
          <Section title="account">
            <Field label="email (read-only)">
              <input
                readOnly
                value={user?.email ?? ""}
                className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-subtle cursor-not-allowed"
              />
            </Field>
            <Field label="display name">
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Ada Lovelace"
                className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
              />
            </Field>
          </Section>

          {/* AI Provider */}
          <Section title="ai configuration">
            <p className="mb-3 font-mono text-[11px] text-subtle leading-relaxed">
              SecureLoop uses Gemini to analyze code, explain vulnerabilities, generate patches, and validate fixes.
              Your API key is stored encrypted in Supabase and never shared.
            </p>
            <Field label="Google Gemini API key">
              <input
                type="password"
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                placeholder="AIzaSy…"
                className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
              />
              <p className="mt-1 font-mono text-[10px] text-subtle/50">
                Get a key at{" "}
                <a
                  href="https://aistudio.google.com/app/apikey"
                  target="_blank"
                  rel="noreferrer"
                  className="text-accent hover:underline"
                >
                  aistudio.google.com
                </a>
              </p>
            </Field>
            <div className="mt-3">
              <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                model
              </label>
              <div className="flex gap-2">
                {[
                  { id: "gemini", label: "Gemini 2.0 Flash" },
                  { id: "gemini-pro", label: "Gemini 2.0 Pro" },
                ].map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setLlmProvider(m.id)}
                    className={`rounded-full border px-4 py-2 font-mono text-[11px] cursor-pointer transition-colors ${
                      llmProvider === m.id
                        ? "border-accent/50 bg-accent/10 text-foreground"
                        : "border-border text-subtle hover:text-foreground"
                    }`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>
          </Section>

          {/* GitHub */}
          <Section title="github integration">
            <p className="mb-3 font-mono text-[11px] text-subtle leading-relaxed">
              A personal access token with <code className="text-foreground">repo</code> scope
              is required to scan <strong className="text-foreground">private</strong> repositories.
              Public repos work without a token.
            </p>
            <Field label="github personal access token">
              <input
                type="password"
                value={githubToken}
                onChange={(e) => setGithubToken(e.target.value)}
                placeholder="ghp_••••••••••••••••"
                className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none"
              />
              <p className="mt-1 font-mono text-[10px] text-subtle/50">
                Create at GitHub → Settings → Developer Settings → Personal access tokens
              </p>
            </Field>
          </Section>

          {/* Danger zone */}
          <Section title="session">
            <div className="flex items-center justify-between rounded-lg border border-danger/20 bg-danger/5 px-4 py-3">
              <div>
                <p className="font-mono text-xs font-semibold text-foreground">Sign out</p>
                <p className="font-mono text-[11px] text-subtle mt-0.5">
                  You will be redirected to the login page.
                </p>
              </div>
              <button
                onClick={signOut}
                className="rounded-full border border-danger/40 px-4 py-2 font-mono text-[11px] text-danger hover:bg-danger/10 cursor-pointer transition-colors"
              >
                sign out
              </button>
            </div>
          </Section>
        </div>

        {error && (
          <p className="mt-4 font-mono text-xs text-danger">{error}</p>
        )}

        <div className="mt-8 flex items-center gap-3">
          <button
            onClick={saveSettings}
            disabled={saving}
            className="pill-hover inline-flex cursor-pointer items-center gap-2 rounded-full border border-border bg-elevated px-5 py-2.5 font-mono text-xs font-medium text-foreground disabled:opacity-50"
          >
            <span className="size-1.5 rounded-full bg-accent" />
            <Save className="size-3" />
            {saving ? "saving…" : "save settings"}
          </button>
          {saved && (
            <span className="font-mono text-xs text-success">✓ saved</span>
          )}
        </div>
      </main>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-elevated p-5">
      <p className="mb-4 font-mono text-[10px] uppercase tracking-wider text-subtle">
        {title}
      </p>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-subtle">
        {label}
      </label>
      {children}
    </div>
  );
}
