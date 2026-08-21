import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { ShieldCheck, Github } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { Logo } from "@/components/chrome";

export const Route = createFileRoute("/login")({
  head: () => ({
    meta: [
      { title: "Sign in — SecureLoop" },
      { name: "description", content: "Sign in to your SecureLoop account." },
    ],
  }),
  component: LoginPage,
});

function LoginPage() {
  const navigate = useNavigate();
  const { user, loading, signIn, signUp, signInWithGitHub } = useAuth();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && user) {
      navigate({ to: "/dashboard" });
    }
  }, [user, loading, navigate]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setSubmitting(true);

    if (mode === "signup") {
      const { error } = await signUp(email, password, displayName);
      if (error) {
        setError(error.message);
      } else {
        setSuccessMsg(
          "Account created! Check your email to confirm, then sign in.",
        );
        setMode("signin");
      }
    } else {
      const { error } = await signIn(email, password);
      if (error) {
        setError(error.message);
      } else {
        navigate({ to: "/dashboard" });
      }
    }
    setSubmitting(false);
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span className="font-mono text-xs text-subtle animate-pulse">
          loading…
        </span>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      {/* Nav */}
      <header className="border-b border-border px-6 py-4">
        <Logo />
      </header>

      <div className="flex flex-1 items-center justify-center px-4 py-16">
        <div className="w-full max-w-sm">
          {/* Icon */}
          <div className="mb-8 flex flex-col items-center">
            <div className="flex size-10 items-center justify-center rounded-lg border border-border bg-elevated">
              <ShieldCheck className="size-5 text-accent" strokeWidth={1.5} />
            </div>
            <h1 className="mt-4 font-display text-xl font-semibold tracking-tight">
              {mode === "signin" ? "Welcome back" : "Create account"}
            </h1>
            <p className="mt-1 text-xs text-subtle">
              {mode === "signin"
                ? "Sign in to your SecureLoop account"
                : "Start securing your code today"}
            </p>
          </div>

          {/* GitHub OAuth */}
          <button
            onClick={() => signInWithGitHub()}
            className="pill-hover mb-4 flex w-full cursor-pointer items-center justify-center gap-2.5 rounded-lg border border-border bg-elevated px-4 py-2.5 font-mono text-xs font-medium transition-colors hover:text-foreground"
          >
            <Github className="size-4" />
            Continue with GitHub
          </button>

          <div className="relative mb-4">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center">
              <span className="bg-background px-3 font-mono text-[10px] uppercase tracking-wider text-subtle">
                or
              </span>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-3">
            {mode === "signup" && (
              <div>
                <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                  Display name
                </label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Ada Lovelace"
                  className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30 transition-colors"
                />
              </div>
            )}
            <div>
              <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                required
                className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30 transition-colors"
              />
            </div>
            <div>
              <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-subtle">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                minLength={8}
                className="w-full rounded-lg border border-border bg-elevated px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-subtle/50 focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30 transition-colors"
              />
            </div>

            {error && (
              <p className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 font-mono text-[11px] text-danger">
                {error}
              </p>
            )}
            {successMsg && (
              <p className="rounded-lg border border-success/30 bg-success/10 px-3 py-2 font-mono text-[11px] text-success">
                {successMsg}
              </p>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="pill-hover mt-1 flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-border bg-elevated px-4 py-2.5 font-mono text-xs font-medium text-foreground disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <span className="size-1.5 rounded-full bg-accent" />
              {submitting ? "…" : mode === "signin" ? "sign in" : "create account"}
            </button>
          </form>

          <p className="mt-5 text-center font-mono text-[11px] text-subtle">
            {mode === "signin" ? (
              <>
                No account?{" "}
                <button
                  onClick={() => {
                    setMode("signup");
                    setError(null);
                  }}
                  className="cursor-pointer text-foreground underline-offset-2 hover:underline"
                >
                  sign up
                </button>
              </>
            ) : (
              <>
                Already have an account?{" "}
                <button
                  onClick={() => {
                    setMode("signin");
                    setError(null);
                  }}
                  className="cursor-pointer text-foreground underline-offset-2 hover:underline"
                >
                  sign in
                </button>
              </>
            )}
          </p>

          <p className="mt-3 text-center font-mono text-[11px] text-subtle">
            <Link to="/" className="hover:text-foreground">
              ← back to home
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
