import { useState, useEffect, useCallback } from "react";
import { supabase } from "@/lib/supabase";
import type { User, Session } from "@supabase/supabase-js";

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    // Safety timeout: guarantee loading ends within 1.2s even if network is slow/failing
    const timer = setTimeout(() => {
      if (mounted) setLoading(false);
    }, 1200);

    async function syncProfile(sess: Session | null) {
      if (sess?.user) {
        try {
          const updates: any = {
            id: sess.user.id,
            display_name:
              (sess.user.user_metadata as Record<string, any>)?.[
                "full_name"
              ] ||
              (sess.user.user_metadata as Record<string, any>)?.[
                "preferred_username"
              ] ||
              sess.user.email,
            updated_at: new Date().toISOString(),
          };
          if (sess.provider_token) {
            updates.github_token = sess.provider_token;
          }
          await supabase.from("profiles").upsert(updates);
        } catch (e) {
          console.warn("Failed to sync profile:", e);
        }
      }
    }

    // Get initial session
    supabase.auth
      .getSession()
      .then(({ data: { session } }) => {
        if (!mounted) return;
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);
        syncProfile(session);
      })
      .catch((err) => {
        console.warn("getSession error:", err);
        if (mounted) setLoading(false);
      });

    // Listen for auth changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (!mounted) return;
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
      syncProfile(session);
    });

    return () => {
      mounted = false;
      clearTimeout(timer);
      subscription.unsubscribe();
    };
  }, []);

  const signUp = useCallback(
    async (email: string, password: string, displayName?: string) => {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { data: { display_name: displayName } },
      });
      return { data, error };
    },
    [],
  );

  const signIn = useCallback(async (email: string, password: string) => {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    return { data, error };
  }, []);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
  }, []);

  const signInWithGitHub = useCallback(async () => {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: `${window.location.origin}/dashboard`,
        scopes: "repo read:user user:email",
      },
    });
    return { data, error };
  }, []);

  const providerToken = session?.provider_token ?? null;
  const isGitHubAuth = user?.app_metadata?.provider === "github";
  const githubUser = isGitHubAuth ? user?.user_metadata : null;

  return { user, session, loading, signUp, signIn, signOut, signInWithGitHub, providerToken, isGitHubAuth, githubUser };
}
