/**
 * src/lib/preflight-checker.ts
 *
 * Pre-flight API Key & Provider Verification.
 * - Executes ONE lightweight authenticated request before AI scan stages begin.
 * - Detects 401/403 fast before any finding is processed.
 * - Halts provider immediately on authentication rejection.
 * - Tests primary key, and falls back to testing backup key if primary is rejected.
 * - Never includes more than the last 4 characters of any key in logs or messages.
 * - Classifies "Failed to fetch" into mixed-content / ECONNREFUSED / CORS / LNA
 *   so the user sees a checklist instead of a generic error.
 */

import {
  detectProvider,
  redactKeys,
  validateEndpointUrl,
  formatKeyHint,
  PROVIDER_INFOS,
  type DetectedProvider,
} from "./ai-provider-detector";
import { classifyFetchFailure, buildPreflightChecklist, isDeployedHttps } from "./preflight-errors";

export interface PreflightCheckResult {
  ok: boolean;
  provider: DetectedProvider;
  providerName: string;
  status?: number | undefined;
  isAuthError: boolean;
  errorMessage?: string | undefined;
  /** Short checklist items to show when ok:false and !isAuthError */
  checklist?: string[] | undefined;
  /** Workaround text for mixed content / LNA failures */
  workaround?: string | undefined;
  /** Exact URL that was tried (for display) */
  urlTried?: string | undefined;
  keyHint?: string | undefined;
}

export interface PreflightOptions {
  explicitProvider?: DetectedProvider | undefined;
  baseUrl?: string | undefined;
  timeoutMs?: number | undefined;
}

/**
 * Executes a single cheap authenticated pre-flight call for a given API key.
 */
export async function preflightCheckProvider(
  apiKey: string,
  options: PreflightOptions = {},
): Promise<PreflightCheckResult> {
  const trimmedKey = (apiKey || "").trim();
  const provider = detectProvider(trimmedKey, options.explicitProvider);
  const info = PROVIDER_INFOS[provider];
  const providerName = info?.name || "AI Provider";
  const keyHint = formatKeyHint(trimmedKey);
  const timeoutMs = options.timeoutMs ?? 8000;

  if (!trimmedKey) {
    return {
      ok: false,
      provider: "unknown",
      providerName: "Unknown Provider",
      isAuthError: false,
      errorMessage: "No API key provided.",
      keyHint: "",
    };
  }

  if (provider === "unknown") {
    return {
      ok: false,
      provider: "unknown",
      providerName: "Unknown Provider",
      isAuthError: false,
      errorMessage: "Key format not recognized. Choose the provider manually from the dropdown.",
      keyHint,
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let lastUrlTried = "";

  try {
    if (provider === "groq") {
      lastUrlTried = "https://api.groq.com/openai/v1/models";
      const res = await fetch("https://api.groq.com/openai/v1/models", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${trimmedKey}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
      });

      if (res.status === 401 || res.status === 403) {
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: true,
          errorMessage: `${providerName} rejected your API key (HTTP ${res.status}). Check that the key belongs to ${providerName}.`,
          keyHint,
        };
      }

      if (res.status === 429) {
        return {
          ok: false,
          provider,
          providerName,
          status: 429,
          isAuthError: false,
          errorMessage: `${providerName} rate limit or free quota reached. Please wait or configure a backup provider.`,
          keyHint,
        };
      }

      if (!res.ok) {
        const body = redactKeys(await res.text(), [trimmedKey]);
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: false,
          errorMessage: `${providerName} returned HTTP ${res.status}: ${body.slice(0, 200)}`,
          keyHint,
        };
      }

      return { ok: true, provider, providerName, keyHint, isAuthError: false };
    }

    if (provider === "gemini") {
      const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${trimmedKey}`;
      lastUrlTried = "https://generativelanguage.googleapis.com/v1beta/models";
      const res = await fetch(url, {
        method: "GET",
        signal: controller.signal,
      });

      if (res.status === 400 || res.status === 401 || res.status === 403) {
        const text = await res.text();
        const isApiKeyError =
          text.includes("API_KEY_INVALID") ||
          text.includes("API key not valid") ||
          res.status === 401 ||
          res.status === 403;

        if (isApiKeyError) {
          return {
            ok: false,
            provider,
            providerName,
            status: res.status,
            isAuthError: true,
            errorMessage: `${providerName} rejected your API key (HTTP ${res.status}). Check that the key belongs to ${providerName}.`,
            keyHint,
          };
        }
      }

      if (res.status === 429) {
        return {
          ok: false,
          provider,
          providerName,
          status: 429,
          isAuthError: false,
          errorMessage: `${providerName} rate limit or free quota reached. Please wait or configure a backup provider.`,
          keyHint,
        };
      }

      if (!res.ok) {
        const body = redactKeys(await res.text(), [trimmedKey]);
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: false,
          errorMessage: `${providerName} returned HTTP ${res.status}: ${body.slice(0, 200)}`,
          keyHint,
        };
      }

      return { ok: true, provider, providerName, keyHint, isAuthError: false };
    }

    if (provider === "openrouter") {
      lastUrlTried = "https://openrouter.ai/api/v1/auth/key";
      const res = await fetch("https://openrouter.ai/api/v1/auth/key", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${trimmedKey}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
      });

      if (res.status === 401 || res.status === 403) {
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: true,
          errorMessage: `${providerName} rejected your API key (HTTP ${res.status}). Check that the key belongs to ${providerName}.`,
          keyHint,
        };
      }

      if (res.status === 429) {
        return {
          ok: false,
          provider,
          providerName,
          status: 429,
          isAuthError: false,
          errorMessage: `${providerName} rate limit or free quota reached.`,
          keyHint,
        };
      }

      if (!res.ok) {
        const body = redactKeys(await res.text(), [trimmedKey]);
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: false,
          errorMessage: `${providerName} returned HTTP ${res.status}: ${body.slice(0, 200)}`,
          keyHint,
        };
      }

      return { ok: true, provider, providerName, keyHint, isAuthError: false };
    }

    if (provider === "freellmapi" || provider === "custom_openai") {
      const customUrl =
        options.baseUrl ||
        (typeof sessionStorage !== "undefined"
          ? sessionStorage.getItem("sl_ai_custom_url")
          : null) ||
        "http://localhost:3001/v1";

      const { isValid, error, normalizedUrl } = validateEndpointUrl(customUrl);
      if (!isValid || !normalizedUrl) {
        return {
          ok: false,
          provider,
          providerName,
          status: 400,
          isAuthError: false,
          errorMessage: error || "Invalid custom endpoint Base URL.",
          keyHint,
        };
      }

      // Warn about mixed content before even attempting the fetch (saves a confusing error)
      const modelsUrl = `${normalizedUrl}/models`;
      lastUrlTried = modelsUrl;
      if (
        isDeployedHttps() &&
        (normalizedUrl.startsWith("http://") ||
          normalizedUrl.match(/^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.)/))
      ) {
        const kind = normalizedUrl.startsWith("http://") ? "mixed_content" : "local_network_access";
        const cl = buildPreflightChecklist(modelsUrl, providerName, keyHint, kind);
        return {
          ok: false,
          provider,
          providerName,
          isAuthError: false,
          errorMessage: cl.message,
          checklist: cl.checklist,
          workaround: cl.workaround,
          urlTried: modelsUrl,
          keyHint,
        };
      }

      const res = await fetch(modelsUrl, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${trimmedKey}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
      });

      if (res.status === 401 || res.status === 403) {
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: true,
          errorMessage: `${providerName} rejected your API key (HTTP ${res.status}). Check that the key belongs to ${providerName}.`,
          urlTried: modelsUrl,
          keyHint,
        };
      }

      if (res.status === 429) {
        return {
          ok: false,
          provider,
          providerName,
          status: 429,
          isAuthError: false,
          errorMessage: `${providerName} rate limit or free quota reached.`,
          urlTried: modelsUrl,
          keyHint,
        };
      }

      if (!res.ok) {
        const body = redactKeys(await res.text(), [trimmedKey]);
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: false,
          errorMessage: `${providerName} returned HTTP ${res.status}: ${body.slice(0, 200)}`,
          urlTried: modelsUrl,
          keyHint,
        };
      }

      return { ok: true, provider, providerName, keyHint, isAuthError: false, urlTried: modelsUrl };
    }

    if (provider === "cohere") {
      lastUrlTried = "https://api.cohere.com/v2/models";
      const res = await fetch("https://api.cohere.com/v2/models", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${trimmedKey}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
      });

      if (res.status === 401 || res.status === 403) {
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: true,
          errorMessage: `${providerName} rejected your API key (HTTP ${res.status}). Check that the key belongs to ${providerName}.`,
          keyHint,
        };
      }

      if (res.status === 429) {
        return {
          ok: false,
          provider,
          providerName,
          status: 429,
          isAuthError: false,
          errorMessage: `${providerName} rate limit or free quota reached.`,
          keyHint,
        };
      }

      if (!res.ok) {
        const body = redactKeys(await res.text(), [trimmedKey]);
        return {
          ok: false,
          provider,
          providerName,
          status: res.status,
          isAuthError: false,
          errorMessage: `${providerName} returned HTTP ${res.status}: ${body.slice(0, 200)}`,
          keyHint,
        };
      }

      return { ok: true, provider, providerName, keyHint, isAuthError: false };
    }

    if (provider === "openai") {
      try {
        lastUrlTried = "https://api.openai.com/v1/models";
        const res = await fetch("https://api.openai.com/v1/models", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${trimmedKey}`,
            "Content-Type": "application/json",
          },
          signal: controller.signal,
        });

        if (res.status === 401 || res.status === 403) {
          return {
            ok: false,
            provider,
            providerName,
            status: res.status,
            isAuthError: true,
            errorMessage: `${providerName} rejected your API key (HTTP ${res.status}). Check that the key belongs to ${providerName}.`,
            keyHint,
          };
        }

        if (res.status === 429) {
          return {
            ok: false,
            provider,
            providerName,
            status: 429,
            isAuthError: false,
            errorMessage: `${providerName} rate limit or free quota reached.`,
            keyHint,
          };
        }

        return { ok: true, provider, providerName, keyHint, isAuthError: false };
      } catch (err: any) {
        return {
          ok: false,
          provider,
          providerName,
          status: 0,
          isAuthError: false,
          errorMessage:
            "OpenAI API blocks direct browser calls (CORS). Use OpenRouter, Groq, Gemini, or a custom proxy.",
          keyHint,
        };
      }
    }

    return { ok: true, provider, providerName, keyHint, isAuthError: false };
  } catch (err: any) {
    const errorMsg = redactKeys(err?.message || String(err), [trimmedKey]);
    if (err.name === "AbortError") {
      return {
        ok: false,
        provider,
        providerName,
        isAuthError: false,
        errorMessage: `${providerName} pre-flight check timed out after ${timeoutMs}ms.`,
        urlTried: lastUrlTried || undefined,
        keyHint,
      };
    }
    const kind = classifyFetchFailure(lastUrlTried, err?.name, err?.message);
    const cl = buildPreflightChecklist(lastUrlTried, providerName, keyHint, kind);
    return {
      ok: false,
      provider,
      providerName,
      isAuthError: false,
      errorMessage: cl.message,
      checklist: cl.checklist,
      workaround: cl.workaround,
      urlTried: lastUrlTried || undefined,
      keyHint,
    };
  } finally {
    clearTimeout(timer);
  }
}
