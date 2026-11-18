/**
 * src/lib/ai-provider-detector.ts
 *
 * Provider detection, URL validation, and key redaction.
 * - Detects providers from distinct key prefixes.
 * - Explicitly detects "freellmapi-" as "freellmapi".
 * - Never guesses unknown keys as Cohere or Gemini; returns "unknown" when unrecognized.
 * - Validates custom OpenAI/FreeLLMAPI endpoint URLs (http/https only, no inline credentials).
 * - Redacts secrets and ensures no more than last 4 characters of any key appear in messages.
 */

export type DetectedProvider =
  | "gemini"
  | "openrouter"
  | "groq"
  | "openai"
  | "cohere"
  | "freellmapi"
  | "custom_openai"
  | "unknown";

export interface ProviderInfo {
  id: DetectedProvider;
  name: string;
  supportsBrowserCors: boolean;
  freeTierRpm: number;
  note?: string;
  requiresBaseUrl?: boolean;
  defaultBaseUrl?: string;
}

export const PROVIDER_INFOS: Record<DetectedProvider, ProviderInfo> = {
  gemini: {
    id: "gemini",
    name: "Google Gemini",
    supportsBrowserCors: true,
    freeTierRpm: 15,
    note: "Free-tier Gemini prompts may be used by Google to improve products. Avoid scanning private code.",
  },
  groq: {
    id: "groq",
    name: "Groq",
    supportsBrowserCors: true,
    freeTierRpm: 30,
  },
  openrouter: {
    id: "openrouter",
    name: "OpenRouter",
    supportsBrowserCors: true,
    freeTierRpm: 20,
  },
  freellmapi: {
    id: "freellmapi",
    name: "FreeLLMAPI",
    supportsBrowserCors: true,
    freeTierRpm: 30,
    requiresBaseUrl: true,
    defaultBaseUrl: "http://localhost:3001/v1",
    note: "FreeLLMAPI routes requests to free-tier providers. Free tiers may use your code to improve products. Don't scan private code.",
  },
  custom_openai: {
    id: "custom_openai",
    name: "Custom OpenAI-compatible",
    supportsBrowserCors: true,
    freeTierRpm: 30,
    requiresBaseUrl: true,
    defaultBaseUrl: "http://localhost:3001/v1",
    note: "Custom OpenAI-compatible endpoint. Requests go to the endpoint you enter. Don't scan private code with untrusted proxies.",
  },
  openai: {
    id: "openai",
    name: "OpenAI",
    supportsBrowserCors: false,
    freeTierRpm: 3,
    note: "OpenAI API blocks direct browser calls (CORS). Requires a proxy or compatible gateway.",
  },
  cohere: {
    id: "cohere",
    name: "Cohere",
    supportsBrowserCors: false,
    freeTierRpm: 10,
    note: "Cohere may block direct browser CORS requests.",
  },
  unknown: {
    id: "unknown",
    name: "Unknown Provider",
    supportsBrowserCors: false,
    freeTierRpm: 10,
  },
};

/**
 * Validates custom endpoint URLs:
 * - Must be valid http:// or https:// URL.
 * - Must not contain credentials (username or password).
 * - Strips trailing slashes for clean endpoint joining.
 */
export function validateEndpointUrl(url: string): {
  isValid: boolean;
  error?: string;
  normalizedUrl?: string;
} {
  const trimmed = (url || "").trim();
  if (!trimmed) {
    return { isValid: false, error: "Endpoint Base URL is required." };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      isValid: false,
      error: "Invalid URL format. Please provide a complete URL like http://localhost:3001/v1",
    };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      isValid: false,
      error: `Unsupported protocol '${parsed.protocol}'. Only http:// and https:// endpoints are supported.`,
    };
  }

  if (parsed.username || parsed.password) {
    return {
      isValid: false,
      error:
        "Security restriction: URLs cannot include inline credentials (user:password@host). Use the API key field instead.",
    };
  }

  // Remove trailing slashes and ensure path ends with /v1
  let path = parsed.pathname.replace(/\/+$/, "");
  if (!path.endsWith("/v1")) {
    if (path === "" || path === "/") {
      path = "/v1";
    } else {
      path = `${path}/v1`;
    }
  }

  const normalizedUrl = `${parsed.origin}${path}`;

  return { isValid: true, normalizedUrl };
}

/**
 * Formats a safe key hint showing at most the last 4 characters.
 */
export function formatKeyHint(key: string): string {
  const trimmed = (key || "").trim();
  if (!trimmed) return "";
  if (trimmed.length <= 4) return "••••";
  return `••••${trimmed.slice(-4)}`;
}

/**
 * Detect AI Provider from API Key prefix/format, or use explicit manual override.
 * Never guesses unknown formats as Cohere or Gemini; returns "unknown" when not recognized.
 */
export function detectProvider(key: string, explicitProvider?: DetectedProvider): DetectedProvider {
  if (explicitProvider && explicitProvider !== "unknown") {
    return explicitProvider;
  }

  const trimmed = (key || "").trim();
  if (!trimmed) return "unknown";

  // FreeLLMAPI unified keys start with "freellmapi-"
  if (trimmed.startsWith("freellmapi-")) {
    return "freellmapi";
  }

  // Google Gemini keys start with "AQ." (AI Studio) or "AIza" (Google Cloud)
  if (trimmed.startsWith("AQ.") || trimmed.startsWith("AIza")) {
    return "gemini";
  }

  // OpenRouter keys start with "sk-or-"
  if (trimmed.startsWith("sk-or-")) {
    return "openrouter";
  }

  // Groq keys start with "gsk_"
  if (trimmed.startsWith("gsk_")) {
    return "groq";
  }

  // OpenAI keys start with "sk-proj-" or "sk-" (and not OpenRouter "sk-or-")
  if (
    trimmed.startsWith("sk-proj-") ||
    (trimmed.startsWith("sk-") && !trimmed.startsWith("sk-or-"))
  ) {
    return "openai";
  }

  // Cohere keys are strictly 32 or 40-character alphanumeric tokens (never starts with freellmapi-, sk-, gsk_)
  if ((trimmed.length === 32 || trimmed.length === 40) && /^[a-zA-Z0-9]{32,40}$/.test(trimmed)) {
    return "cohere";
  }

  // Unrecognized key format: do NOT guess or default
  return "unknown";
}

/**
 * Redact API keys and tokens from strings, errors, and URLs.
 */
export function redactKeys(text: string, keysToRedact: string[] = []): string {
  if (!text) return "";
  let result = text;

  // Redact known active keys
  for (const k of keysToRedact) {
    if (k && k.trim().length > 4) {
      result = result.split(k.trim()).join("[REDACTED_API_KEY]");
    }
  }

  // Regex pattern redactions for safety
  result = result.replace(/AIza[0-9A-Za-z-_]{30,}/g, "[REDACTED_GEMINI_KEY]");
  result = result.replace(/AQ\.[0-9A-Za-z-_]{20,}/g, "[REDACTED_GEMINI_KEY]");
  result = result.replace(/gsk_[a-zA-Z0-9]{20,}/g, "[REDACTED_GROQ_KEY]");
  result = result.replace(/sk-or-[a-zA-Z0-9-_]{20,}/g, "[REDACTED_OPENROUTER_KEY]");
  result = result.replace(/sk-(?:proj-)?[a-zA-Z0-9-_]{20,}/g, "[REDACTED_OPENAI_KEY]");
  result = result.replace(/freellmapi-[a-zA-Z0-9-_]{10,}/g, "[REDACTED_FREELLMAPI_KEY]");

  // URL query parameter redaction
  result = result.replace(/([?&]key=)[^& \n\r"']+/gi, "$1[REDACTED]");
  result = result.replace(/(Bearer\s+)[a-zA-Z0-9._-]+/gi, "$1[REDACTED]");

  return result;
}
