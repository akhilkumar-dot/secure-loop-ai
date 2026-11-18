export type DetectedProvider = "gemini" | "openrouter" | "groq" | "openai" | "cohere" | "unknown";

export interface ProviderInfo {
  id: DetectedProvider;
  name: string;
  supportsBrowserCors: boolean;
  freeTierRpm: number;
  note?: string;
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
 * Detect AI Provider from API Key prefix/format.
 */
export function detectProvider(key: string): DetectedProvider {
  const trimmed = (key || "").trim();
  if (!trimmed) return "unknown";

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
  // OpenAI keys start with "sk-proj-" or "sk-"
  if (trimmed.startsWith("sk-proj-") || trimmed.startsWith("sk-")) {
    return "openai";
  }
  // Cohere keys are alphanumeric strings > 20 characters
  if (trimmed.length > 20 && /^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return "cohere";
  }
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

  // URL query parameter redaction
  result = result.replace(/([?&]key=)[^& \n\r"']+/gi, "$1[REDACTED]");
  result = result.replace(/(Bearer\s+)[a-zA-Z0-9._-]+/gi, "$1[REDACTED]");

  return result;
}
