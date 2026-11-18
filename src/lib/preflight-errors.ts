/**
 * src/lib/preflight-errors.ts
 *
 * Error classification helpers and checklist message builder for pre-flight
 * fetch failures.
 *
 * "Failed to fetch" is an opaque browser network error that covers at least:
 *   1. ECONNREFUSED  — server not running on that port
 *   2. Mixed Content — HTTPS page → HTTP endpoint (Chrome/Firefox block it)
 *   3. Local Network Access — Chrome 94+ blocks private IPs from public origins
 *   4. CORS preflight rejection — server running but no CORS headers
 *   5. AbortError (timeout)   — handled separately in preflightCheckProvider
 *
 * The browser deliberately hides which case occurred to prevent port-scanning.
 * We can narrow it down from context:
 *   - `window.isSecureContext` + http:// url → almost certainly Mixed Content
 *   - `window.isSecureContext` + private IP → Local Network Access block
 *   - everything else → ECONNREFUSED or CORS
 */

/** Check if running in a secure context (HTTPS or localhost dev) */
export function isSecureContext(): boolean {
  if (typeof window === "undefined") return false;
  return window.isSecureContext;
}

/** Returns true if `origin` is a deployed HTTPS site (not localhost) */
export function isDeployedHttps(): boolean {
  if (typeof window === "undefined") return false;
  const { protocol, hostname } = window.location;
  return protocol === "https:" && hostname !== "localhost" && hostname !== "127.0.0.1";
}

/** Private / loopback IP/hostname patterns */
const PRIVATE_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^::1$/,
];

export function isPrivateHost(urlString: string): boolean {
  try {
    const { hostname } = new URL(urlString);
    return PRIVATE_PATTERNS.some((p) => p.test(hostname));
  } catch {
    return false;
  }
}

/**
 * Classify a "Failed to fetch" error into the most likely root cause
 * given the target URL and app origin.
 */
export type FetchFailureKind =
  "mixed_content" | "local_network_access" | "connection_refused" | "cors" | "timeout" | "unknown";

export function classifyFetchFailure(
  targetUrl: string,
  errorName?: string,
  errorMessage?: string,
): FetchFailureKind {
  if (errorName === "AbortError") return "timeout";

  const appIsDeployed = isDeployedHttps();
  const targetIsHttp = targetUrl.startsWith("http://");
  const targetIsPrivate = isPrivateHost(targetUrl);

  // Chrome/Firefox block http:// from https:// pages
  if (appIsDeployed && targetIsHttp) {
    return "mixed_content";
  }

  // Chrome 94+ blocks public HTTPS origins → private network hosts
  // even when the target is https:// (Local Network Access policy)
  if (appIsDeployed && targetIsPrivate) {
    return "local_network_access";
  }

  const lowerMsg = (errorMessage || "").toLowerCase();
  if (
    lowerMsg.includes("cors") ||
    lowerMsg.includes("cross-origin") ||
    lowerMsg.includes("blocked by cors")
  ) {
    return "cors";
  }

  // Generic "Failed to fetch" (Chrome/Safari) or "NetworkError" (Firefox)
  if (
    lowerMsg.includes("failed to fetch") ||
    lowerMsg.includes("network error") ||
    lowerMsg.includes("networkerror")
  ) {
    return "connection_refused";
  }

  return "unknown";
}

export interface PreflightChecklist {
  kind: FetchFailureKind;
  urlTried: string;
  providerName: string;
  keyHint: string;
  message: string;
  checklist: string[];
  workaround?: string;
}

function safePort(url: string, defaultPort = "3001"): string {
  try {
    return new URL(url).port || defaultPort;
  } catch {
    return defaultPort;
  }
}

function safeHostname(url: string, defaultHost = "localhost"): string {
  try {
    return new URL(url).hostname || defaultHost;
  } catch {
    return defaultHost;
  }
}

/**
 * Build a human-readable checklist message for a failed pre-flight network call.
 * Never includes the API key; shows at most the last 4 characters via keyHint.
 */
export function buildPreflightChecklist(
  targetUrl: string,
  providerName: string,
  keyHint: string,
  kind: FetchFailureKind,
): PreflightChecklist {
  const base = {
    kind,
    urlTried: targetUrl,
    providerName,
    keyHint,
  };
  const port = safePort(targetUrl, "3001");
  const hostname = safeHostname(targetUrl, "localhost");

  if (kind === "mixed_content") {
    return {
      ...base,
      message: `Mixed Content: This app is served over HTTPS but "${targetUrl}" uses plain HTTP. Browsers block this.`,
      checklist: [
        `Your FreeLLMAPI server is running on port ${port} ✓ (pre-flight cannot confirm while app is deployed)`,
        "The URL uses http:// — Chrome/Firefox block HTTP calls from HTTPS pages",
        "To use FreeLLMAPI from the deployed app, your server needs an HTTPS endpoint",
      ],
      workaround:
        "Run the app locally with `npm run dev` (served on http://localhost:5173) instead of the deployed Lovable URL — there is no mixed-content block from localhost. Alternatively, put your FreeLLMAPI server behind a Caddy or nginx reverse proxy that terminates TLS (see docs).",
    };
  }

  if (kind === "local_network_access") {
    return {
      ...base,
      message: `Local Network Access blocked: Chrome 94+ prevents public HTTPS sites from reaching private network hosts (${hostname}).`,
      checklist: [
        "The app is deployed on HTTPS (public origin)",
        `"${targetUrl}" is a private/loopback address`,
        "Chrome's Local Network Access policy blocks this combination",
      ],
      workaround:
        "Run the app locally with `npm run dev` — from localhost there is no Local Network Access restriction. The deployed build cannot reach localhost/LAN servers without a public HTTPS proxy.",
    };
  }

  if (kind === "connection_refused") {
    return {
      ...base,
      message: `Connection refused at "${targetUrl}". The server is likely not running.`,
      checklist: [
        `FreeLLMAPI server is running (try: "npx github:tashfeenahmed/freellmapi" or "node server.js" in its directory)`,
        `Listening on the correct port: ${port}`,
        `Base URL ends with /v1 (you entered: "${targetUrl}")`,
        `No firewall blocking port ${port}`,
      ],
    };
  }

  if (kind === "cors") {
    return {
      ...base,
      message: `CORS error: The server at "${targetUrl}" did not include the required Access-Control-Allow-Origin header.`,
      checklist: [
        "FreeLLMAPI server is running",
        `Server sends "Access-Control-Allow-Origin: *" or the app's exact origin`,
        `Server handles OPTIONS preflight for Authorization header`,
      ],
      workaround:
        "FreeLLMAPI should handle CORS out of the box. If using a custom proxy, add: `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Headers: Authorization, Content-Type`, `Access-Control-Allow-Methods: GET, POST, OPTIONS`",
    };
  }

  return {
    ...base,
    message: `Could not reach "${targetUrl}". The browser did not provide a specific reason (this is normal browser security behaviour).`,
    checklist: [
      `FreeLLMAPI server is running on port ${port}`,
      `Base URL is correct and ends with /v1`,
      `If this app is served over HTTPS: the server also needs HTTPS or you must run the app locally`,
      `No CORS block (server must send Access-Control-Allow-Origin)`,
    ],
  };
}
