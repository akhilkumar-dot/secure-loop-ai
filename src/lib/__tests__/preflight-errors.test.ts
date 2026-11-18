/**
 * src/lib/__tests__/preflight-errors.test.ts
 *
 * Pure-logic tests for the pre-flight error classifier and URL normalizer.
 * Uses real error fixtures: "real error: Failed to fetch"
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { classifyFetchFailure, buildPreflightChecklist, isPrivateHost } from "../preflight-errors";
import { validateEndpointUrl, formatKeyHint } from "../ai-provider-detector";

describe("Pre-Flight Error Classifier", () => {
  const originalWindow = globalThis.window;

  afterEach(() => {
    // Restore global window
    if (originalWindow !== undefined) {
      globalThis.window = originalWindow;
    } else {
      delete (globalThis as any).window;
    }
  });

  describe("classifyFetchFailure", () => {
    // Real error fixture captured from Chrome during scan failure
    const REAL_FAILED_TO_FETCH = "TypeError: Failed to fetch";

    it("identifies AbortError as timeout", () => {
      const kind = classifyFetchFailure(
        "http://localhost:3001/v1",
        "AbortError",
        "The operation was aborted",
      );
      expect(kind).toBe("timeout");
    });

    it("classifies real error 'Failed to fetch' as mixed_content when app is deployed HTTPS and target is HTTP", () => {
      (globalThis as any).window = {
        location: {
          protocol: "https:",
          hostname: "secure-loop-ai.lovable.app",
        },
      };

      const kind = classifyFetchFailure(
        "http://localhost:3001/v1",
        "TypeError",
        REAL_FAILED_TO_FETCH,
      );
      expect(kind).toBe("mixed_content");
    });

    it("classifies real error 'Failed to fetch' as local_network_access when app is deployed HTTPS and target is private HTTPS", () => {
      (globalThis as any).window = {
        location: {
          protocol: "https:",
          hostname: "secure-loop-ai.lovable.app",
        },
      };

      const kind = classifyFetchFailure(
        "https://192.168.1.50:8443/v1",
        "TypeError",
        REAL_FAILED_TO_FETCH,
      );
      expect(kind).toBe("local_network_access");
    });

    it("classifies real error 'Failed to fetch' as connection_refused when running in local dev (localhost)", () => {
      (globalThis as any).window = {
        location: {
          protocol: "http:",
          hostname: "localhost",
        },
      };

      const kind = classifyFetchFailure(
        "http://localhost:3001/v1",
        "TypeError",
        REAL_FAILED_TO_FETCH,
      );
      expect(kind).toBe("connection_refused");
    });

    it("classifies explicit CORS error message", () => {
      delete (globalThis as any).window;
      const kind = classifyFetchFailure(
        "https://api.example.com/v1",
        "TypeError",
        "Blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.",
      );
      expect(kind).toBe("cors");
    });

    it("classifies network error without specific hint as connection_refused", () => {
      delete (globalThis as any).window;
      const kind = classifyFetchFailure(
        "http://localhost:3001/v1",
        "TypeError",
        "NetworkError when attempting to fetch resource.",
      );
      expect(kind).toBe("connection_refused");
    });
  });

  describe("isPrivateHost", () => {
    it("recognizes loopback and local IPs as private", () => {
      expect(isPrivateHost("http://localhost:3001/v1")).toBe(true);
      expect(isPrivateHost("http://127.0.0.1:3001/v1")).toBe(true);
      expect(isPrivateHost("https://10.0.0.1:8080/v1")).toBe(true);
      expect(isPrivateHost("http://192.168.1.1:3001/v1")).toBe(true);
      expect(isPrivateHost("http://172.20.0.5:3001/v1")).toBe(true);
    });

    it("recognizes public domains as non-private", () => {
      expect(isPrivateHost("https://api.openai.com/v1")).toBe(false);
      expect(isPrivateHost("https://openrouter.ai/api/v1")).toBe(false);
      expect(isPrivateHost("https://my-proxy.example.com/v1")).toBe(false);
    });

    it("handles invalid URLs without throwing", () => {
      expect(isPrivateHost("not-a-valid-url")).toBe(false);
    });
  });

  describe("buildPreflightChecklist", () => {
    const keyHint = formatKeyHint("freellmapi-test-key-abcd");

    it("builds mixed_content checklist with port, target URL and local dev workaround", () => {
      const res = buildPreflightChecklist(
        "http://localhost:3001/v1/models",
        "FreeLLMAPI",
        keyHint,
        "mixed_content",
      );

      expect(res.kind).toBe("mixed_content");
      expect(res.message).toContain("Mixed Content");
      expect(res.message).toContain("http://localhost:3001/v1/models");
      expect(res.checklist.length).toBeGreaterThan(0);
      expect(res.workaround).toBeDefined();
      expect(res.workaround).toContain("npm run dev");
      // Key must never appear in message or checklist
      expect(res.message).not.toContain("freellmapi-test-key-abcd");
    });

    it("builds local_network_access checklist with target host and policy guidance", () => {
      const res = buildPreflightChecklist(
        "https://192.168.1.100:8443/v1/models",
        "FreeLLMAPI",
        keyHint,
        "local_network_access",
      );

      expect(res.kind).toBe("local_network_access");
      expect(res.message).toContain("Local Network Access blocked");
      expect(res.checklist.some((c) => c.includes("192.168.1.100"))).toBe(true);
      expect(res.workaround).toContain("npm run dev");
    });

    it("builds connection_refused checklist with server start commands", () => {
      const res = buildPreflightChecklist(
        "http://localhost:3001/v1/models",
        "FreeLLMAPI",
        keyHint,
        "connection_refused",
      );

      expect(res.kind).toBe("connection_refused");
      expect(res.message).toContain("Connection refused");
      expect(res.checklist.some((c) => c.includes("freellmapi"))).toBe(true);
      expect(res.checklist.some((c) => c.includes("3001"))).toBe(true);
    });

    it("handles malformed target URLs gracefully without throwing", () => {
      const res = buildPreflightChecklist(
        "malformed-url",
        "FreeLLMAPI",
        keyHint,
        "connection_refused",
      );

      expect(res.kind).toBe("connection_refused");
      expect(res.message).toContain("Connection refused");
      expect(res.checklist.length).toBeGreaterThan(0);
    });
  });

  describe("URL Normalizer (validateEndpointUrl)", () => {
    it("ensures bare URLs have /v1 appended", () => {
      const res1 = validateEndpointUrl("http://localhost:3001");
      expect(res1.isValid).toBe(true);
      expect(res1.normalizedUrl).toBe("http://localhost:3001/v1");

      const res2 = validateEndpointUrl("http://localhost:3001/");
      expect(res2.isValid).toBe(true);
      expect(res2.normalizedUrl).toBe("http://localhost:3001/v1");
    });

    it("preserves already normalized /v1 URLs", () => {
      const res = validateEndpointUrl("http://localhost:3001/v1");
      expect(res.isValid).toBe(true);
      expect(res.normalizedUrl).toBe("http://localhost:3001/v1");
    });

    it("strips trailing slashes cleanly after /v1", () => {
      const res = validateEndpointUrl("http://localhost:3001/v1///");
      expect(res.isValid).toBe(true);
      expect(res.normalizedUrl).toBe("http://localhost:3001/v1");
    });

    it("appends /v1 to subpaths that lack it", () => {
      const res = validateEndpointUrl("http://localhost:3001/api");
      expect(res.isValid).toBe(true);
      expect(res.normalizedUrl).toBe("http://localhost:3001/api/v1");
    });
  });
});
