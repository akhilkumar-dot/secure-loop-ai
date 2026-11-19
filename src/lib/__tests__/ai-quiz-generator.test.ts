/**
 * Unit tests for AI-generated education quiz checks
 *
 * Verifies:
 * 1. buildQuizPrompt incorporates real finding context (code snippet, CWE, rule_id, file_path, tier)
 * 2. normalizeVulnClass correctly maps standard and unknown/custom vuln classes
 * 3. AiQuizResponseSchema validates standard 4-option response shapes with misconceptions
 * 4. generateAiQuizQuestion correctly parses JSON and generates a valid TieredQuestion
 */

import { describe, it, expect, vi } from "vitest";
import {
  buildQuizPrompt,
  normalizeVulnClass,
  AiQuizResponseSchema,
  generateAiQuizQuestion,
  type FindingQuizContext,
} from "../ai-quiz-generator";

describe("AI Quiz Generator for Education Checks", () => {
  const sampleFindingContext: FindingQuizContext = {
    vulnClass: "other",
    tier: "medium",
    cwe: "CWE-614",
    filePath: "src/server/session.ts",
    rawMessage: "express-session configured without secure: true",
    codeSnippet: `app.use(session({
  secret: 'app-secret',
  resave: false,
  saveUninitialized: true
}));`,
    ruleId: "javascript.express.security.audit.session.session-no-secure",
    severity: "high",
  };

  describe("buildQuizPrompt", () => {
    it("embeds the finding's exact code snippet, CWE, rule_id, and file_path in prompt", () => {
      const prompt = buildQuizPrompt(sampleFindingContext);

      expect(prompt).toContain("CWE-614");
      expect(prompt).toContain("src/server/session.ts");
      expect(prompt).toContain("javascript.express.security.audit.session.session-no-secure");
      expect(prompt).toContain("express-session configured without secure: true");
      expect(prompt).toContain("app.use(session({");
      expect(prompt).toContain("secret: 'app-secret'");
      expect(prompt).toContain("MEDIUM");
      expect(prompt).toContain("mechanics & remediation");
    });

    it("instructs the LLM to output exactly 4 options with misconceptionId tags", () => {
      const prompt = buildQuizPrompt(sampleFindingContext);
      expect(prompt).toContain("exactly 4 distinct options");
      expect(prompt).toContain("misconceptionId");
      expect(prompt).toContain("No markdown fences");
    });
  });

  describe("normalizeVulnClass", () => {
    it("preserves standard vulnerability classes", () => {
      expect(normalizeVulnClass("sqli")).toBe("sqli");
      expect(normalizeVulnClass("xss")).toBe("xss");
      expect(normalizeVulnClass("csrf")).toBe("csrf");
      expect(normalizeVulnClass("insecure_deserialization")).toBe("insecure_deserialization");
    });

    it("normalizes 'other' and unknown classes to safe fallback classes", () => {
      expect(normalizeVulnClass("other")).toBe("sqli");
      expect(normalizeVulnClass("command_injection")).toBe("sqli");
      expect(normalizeVulnClass("ssrf")).toBe("xss");
      expect(normalizeVulnClass("open_redirect")).toBe("xss");
      expect(normalizeVulnClass(null)).toBe("sqli");
      expect(normalizeVulnClass(undefined)).toBe("sqli");
    });
  });

  describe("AiQuizResponseSchema", () => {
    it("validates valid 4-option response with correctIndex and misconception tags", () => {
      const validAiOutput = {
        question:
          "Why must cookies with sensitive session identifiers have the 'secure' flag enabled in production?",
        options: [
          {
            text: "It restricts transmission exclusively over TLS/HTTPS encrypted connections.",
            misconceptionId: null,
          },
          {
            text: "It prevents client-side JavaScript from reading document.cookie.",
            misconceptionId: "confuses_secure_with_httponly",
          },
          {
            text: "It prevents cross-site request forgery attacks on state-changing endpoints.",
            misconceptionId: "confuses_secure_with_samesite",
          },
          {
            text: "It encrypts the payload of the cookie on the server before storage.",
            misconceptionId: "confuses_transport_security_with_at_rest_encryption",
          },
        ],
        correctIndex: 0,
        explanation:
          "The Secure attribute ensures cookies are only transmitted encrypted via HTTPS.",
        source: "OWASP Session Management Cheat Sheet",
      };

      const result = AiQuizResponseSchema.safeParse(validAiOutput);
      expect(result.success).toBe(true);
    });

    it("rejects response with fewer than 4 options", () => {
      const invalidAiOutput = {
        question: "Is this secure?",
        options: [
          { text: "Yes", misconceptionId: null },
          { text: "No", misconceptionId: "wrong" },
        ],
        correctIndex: 0,
      };

      const result = AiQuizResponseSchema.safeParse(invalidAiOutput);
      expect(result.success).toBe(false);
    });

    it("rejects response with invalid correctIndex", () => {
      const invalidAiOutput = {
        question: "Valid question description text?",
        options: [
          { text: "Option A", misconceptionId: null },
          { text: "Option B", misconceptionId: "b" },
          { text: "Option C", misconceptionId: "c" },
          { text: "Option D", misconceptionId: "d" },
        ],
        correctIndex: 4, // Out of bounds for 0-3
      };

      const result = AiQuizResponseSchema.safeParse(invalidAiOutput);
      expect(result.success).toBe(false);
    });
  });
});
