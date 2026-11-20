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
import * as aiPipeline from "../ai-pipeline";
import {
  buildQuizPrompt,
  normalizeVulnClass,
  AiQuizResponseSchema,
  AiMultiQuizResponseSchema,
  generateAiQuizQuestion,
  generateAiQuizQuestions,
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

  describe("AiMultiQuizResponseSchema", () => {
    it("validates a structured response with 3 progressive questions", () => {
      const validMultiOutput = {
        questions: [
          {
            question: "Question 1: What is the root cause of this vulnerability?",
            options: [
              { text: "Missing validation on input", misconceptionId: null },
              { text: "Using wrong port", misconceptionId: "wrong_port" },
              { text: "Outdated node version", misconceptionId: "node_version" },
              { text: "Missing async keyword", misconceptionId: "syntax_error" },
            ],
            correctIndex: 0,
            explanation: "Input reaches execution sink unvalidated.",
            source: "OWASP",
          },
          {
            question: "Question 2: How can this vulnerability be triggered?",
            options: [
              { text: "Only by root user", misconceptionId: "privilege_assumption" },
              { text: "By crafting a malicious request parameter", misconceptionId: null },
              { text: "Only on Windows servers", misconceptionId: "os_assumption" },
              { text: "During server reboot", misconceptionId: "lifecycle_assumption" },
            ],
            correctIndex: 1,
            explanation: "Untrusted request parameter triggers the vulnerable branch.",
            source: "CWE",
          },
          {
            question: "Question 3: What is the most robust remediation?",
            options: [
              { text: "Add a comment in the file", misconceptionId: "comment_fix" },
              { text: "Restart the application server", misconceptionId: "restart_fix" },
              { text: "Use parameterized queries or canonical escaping", misconceptionId: null },
              { text: "Check string length only", misconceptionId: "shallow_length_check" },
            ],
            correctIndex: 2,
            explanation: "Parameterization neutralizes injection by design.",
            source: "OWASP Cheat Sheet",
          },
        ],
      };

      const result = AiMultiQuizResponseSchema.safeParse(validMultiOutput);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.questions).toHaveLength(3);
        expect(result.data.questions[0]?.correctIndex).toBe(0);
        expect(result.data.questions[1]?.correctIndex).toBe(1);
        expect(result.data.questions[2]?.correctIndex).toBe(2);
      }
    });

    it("rejects when questions array is empty", () => {
      const invalidMultiOutput = {
        questions: [],
      };
      const result = AiMultiQuizResponseSchema.safeParse(invalidMultiOutput);
      expect(result.success).toBe(false);
    });
  });

  describe("generateAiQuizQuestions backup key prioritization", () => {
    const validQuestionsMock = {
      questions: [
        {
          question: "What is the primary root cause of this vulnerability?",
          options: [
            { text: "Option A is the correct answer", misconceptionId: null },
            { text: "Option B is incorrect", misconceptionId: "m1" },
            { text: "Option C is flawed", misconceptionId: "m2" },
            { text: "Option D is wrong", misconceptionId: "m3" },
          ],
          correctIndex: 0,
        },
      ],
    };

    it("prioritizes backupKey when both apiKey and backupKey are provided", async () => {
      const keysTried: string[] = [];
      const mockProvider = {
        generateChatCompletion: vi.fn().mockResolvedValue({
          content: JSON.stringify(validQuestionsMock),
        }),
      };

      const spy = vi.spyOn(aiPipeline, "getProvider").mockImplementation((key: string) => {
        keysTried.push(key);
        return mockProvider as any;
      });

      const result = await generateAiQuizQuestions(
        sampleFindingContext,
        "main_api_key_123",
        "backup_api_key_456",
      );

      expect(keysTried).toEqual(["backup_api_key_456"]);
      expect(result).toHaveLength(1);
      expect(result[0]?.question).toBe("What is the primary root cause of this vulnerability?");
      spy.mockRestore();
    });

    it("uses main apiKey when backupKey is null or empty", async () => {
      const keysTried: string[] = [];
      const mockProvider = {
        generateChatCompletion: vi.fn().mockResolvedValue({
          content: JSON.stringify(validQuestionsMock),
        }),
      };

      const spy = vi.spyOn(aiPipeline, "getProvider").mockImplementation((key: string) => {
        keysTried.push(key);
        return mockProvider as any;
      });

      const result = await generateAiQuizQuestions(
        sampleFindingContext,
        "main_api_key_123",
        null,
      );

      expect(keysTried).toEqual(["main_api_key_123"]);
      expect(result).toHaveLength(1);
      spy.mockRestore();
    });

    it("falls back to main apiKey when backupKey fails", async () => {
      const keysTried: string[] = [];
      const mockProviderSuccess = {
        generateChatCompletion: vi.fn().mockResolvedValue({
          content: JSON.stringify(validQuestionsMock),
        }),
      };
      const mockProviderFail = {
        generateChatCompletion: vi.fn().mockRejectedValue(new Error("Backup key rate limit")),
      };

      const spy = vi.spyOn(aiPipeline, "getProvider").mockImplementation((key: string) => {
        keysTried.push(key);
        if (key === "backup_api_key_456") {
          return mockProviderFail as any;
        }
        return mockProviderSuccess as any;
      });

      const result = await generateAiQuizQuestions(
        sampleFindingContext,
        "main_api_key_123",
        "backup_api_key_456",
      );

      expect(keysTried).toEqual(["backup_api_key_456", "main_api_key_123"]);
      expect(result).toHaveLength(1);
      expect(result[0]?.question).toBe("What is the primary root cause of this vulnerability?");
      spy.mockRestore();
    });
  });
});
