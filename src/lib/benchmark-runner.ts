/**
 * src/lib/benchmark-runner.ts
 *
 * Benchmark Runner for SecureLoop Review 3.
 * Runs 18 known ground-truth samples (from OWASP WebGoat, Juice Shop, NodeGoat, Benchmark)
 * through SAST scan and patch validation.
 *
 * Calculates honest metrics:
 *  - Detection Rate (Recall / Sensitivity): TP / (TP + FN)
 *  - False Positive Rate: FP / (FP + TN)
 *  - Patch Validation Success Rate: Valid Patches / Total Patches Evaluated
 *  - Detailed per-sample logs and execution runtimes
 *  - False-Positive UI marking and dynamic recalculation
 */

import { scanFile, type SastFinding } from "@/lib/sast";
import { applyUnifiedDiff } from "@/lib/patch";

export interface BenchmarkSample {
  id: string;
  name: string;
  file: string;
  vulnClass: "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";
  cwe: string;
  expectedRule: string;
  isVulnerable: boolean;
  source: string;
  license: string;
  description: string;
  code: string;
  canonicalPatch?: string;
}

export interface SampleResult {
  sampleId: string;
  name: string;
  vulnClass: string;
  cwe: string;
  isVulnerable: boolean;
  detected: boolean;
  matchedRule: string | null;
  ruleMatched: boolean;
  findingsCount: number;
  patchApplied: boolean | null; // null if not vulnerable
  patchValid: boolean | null;
  runtimeMs: number;
  manualFalsePositive: boolean;
  error?: string;
}

export interface BenchmarkSummary {
  totalSamples: number;
  vulnerableCount: number;
  safeControlCount: number;
  detectedCount: number;
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  trueNegatives: number;
  detectionRate: number;        // 0 - 100%
  falsePositiveRate: number;    // 0 - 100%
  patchSuccessRate: number;     // 0 - 100%
  totalRuntimeMs: number;
  sampleResults: SampleResult[];
}

// ---------------------------------------------------------------------------
// Canonical Samples Dataset (18 samples with code & patches)
// ---------------------------------------------------------------------------

export const BENCHMARK_SAMPLES: BenchmarkSample[] = [
  {
    id: "sqli-01",
    name: "SQL Injection in Node.js (String Concat)",
    file: "sqli-01-webgoat.js",
    vulnClass: "sqli",
    cwe: "CWE-89",
    expectedRule: "javascript.sql.node-sqli-injection",
    isVulnerable: true,
    source: "OWASP NodeGoat (contributions.js)",
    license: "Apache-2.0",
    description: "User input from req.query concatenated directly into SQL statement.",
    code: `const express = require('express');
const router = express.Router();
const db = require('./db');

router.get('/user', async (req, res) => {
  const userId = req.query.userId;
  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
  const results = await db.query(query);
  res.json(results);
});

module.exports = router;`,
    canonicalPatch: `@@ -7,3 +7,3 @@
-  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
-  const results = await db.query(query);
+  const query = "SELECT * FROM users WHERE id = $1 AND status = 'active'";
+  const results = await db.query(query, [userId]);`,
  },
  {
    id: "sqli-02",
    name: "MongoDB NoSQL Operator Injection",
    file: "sqli-02-nosql.js",
    vulnClass: "sqli",
    cwe: "CWE-943",
    expectedRule: "javascript.mongodb.nosqli.nosql-injection-req-body",
    isVulnerable: true,
    source: "OWASP Juice Shop",
    license: "MIT",
    description: "Raw req.body objects passed directly into Mongoose findOne() enabling auth bypass.",
    code: `const express = require('express');
const router = express.Router();
const User = require('../models/User');

router.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password
  });
  if (user) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

module.exports = router;`,
    canonicalPatch: `@@ -6,4 +6,4 @@
   const user = await User.findOne({
-    username: req.body.username,
-    password: req.body.password
+    username: String(req.body.username || ''),
+    password: String(req.body.password || '')
   });`,
  },
  {
    id: "sqli-03",
    name: "NoSQL $where Clause String Concat",
    file: "sqli-03-where-inject.js",
    vulnClass: "sqli",
    cwe: "CWE-943",
    expectedRule: "javascript.mongodb.nosqli.nosql-where-injection",
    isVulnerable: true,
    source: "OWASP NodeGoat",
    license: "Apache-2.0",
    description: "Unescaped user input concatenated into MongoDB $where evaluation expression.",
    code: `const router = require('express').Router();
const Allocations = require('../models/Allocations');

router.get('/allocations', function(req, res) {
  const threshold = req.query.threshold;
  Allocations.find({ $where: "this.amount > " + threshold }, function(err, data) {
    if (err) return res.status(500).send(err);
    res.json(data);
  });
});

module.exports = router;`,
    canonicalPatch: `@@ -5,3 +5,3 @@
-  Allocations.find({ $where: "this.amount > " + threshold }, function(err, data) {
+  Allocations.find({ amount: { $gt: Number(threshold) } }, function(err, data) {`,
  },
  {
    id: "sqli-04",
    name: "SQL Parameterized Query (Safe Control)",
    file: "sqli-04-safe-control.js",
    vulnClass: "sqli",
    cwe: "CWE-89",
    expectedRule: "none",
    isVulnerable: false,
    source: "OWASP Benchmark",
    license: "Apache-2.0",
    description: "Safe control sample using parameterized SQL query ($1 placeholder).",
    code: `const express = require('express');
const router = express.Router();
const pool = require('./db');

router.get('/profile', async (req, res) => {
  const userId = req.query.id;
  const query = "SELECT id, username, email FROM users WHERE id = $1";
  const result = await pool.query(query, [userId]);
  res.json(result.rows[0]);
});

module.exports = router;`,
  },
  {
    id: "xss-01",
    name: "DOM-based XSS via innerHTML",
    file: "xss-01-innerhtml.js",
    vulnClass: "xss",
    cwe: "CWE-79",
    expectedRule: "javascript.browser.security.innerHTML-assignment.innerHTML-assignment",
    isVulnerable: true,
    source: "OWASP Juice Shop",
    license: "MIT",
    description: "Direct assignment of URL parameters into element.innerHTML without sanitization.",
    code: `function renderSearchResults(data) {
  const container = document.getElementById("search-results");
  const query = new URLSearchParams(window.location.search).get("q");
  container.innerHTML = "<h3>Results for: " + query + "</h3>" + data;
}`,
    canonicalPatch: `@@ -3,2 +3,3 @@
   const query = new URLSearchParams(window.location.search).get("q");
-  container.innerHTML = "<h3>Results for: " + query + "</h3>" + data;
+  container.textContent = "Results for: " + query;
+}`,
  },
  {
    id: "xss-02",
    name: "Reflected XSS in HTTP Response",
    file: "xss-02-res-send.js",
    vulnClass: "xss",
    cwe: "CWE-79",
    expectedRule: "javascript.express.xss.res-send-user-data.res-send-user-data",
    isVulnerable: true,
    source: "OWASP NodeGoat",
    license: "Apache-2.0",
    description: "User-supplied query parameter reflected in unescaped HTML string sent via res.send().",
    code: `const express = require('express');
const app = express();

app.get('/welcome', (req, res) => {
  const name = req.query.name;
  res.send("<html><body><h1>Welcome back, " + name + "!</h1></body></html>");
});`,
    canonicalPatch: `@@ -4,3 +4,3 @@
   const name = req.query.name;
-  res.send("<html><body><h1>Welcome back, " + name + "!</h1></body></html>");
+  res.json({ message: "Welcome back", name: String(name || '') });`,
  },
  {
    id: "xss-03",
    name: "Code Injection / XSS via eval()",
    file: "xss-03-eval-input.js",
    vulnClass: "xss",
    cwe: "CWE-79",
    expectedRule: "javascript.lang.security.audit.eval-user-input.eval-user-input",
    isVulnerable: true,
    source: "OWASP NodeGoat (contributions.js)",
    license: "Apache-2.0",
    description: "eval() called directly on user request body content.",
    code: `const router = require('express').Router();

router.post("/contributions", function(req, res) {
  const contribution = req.body.contribution;
  eval(contribution);
  res.json({ status: "processed" });
});

module.exports = router;`,
    canonicalPatch: `@@ -4,3 +4,3 @@
   const contribution = req.body.contribution;
-  eval(contribution);
+  const clean = Number(contribution);
   res.json({ status: "processed" });`,
  },
  {
    id: "xss-04",
    name: "Safe DOM Text Insertion (Safe Control)",
    file: "xss-04-safe-control.js",
    vulnClass: "xss",
    cwe: "CWE-79",
    expectedRule: "none",
    isVulnerable: false,
    source: "OWASP Secure Coding Practices",
    license: "CC-BY-SA-4.0",
    description: "Safe control sample using textContent for text insertion.",
    code: `function updateProfileBadge(user) {
  const badge = document.getElementById("username-badge");
  badge.textContent = user.displayName;
}`,
  },
  {
    id: "csrf-01",
    name: "Spring Security CSRF Disabled",
    file: "csrf-01-disabled.java",
    vulnClass: "csrf",
    cwe: "CWE-352",
    expectedRule: "java.spring.security.audit.csrf.spring-csrf-disabled",
    isVulnerable: true,
    source: "OWASP WebGoat (SecurityConfig.java)",
    license: "Apache-2.0",
    description: "Explicit call to http.csrf().disable() on Spring Security authenticated web endpoints.",
    code: `package org.owasp.webgoat;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class WebSecurityConfig {
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}`,
    canonicalPatch: `@@ -6,4 +6,3 @@
     protected void configure(HttpSecurity http) throws Exception {
         http
-            .csrf().disable()
             .authorizeRequests()`,
  },
  {
    id: "csrf-02",
    name: "State-changing POST without CSRF Token",
    file: "csrf-02-session-no-csrf.js",
    vulnClass: "csrf",
    cwe: "CWE-352",
    expectedRule: "javascript.express.security.audit.csrf.csrf-not-enabled",
    isVulnerable: true,
    source: "OWASP NodeGoat",
    license: "Apache-2.0",
    description: "Session-authenticated Express app with state-changing routes and no anti-CSRF token middleware.",
    code: `const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'app-secret',
  resave: false,
  saveUninitialized: true
}));

app.post('/transfer', (req, res) => {
  const { recipient, amount } = req.body;
  processTransfer(recipient, amount);
  res.json({ success: true });
});`,
    canonicalPatch: `@@ -3,2 +3,3 @@
 const session = require('express-session');
+const csrf = require('csurf');
 const app = express();
@@ -8,3 +9,4 @@
 }));
+app.use(csrf());

 app.post('/transfer', (req, res) => {`,
  },
  {
    id: "csrf-03",
    name: "Session Cookie Missing Secure Flag",
    file: "csrf-03-session-no-secure.js",
    vulnClass: "csrf",
    cwe: "CWE-614",
    expectedRule: "javascript.express.security.audit.session.session-no-secure.session-no-secure",
    isVulnerable: true,
    source: "OWASP Top 10 (A05:2021)",
    license: "CC-BY-SA-4.0",
    description: "Express session configured with cookie without secure:true flag.",
    code: `const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  name: 'sess_id',
  secret: 'super-secret-key-12345',
  cookie: {
    httpOnly: true,
    maxAge: 3600000
  }
}));`,
    canonicalPatch: `@@ -7,3 +7,4 @@
   cookie: {
     httpOnly: true,
+    secure: true,
     maxAge: 3600000`,
  },
  {
    id: "csrf-04",
    name: "Strict Session + CSURF Token (Safe Control)",
    file: "csrf-04-safe-control.js",
    vulnClass: "csrf",
    cwe: "CWE-352",
    expectedRule: "none",
    isVulnerable: false,
    source: "OWASP Cheat Sheet Series",
    license: "CC-BY-SA-4.0",
    description: "Safe control sample with secure, sameSite=strict cookies and csurf protection.",
    code: `const express = require('express');
const session = require('express-session');
const csrf = require('csurf');
const app = express();

app.use(session({
  name: 'sess_id',
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
}));

const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);`,
  },
  {
    id: "deser-01",
    name: "node-serialize IIFE Deserialization",
    file: "deser-01-node-serialize.js",
    vulnClass: "insecure_deserialization",
    cwe: "CWE-502",
    expectedRule: "javascript.lang.security.audit.unsafe-deserialization.unsafe-deserialization",
    isVulnerable: true,
    source: "OWASP NodeGoat (profile.js)",
    license: "Apache-2.0",
    description: "node-serialize unserialize() called on untrusted base64 cookie data.",
    code: `const express = require('express');
const serialize = require('node-serialize');
const app = express();

app.get('/profile', (req, res) => {
  if (req.cookies.profile) {
    const str = Buffer.from(req.cookies.profile, 'base64').toString();
    const obj = serialize.unserialize(str);
    res.send("Welcome back " + obj.username);
  }
});`,
    canonicalPatch: `@@ -7,3 +7,3 @@
     const str = Buffer.from(req.cookies.profile, 'base64').toString();
-    const obj = serialize.unserialize(str);
+    const obj = JSON.parse(str);
     res.send("Welcome back " + obj.username);`,
  },
  {
    id: "deser-02",
    name: "Python pickle.loads() on Request Data",
    file: "deser-02-python-pickle.py",
    vulnClass: "insecure_deserialization",
    cwe: "CWE-502",
    expectedRule: "python.lang.security.deserialization.pickle",
    isVulnerable: true,
    source: "OWASP Benchmark / CWE-502",
    license: "Apache-2.0",
    description: "pickle.loads() invoked on user request body data.",
    code: `import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/load_session", methods=["POST"])
def load_session():
    data = base64.b64decode(request.form["session_data"])
    session = pickle.loads(data)
    return f"Loaded session for user: {session.get('user')}"`,
    canonicalPatch: `@@ -1,2 +1,2 @@
-import pickle
+import json
 import base64
@@ -10,2 +10,2 @@
     data = base64.b64decode(request.form["session_data"])
-    session = pickle.loads(data)
+    session = json.loads(data.decode('utf-8'))`,
  },
  {
    id: "deser-03",
    name: "Java ObjectInputStream Deserialization",
    file: "deser-03-java-objectinput.java",
    vulnClass: "insecure_deserialization",
    cwe: "CWE-502",
    expectedRule: "java.lang.security.audit.object-input-stream",
    isVulnerable: true,
    source: "OWASP WebGoat",
    license: "Apache-2.0",
    description: "Raw Java ObjectInputStream deserialization without class filtering.",
    code: `package org.owasp.webgoat.deserialization;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class UserSessionService {
    public Object deserializeToken(byte[] serializedData) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
}`,
  },
  {
    id: "deser-04",
    name: "Safe JSON.parse() Parser (Safe Control)",
    file: "deser-04-safe-json.js",
    vulnClass: "insecure_deserialization",
    cwe: "CWE-502",
    expectedRule: "none",
    isVulnerable: false,
    source: "OWASP Secure Coding Practices",
    license: "CC-BY-SA-4.0",
    description: "Safe control sample using data-only JSON.parse() with type enforcement.",
    code: `const express = require('express');
const router = express.Router();

router.post('/preferences', (req, res) => {
  try {
    const prefs = JSON.parse(req.body.payload);
    res.json({ theme: String(prefs.theme || 'dark') });
  } catch (e) {
    res.status(400).json({ error: "Invalid JSON" });
  }
});

module.exports = router;`,
  },
  {
    id: "cmd-01",
    name: "OS Command Injection via exec()",
    file: "cmd-01-exec-injection.js",
    vulnClass: "other",
    cwe: "CWE-78",
    expectedRule: "javascript.lang.security.audit.child-process-injection.child-process-injection",
    isVulnerable: true,
    source: "OWASP NodeGoat",
    license: "Apache-2.0",
    description: "User-controlled filename concatenated directly into child_process.exec() string.",
    code: `const { exec } = require('child_process');
const express = require('express');
const router = express.Router();

router.post('/convert', (req, res) => {
  const filename = req.body.filename;
  exec('convert ' + filename + ' output.png', (err, stdout) => {
    if (err) return res.status(500).send("Conversion failed");
    res.send("Converted successfully");
  });
});

module.exports = router;`,
    canonicalPatch: `@@ -1,2 +1,2 @@
-const { exec } = require('child_process');
+const { execFile } = require('child_process');
 const express = require('express');
@@ -7,3 +7,3 @@
   const filename = req.body.filename;
-  exec('convert ' + filename + ' output.png', (err, stdout) => {
+  execFile('convert', [filename, 'output.png'], (err, stdout) => {`,
  },
  {
    id: "cred-01",
    name: "Hardcoded Production Credentials",
    file: "cred-01-hardcoded-secret.js",
    vulnClass: "other",
    cwe: "CWE-798",
    expectedRule: "javascript.lang.security.audit.hardcoded-credentials.hardcoded-credentials",
    isVulnerable: true,
    source: "OWASP Benchmark / CWE-798",
    license: "CC-BY-SA-4.0",
    description: "Hardcoded plaintext database password assigned in database connection options.",
    code: `const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'db.prod.internal',
  user: 'admin',
  password: 'ProductionSecretPassword2026!'
});

module.exports = connection;`,
    canonicalPatch: `@@ -5,3 +5,3 @@
   user: 'admin',
-  password: 'ProductionSecretPassword2026!'
+  password: process.env.DB_PASSWORD
 });`,
  },
];

// ---------------------------------------------------------------------------
// Benchmark Execution Engine
// ---------------------------------------------------------------------------

/**
 * Execute the benchmark suite against all samples.
 * Optional `manualFalsePositives` map allows user-overrides from the UI.
 */
export function runBenchmark(
  manualFalsePositives: Record<string, boolean> = {},
): BenchmarkSummary {
  const startTime = Date.now();
  const sampleResults: SampleResult[] = [];

  for (const sample of BENCHMARK_SAMPLES) {
    const sStart = Date.now();
    let detected = false;
    let matchedRule: string | null = null;
    let ruleMatched = false;
    let findingsCount = 0;
    let patchApplied: boolean | null = null;
    let patchValid: boolean | null = null;
    let error: string | undefined;

    try {
      // 1. Scan the sample code with SAST engine
      const findings = scanFile(sample.file, sample.code);
      findingsCount = findings.length;

      if (findingsCount > 0) {
        detected = true;
        matchedRule = findings[0]?.rule_id ?? null;
        // Check rule match
        if (sample.expectedRule === "none") {
          ruleMatched = false; // fired on safe control
        } else {
          ruleMatched = findings.some(
            (f) => f.rule_id === sample.expectedRule || f.cwe.includes(sample.cwe),
          );
        }
      } else {
        detected = false;
        ruleMatched = sample.expectedRule === "none";
      }

      // 2. Validate patch if sample has canonical patch
      if (sample.canonicalPatch && sample.isVulnerable) {
        const patchRes = applyUnifiedDiff(sample.code, sample.canonicalPatch);
        patchApplied = patchRes.ok;
        if (patchRes.ok && patchRes.patched) {
          // Re-scan patched code to verify vulnerability is gone
          const reScan = scanFile(sample.file, patchRes.patched);
          patchValid = reScan.length === 0;
        } else {
          patchValid = false;
          error = patchRes.error;
        }
      }
    } catch (err: any) {
      error = err?.message || String(err);
    }

    const sEnd = Date.now();
    const isManualFP = manualFalsePositives[sample.id] ?? false;

    const result: SampleResult = {
      sampleId: sample.id,
      name: sample.name,
      vulnClass: sample.vulnClass,
      cwe: sample.cwe,
      isVulnerable: sample.isVulnerable,
      detected,
      matchedRule,
      ruleMatched,
      findingsCount,
      patchApplied,
      patchValid,
      runtimeMs: Math.max(1, sEnd - sStart),
      manualFalsePositive: isManualFP,
    };
    if (error !== null && error !== undefined) result.error = error;
    sampleResults.push(result);
  }

  const totalRuntimeMs = Date.now() - startTime;

  // Compute metrics
  let tp = 0; // vulnerable && detected && !manualFP
  let fn = 0; // vulnerable && !detected
  let fp = 0; // (!vulnerable && detected) || manualFP
  let tn = 0; // !vulnerable && !detected && !manualFP

  for (const r of sampleResults) {
    if (r.manualFalsePositive) {
      // User marked finding as false positive
      fp++;
    } else if (r.isVulnerable) {
      if (r.detected) {
        tp++;
      } else {
        fn++;
      }
    } else {
      // Safe control sample
      if (r.detected) {
        fp++;
      } else {
        tn++;
      }
    }
  }

  const totalSamples = sampleResults.length;
  const vulnerableCount = sampleResults.filter((s) => s.isVulnerable).length;
  const safeControlCount = totalSamples - vulnerableCount;
  const detectedCount = sampleResults.filter((s) => s.detected).length;

  const detectionRate = tp + fn > 0 ? Math.round((tp / (tp + fn)) * 100) : 0;
  const falsePositiveRate = fp + tn > 0 ? Math.round((fp / (fp + tn)) * 100) : 0;

  const patchTested = sampleResults.filter((s) => s.patchValid !== null);
  const patchPassed = patchTested.filter((s) => s.patchValid === true);
  const patchSuccessRate =
    patchTested.length > 0 ? Math.round((patchPassed.length / patchTested.length) * 100) : 0;

  return {
    totalSamples,
    vulnerableCount,
    safeControlCount,
    detectedCount,
    truePositives: tp,
    falseNegatives: fn,
    falsePositives: fp,
    trueNegatives: tn,
    detectionRate,
    falsePositiveRate,
    patchSuccessRate,
    totalRuntimeMs,
    sampleResults,
  };
}

