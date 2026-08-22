import { createClient } from "@supabase/supabase-js";
import assert from "node:assert";

// using the actual project URL and anon key from supabase.ts
const SUPABASE_URL = process.env.SUPABASE_URL || "https://tzdlytanerwfadbqzhue.supabase.co";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR6ZGx5dGFuZXJ3ZmFkYnF6aHVlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODcyODIxNzMsImV4cCI6MjEwMjg1ODE3M30.0zhMPFzcPeL2dfWy90ZaZZ8nti8posjm1HPNbb3gu4c";

// Note: To run this test successfully without RLS errors, you must provide a service_role key 
// in the SUPABASE_SERVICE_ROLE_KEY environment variable.
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

async function runTests() {
  console.log("Setting up test scan run...");
  
  // Create a dummy project and scan run to satisfy foreign key constraints
  const { data: project, error: projErr } = await supabase
    .from("projects")
    .insert({
      name: "Test Project",
      source_type: "git",
      default_branch: "main"
    })
    .select("id")
    .single();
    
  if (projErr) throw new Error("Failed to create project: " + projErr.message);

  const { data: scanRun, error: scanErr } = await supabase
    .from("scan_runs")
    .insert({
      project_id: project.id,
      status: "queued",
      tools: ["sast-rules"],
      started_at: new Date().toISOString(),
      findings_count: 0
    })
    .select("id")
    .single();

  if (scanErr) throw new Error("Failed to create scan run: " + scanErr.message);

  console.log("1. Testing valid insertion ('sast-rules')");
  
  const validFinding = {
    scan_run_id: scanRun.id,
    project_id: project.id,
    tool: "sast-rules", // The value produced by the SAST-saving code
    rule_id: "javascript.express.security.injection.nosql",
    cwe: "CWE-943",
    severity: "high",
    file_path: "app.js",
    line_start: 10,
    line_end: 10,
    vulnerability_class: "other",
    raw_message: "Test finding",
    status: "open",
    code_lines: []
  };

  const { data: inserted, error: validErr } = await supabase
    .from("findings")
    .insert(validFinding)
    .select("id")
    .single();

  assert(!validErr, "Expected valid insertion to succeed, but got error: " + validErr?.message);
  assert(inserted?.id, "Expected valid finding to be inserted and return an ID");
  
  console.log("✓ Valid insertion succeeded");

  console.log("2. Testing invalid insertion ('invalid-tool')");
  
  const invalidFinding = {
    ...validFinding,
    tool: "invalid-tool",
  };

  const { error: invalidErr } = await supabase
    .from("findings")
    .insert(invalidFinding)
    .select("id")
    .single();

  assert(invalidErr, "Expected invalid insertion to fail, but it succeeded");
  assert(invalidErr.message.includes("findings_tool_check") || invalidErr.message.includes("constraint"), 
    "Expected constraint violation error, got: " + invalidErr.message);
  
  console.log("✓ Invalid insertion correctly rejected by CHECK constraint");

  // Cleanup
  console.log("Cleaning up test data...");
  await supabase.from("projects").delete().eq("id", project.id);
  console.log("✓ Tests passed!");
}

runTests().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
