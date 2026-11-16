/**
 * scripts/seed-demo.ts
 *
 * Seed realistic demonstration data into Supabase for Review 3 live demo walkthrough.
 * Run with: npm run seed:demo
 */

import { supabase } from "../src/lib/supabase";
import { seedDemoData } from "../src/lib/demo-seeder";

async function main() {
  console.log("====================================================");
  console.log("       SecureLoop Demo Data Seeder (Review 3)        ");
  console.log("====================================================\n");

  // Find a target user from profiles table
  const { data: profiles, error: pErr } = await supabase
    .from("profiles")
    .select("id, display_name")
    .limit(1);

  let targetUserId = profiles?.[0]?.id;

  if (!targetUserId) {
    console.log("No profile found. Checking auth session or creating demo placeholder...");
    // Attempt to read current user or create one
    const { data: authData } = await supabase.auth.getUser();
    targetUserId = authData.user?.id;
  }

  if (!targetUserId) {
    console.error("No user found in Supabase. Please sign up or log in first in your browser at http://localhost:5173/login");
    console.log("Alternatively, use the 'Load Demo Walkthrough' button directly on the Dashboard!");
    process.exit(1);
  }

  console.log(`Seeding demo walkthrough data for user ID: ${targetUserId}...`);
  const res = await seedDemoData(targetUserId);

  console.log("✓ Demo Project seeded: 'OWASP WebGoat Audit'");
  console.log("✓ Findings, Gemini Explanations & Validated Patches seeded");
  console.log("✓ Recurring Misconception (3-of-4) seeded");
  console.log("✓ Spaced Repetition Due Reviews & Mastery seeded");
  console.log("✓ Security Score seeded\n");
  console.log(`Project ID: ${res.projectId}`);
  console.log(`Sample Finding ID: ${res.findingId}`);
  console.log("\nReady for live walkthrough! See DEMO.md for click path.");
}

main().catch((err) => {
  console.error("Seeding failed:", err);
  process.exit(1);
});

