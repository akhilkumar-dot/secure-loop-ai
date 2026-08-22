import { fetchRepoFiles } from "./src/lib/github.js";
import crypto from "crypto";

async function run() {
  console.log("Starting test for fetchRepoFiles...");
  
  // Create a random run ID for this test
  const runId = crypto.randomUUID();

  const repoUrl = "https://github.com/OWASP/NodeGoat";
  console.log(`Cloning ${repoUrl} without token...`);

  const t0 = Date.now();
  const res1 = await fetchRepoFiles({
    data: {
      repoUrl,
      runId,
    }
  });

  const t1 = Date.now();
  console.log(`Scan 1 done in ${t1 - t0}ms. Commit SHA: ${res1.commitSha}. Files found: ${res1.files?.length}`);
  if (res1.error) console.error("Error 1:", res1.error);

  console.log(`Running again with same runId to test cache...`);
  const t2 = Date.now();
  const res2 = await fetchRepoFiles({
    data: {
      repoUrl,
      runId,
    }
  });
  const t3 = Date.now();
  
  console.log(`Scan 2 done in ${t3 - t2}ms. Commit SHA: ${res2.commitSha}. Files found: ${res2.files?.length}`);
  if (res2.error) console.error("Error 2:", res2.error);
  
  if ((t3 - t2) < (t1 - t0)) {
     console.log("Cache appears to be working correctly (second run was faster).");
  } else {
     console.log("Cache did not seem to improve speed, check logs.");
  }
}

run().catch(console.error);
