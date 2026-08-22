/**
 * GitHub REST API helpers — fetch repo file tree and individual file contents.
 * Works with public repos without auth, and private repos with a PAT.
 */

export interface RepoFile {
  path: string;
  content: string;
  sha: string;
}

// Extensions we care about for security analysis
const TARGET_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".php", ".java", ".go", ".cs",
  ".sql", ".graphql",
  ".html", ".htm", ".ejs", ".hbs",
  ".env.example", ".env.sample",
  ".yml", ".yaml",
]);

// Paths to skip
const SKIP_PATTERNS = [
  /node_modules/,
  /\.git\//,
  /dist\//,
  /build\//,
  /coverage\//,
  /\.min\.(js|css)/,
  /package-lock\.json/,
  /yarn\.lock/,
  /pnpm-lock/,
];

/**
 * Parse a GitHub URL into owner/repo.
 * Handles: https://github.com/owner/repo, github.com/owner/repo, owner/repo
 */
export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const cleaned = url
    .replace(/^https?:\/\//, "")
    .replace(/^github\.com\//, "")
    .replace(/\.git$/, "")
    .replace(/\/$/, "");

  const parts = cleaned.split("/");
  if (parts.length >= 2) {
    return { owner: parts[0]!, repo: parts[1]! };
  }
  return null;
}

import { createServerFn } from "@tanstack/react-start";
import simpleGit from "simple-git";
import * as fs from "fs/promises";
import * as path from "path";

// In-memory cache keyed by "repoUrl:commitSha"
const cloneCache = new Map<string, { files: RepoFile[]; repoName: string; commitSha: string; error: undefined }>();

/**
 * Server function to fetch all scannable files from a GitHub repo via git clone.
 */
export const fetchRepoFiles = createServerFn({ method: "POST" })
  .validator((d: { repoUrl: string; token?: string; runId: string }) => d)
  .handler(async ({ data: { repoUrl, token, runId } }) => {
    const parsed = parseGitHubUrl(repoUrl);
    if (!parsed) {
      return { files: [], error: "Invalid GitHub URL", repoName: "", commitSha: undefined };
    }

    const { owner, repo } = parsed;
    const repoName = `${owner}/${repo}`;
    
    const activeToken = token || process.env["GITHUB_TOKEN"] || process.env["VITE_GITHUB_TOKEN"];

    // Prepare clone URL
    let cloneUrl = repoUrl;
    if (!cloneUrl.startsWith("http")) cloneUrl = `https://${cloneUrl}`;
    
    // Embed token in URL if we have one (works for both public and private repos)
    if (activeToken) {
       cloneUrl = cloneUrl.replace("https://", `https://x-access-token:${activeToken}@`);
    }

    try {
      const git = simpleGit();
      
      // 2. Get remote HEAD SHA before cloning to check cache
      const remoteInfo = await git.listRemote([cloneUrl, 'HEAD']);
      const commitSha = remoteInfo ? remoteInfo.split('\t')[0] : "";
      
      if (!commitSha) {
        return { files: [], error: "Could not determine remote commit SHA", repoName, commitSha: undefined };
      }

      // 3. Check cache by commit SHA
      const cacheKey = `${repoUrl}:${commitSha}`;
      if (cloneCache.has(cacheKey)) {
        return cloneCache.get(cacheKey)!;
      }

      const workDir = `/tmp/scan/${runId}`;
      const parentDir = path.dirname(workDir);
      await fs.mkdir(parentDir, { recursive: true });

      // Diagnostic check & cleanup before clone
      try {
        const stats = await fs.stat(workDir);
        if (stats) {
          const contents = await fs.readdir(workDir);
          console.log(`[intake] Target dir ${workDir} exists prior to clone. Contents:`, contents);
          await fs.rm(workDir, { recursive: true, force: true });
        }
      } catch {
        console.log(`[intake] Target dir ${workDir} does not exist. Ready for git clone.`);
      }

      // Clone with retry pattern
      let cloneAttempt = 0;
      while (cloneAttempt < 2) {
        try {
          cloneAttempt++;
          console.log(`[intake] Executing git clone (attempt ${cloneAttempt})...`);
          await git.clone(cloneUrl, workDir, ['--depth', '1']);
          break;
        } catch (cloneErr: any) {
          console.error(`[intake] Git clone attempt ${cloneAttempt} failed:`, cloneErr.message);
          await fs.rm(workDir, { recursive: true, force: true });
          if (cloneAttempt >= 2) throw cloneErr;
        }
      }

      try {
        // 5. Read all files from disk
        const blobs: Array<{ path: string; size: number; fullPath: string }> = [];
        
        async function walkDir(dir: string) {
          const entries = await fs.readdir(dir, { withFileTypes: true });
          for (const entry of entries) {
             if (SKIP_PATTERNS.some(p => p.test(entry.name))) continue;
             
             const fullPath = path.join(dir, entry.name);
             if (entry.isDirectory()) {
               await walkDir(fullPath);
             } else {
               const ext = "." + entry.name.split(".").pop()?.toLowerCase();
               if (TARGET_EXTENSIONS.has(ext)) {
                 const stat = await fs.stat(fullPath);
                 if (stat.size <= 100_000) { // skip files >100kb
                   const relativePath = path.relative(workDir, fullPath).replace(/\\/g, '/');
                   blobs.push({ path: relativePath, size: stat.size, fullPath });
                 }
               }
             }
          }
        }
        
        await walkDir(workDir);

        // Prioritize smaller, more interesting files (routes, controllers, models)
        const prioritized = blobs.sort((a, b) => {
          const score = (p: string) => {
            if (/route|controller|handler|view|model|schema|query/i.test(p)) return 0;
            if (/service|middleware|auth|api/i.test(p)) return 1;
            if (/util|helper|lib/i.test(p)) return 2;
            return 3;
          };
          return score(a.path) - score(b.path);
        });

        const topFiles = prioritized.slice(0, 25);
        const results: RepoFile[] = [];

        for (const file of topFiles) {
           try {
             const content = await fs.readFile(file.fullPath, "utf-8");
             results.push({ path: file.path, content, sha: commitSha });
           } catch {
             // Skip files that can't be read (e.g. symlinks, binary, etc.)
           }
        }

        const response = { files: results, repoName, commitSha, error: undefined };
        cloneCache.set(cacheKey, response);
        
        return response;
      } finally {
        // Ensure cleanup of workDir after reading files so temp disk usage doesn't grow
        await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
      }
    } catch (err: any) {
      return { files: [], error: `Clone error: ${err.message}`, repoName, commitSha: undefined };
    }
  });

/**
 * Get just the file content map for patch context.
 */
export function buildFileMap(files: RepoFile[]): Map<string, string> {
  return new Map(files.map((f) => [f.path, f.content]));
}

export interface GitHubRepoItem {
  id: number;
  name: string;
  full_name: string;
  html_url: string;
  clone_url: string;
  private: boolean;
  description: string | null;
  language: string | null;
  stargazers_count: number;
  updated_at: string;
}

export async function fetchUserGitHubRepos(token: string): Promise<GitHubRepoItem[]> {
  if (!token?.trim()) return [];
  try {
    const res = await fetch("https://api.github.com/user/repos?sort=updated&per_page=50", {
      headers: {
        Authorization: `Bearer ${token.trim()}`,
        Accept: "application/vnd.github.v3+json",
      },
    });
    if (!res.ok) {
      console.warn("GitHub API error fetching repos:", res.statusText);
      return [];
    }
    return (await res.json()) as GitHubRepoItem[];
  } catch (err) {
    console.error("Failed to fetch user GitHub repos:", err);
    return [];
  }
}
