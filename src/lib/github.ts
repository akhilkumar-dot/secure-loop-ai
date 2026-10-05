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
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".rb",
  ".php",
  ".java",
  ".go",
  ".cs",
  ".sql",
  ".graphql",
  ".html",
  ".htm",
  ".ejs",
  ".hbs",
  ".env.example",
  ".env.sample",
  ".yml",
  ".yaml",
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

// In-memory cache keyed by "owner/repo:commitSha"
const repoCache = new Map<
  string,
  { files: RepoFile[]; repoName: string; commitSha: string; error: undefined }
>();

const GITHUB_API = "https://api.github.com";

function makeHeaders(token?: string | null): HeadersInit {
  const h: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

/**
 * Server function to fetch all scannable files from a GitHub repo via GitHub REST API.
 * Uses the Git Trees API (recursive) + blob contents — no git binary or filesystem needed.
 */
export const fetchRepoFiles = createServerFn({ method: "POST" })
  .validator((d: { repoUrl: string; token?: string; runId: string }) => d)
  .handler(async ({ data: { repoUrl, token } }) => {
    const parsed = parseGitHubUrl(repoUrl);
    if (!parsed) {
      return { files: [], error: "Invalid GitHub URL", repoName: "", commitSha: undefined };
    }

    const { owner, repo } = parsed;
    const repoName = `${owner}/${repo}`;
    const activeToken = token || process.env["GITHUB_TOKEN"] || process.env["VITE_GITHUB_TOKEN"];
    const headers = makeHeaders(activeToken);

    try {
      // 1. Get default branch HEAD commit SHA
      const repoRes = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers });
      if (!repoRes.ok) {
        const msg =
          repoRes.status === 404
            ? "Repository not found (check URL and token for private repos)"
            : `GitHub API error: ${repoRes.status} ${repoRes.statusText}`;
        return { files: [], error: msg, repoName, commitSha: undefined };
      }
      const repoData = (await repoRes.json()) as { default_branch: string };
      const defaultBranch = repoData.default_branch ?? "main";

      // 2. Get the commit SHA for the default branch
      const branchRes = await fetch(
        `${GITHUB_API}/repos/${owner}/${repo}/branches/${defaultBranch}`,
        { headers },
      );
      if (!branchRes.ok) {
        return {
          files: [],
          error: `Could not fetch branch info: ${branchRes.statusText}`,
          repoName,
          commitSha: undefined,
        };
      }
      const branchData = (await branchRes.json()) as { commit: { sha: string } };
      const commitSha: string = branchData.commit.sha;

      // 3. Check cache
      const cacheKey = `${repoName}:${commitSha}`;
      if (repoCache.has(cacheKey)) {
        console.log(`[intake] Cache hit for ${cacheKey}`);
        return repoCache.get(cacheKey)!;
      }

      // 4. Fetch the full file tree (recursive)
      const treeRes = await fetch(
        `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${commitSha}?recursive=1`,
        { headers },
      );
      if (!treeRes.ok) {
        return {
          files: [],
          error: `Could not fetch repo tree: ${treeRes.statusText}`,
          repoName,
          commitSha,
        };
      }
      const treeData = (await treeRes.json()) as {
        tree: Array<{ path: string; type: string; size?: number; sha: string }>;
        truncated: boolean;
      };

      if (treeData.truncated) {
        console.warn(`[intake] Tree for ${repoName} was truncated by GitHub (very large repo).`);
      }

      // 5. Filter to scannable files
      const eligible = treeData.tree.filter((item) => {
        if (item.type !== "blob") return false;
        if (!item.path) return false;
        if (SKIP_PATTERNS.some((p) => p.test(item.path))) return false;
        if (item.size && item.size > 100_000) return false;
        const ext = "." + item.path.split(".").pop()?.toLowerCase();
        return TARGET_EXTENSIONS.has(ext);
      });

      // 6. Prioritize high-value files
      const score = (p: string) => {
        if (/route|controller|handler|view|model|schema|query/i.test(p)) return 0;
        if (/service|middleware|auth|api/i.test(p)) return 1;
        if (/util|helper|lib/i.test(p)) return 2;
        return 3;
      };
      const prioritized = eligible.sort((a, b) => score(a.path) - score(b.path)).slice(0, 25);

      // 7. Fetch file contents in parallel (base64 blobs via contents API)
      const results: RepoFile[] = [];
      await Promise.all(
        prioritized.map(async (item) => {
          try {
            const contentRes = await fetch(
              `${GITHUB_API}/repos/${owner}/${repo}/contents/${item.path}?ref=${commitSha}`,
              { headers },
            );
            if (!contentRes.ok) return;
            const contentData = (await contentRes.json()) as {
              content?: string;
              encoding?: string;
            };
            if (contentData.encoding === "base64" && contentData.content) {
              // Decode base64 content — works in both Node.js and edge runtimes
              const decoded =
                typeof Buffer !== "undefined"
                  ? Buffer.from(contentData.content.replace(/\n/g, ""), "base64").toString("utf-8")
                  : atob(contentData.content.replace(/\n/g, ""));
              results.push({ path: item.path, content: decoded, sha: item.sha });
            }
          } catch (e) {
            console.warn(`[intake] Failed to fetch ${item.path}:`, e);
          }
        }),
      );

      const response = { files: results, repoName, commitSha, error: undefined };
      repoCache.set(cacheKey, response);
      return response;
    } catch (err: any) {
      return {
        files: [],
        error: `GitHub API error: ${err.message}`,
        repoName,
        commitSha: undefined,
      };
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
