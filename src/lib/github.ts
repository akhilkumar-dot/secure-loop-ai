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

/**
 * Fetch all scannable files from a GitHub repo.
 * Returns up to 30 files to keep within Gemini token limits.
 */
export async function fetchRepoFiles(
  repoUrl: string,
  token?: string,
): Promise<{ files: RepoFile[]; error?: string; repoName: string }> {
  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return { files: [], error: "Invalid GitHub URL", repoName: "" };
  }

  const { owner, repo } = parsed;
  const repoName = `${owner}/${repo}`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
  };
  if (token) headers["Authorization"] = `token ${token}`;

  try {
    // Get the default branch
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    if (!repoRes.ok) {
      const errData = await repoRes.json().catch(() => ({}));
      return {
        files: [],
        error: repoRes.status === 404
          ? "Repository not found or private (provide a GitHub token for private repos)"
          : `GitHub API error: ${repoRes.status} ${(errData as any).message ?? ""}`,
        repoName,
      };
    }
    const repoData = await repoRes.json();
    const defaultBranch = repoData.default_branch ?? "main";

    // Get the file tree recursively
    const treeRes = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`,
      { headers },
    );
    if (!treeRes.ok) {
      return { files: [], error: `Could not fetch file tree: ${treeRes.status}`, repoName };
    }
    const treeData = await treeRes.json();
    const blobs: Array<{ path: string; url: string; size: number }> = (
      treeData.tree ?? []
    ).filter((item: any) => {
      if (item.type !== "blob") return false;
      if (!item.path) return false;
      if (SKIP_PATTERNS.some((p) => p.test(item.path))) return false;
      const ext = "." + item.path.split(".").pop()?.toLowerCase();
      if (!TARGET_EXTENSIONS.has(ext)) return false;
      if ((item.size ?? 0) > 100_000) return false; // skip files >100kb
      return true;
    });

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

    // Fetch contents in parallel (batched to 5 at a time)
    const results: RepoFile[] = [];
    for (let i = 0; i < topFiles.length; i += 5) {
      const batch = topFiles.slice(i, i + 5);
      const batchResults = await Promise.all(
        batch.map(async (file) => {
          try {
            const res = await fetch(
              `https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`,
              { headers },
            );
            if (!res.ok) return null;
            const data = await res.json();
            if (data.encoding === "base64" && data.content) {
              const content = atob(data.content.replace(/\n/g, ""));
              return { path: file.path, content, sha: data.sha };
            }
            return null;
          } catch {
            return null;
          }
        }),
      );
      results.push(...(batchResults.filter(Boolean) as RepoFile[]));
    }

    return { files: results, repoName };
  } catch (err: any) {
    return {
      files: [],
      error: `Network error: ${err?.message ?? String(err)}`,
      repoName,
    };
  }
}

/**
 * Get just the file content map for patch context.
 */
export function buildFileMap(files: RepoFile[]): Map<string, string> {
  return new Map(files.map((f) => [f.path, f.content]));
}
