/**
 * Zero-dependency ZIP file reader and extractor.
 * Works seamlessly in both browser (Web Streams API & DecompressionStream)
 * and Node.js environments.
 */

import type { RepoFile } from "./github";

// Target extensions for source code analysis
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
  ".json",
]);

// Directories and patterns to skip
const SKIP_PATTERNS = [
  /(?:^|[\\/])node_modules[\\/]/i,
  /(?:^|[\\/])\.git[\\/]/i,
  /(?:^|[\\/])__MACOSX[\\/]/i,
  /(?:^|[\\/])\.DS_Store$/i,
  /(?:^|[\\/])dist[\\/]/i,
  /(?:^|[\\/])build[\\/]/i,
  /(?:^|[\\/])coverage[\\/]/i,
  /\.min\.(js|css)$/i,
  /package-lock\.json$/i,
  /yarn\.lock$/i,
  /pnpm-lock\.yaml$/i,
  /bun\.lockb?$/i,
  /(?:^|[\\/])__tests__[\\/]/i,
  /\.(test|spec)\.[a-z0-9]+$/i,
];

export interface ZipExtractResult {
  files: RepoFile[];
  totalEntriesInZip: number;
  archiveName: string;
  skippedFiles: number;
  error?: string | undefined;
}

/**
 * Computes a simple SHA-1 hex string for a file content.
 */
export async function computeSha1(text: string): Promise<string> {
  const enc = new TextEncoder().encode(text);
  if (typeof crypto !== "undefined" && crypto.subtle) {
    try {
      const hashBuf = await crypto.subtle.digest("SHA-1", enc);
      return Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch {
      // Fallback below
    }
  }

  // Node.js fallback or synchronous fallback
  try {
    const nodeCrypto = await import("crypto");
    return nodeCrypto.createHash("sha1").update(text).digest("hex");
  } catch {
    // Pure JS fallback FNV-1a hash formatted like SHA
    let hash = 0x811c9dc5;
    for (let i = 0; i < enc.length; i++) {
      hash ^= enc[i]!;
      hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(40, "0");
  }
}

/**
 * Decompresses raw deflate bytes using browser DecompressionStream or Node zlib.
 */
async function decompressDeflate(compressedBytes: Uint8Array): Promise<string> {
  // 1. Try native DecompressionStream ('deflate-raw')
  if (typeof DecompressionStream !== "undefined") {
    try {
      const ds = new DecompressionStream("deflate-raw");
      const writer = ds.writable.getWriter();
      // Ensure we pass a clean copy or slice if needed
      await writer.write(compressedBytes as unknown as BufferSource);
      await writer.close();
      const response = new Response(ds.readable);
      return await response.text();
    } catch {
      // If DecompressionStream fails on deflate-raw, fallback to zlib
    }
  }

  // 2. Try Node.js zlib
  try {
    const zlib = await import("zlib");
    const buf = Buffer.from(
      compressedBytes.buffer,
      compressedBytes.byteOffset,
      compressedBytes.byteLength,
    );
    const uncompressed = zlib.inflateRawSync(buf);
    return uncompressed.toString("utf-8");
  } catch (err: any) {
    throw new Error(`Failed to decompress file: ${err?.message || String(err)}`);
  }
}

/**
 * Checks if a file path is a scannable target and not in skip list.
 */
export function isScannableFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  if (normalized.endsWith("/")) return false; // directory

  for (const pat of SKIP_PATTERNS) {
    if (pat.test(normalized)) return false;
  }

  const dotIdx = normalized.lastIndexOf(".");
  if (dotIdx === -1) return false;
  const ext = normalized.slice(dotIdx).toLowerCase();

  return TARGET_EXTENSIONS.has(ext);
}

/**
 * Extracts scannable source code files from an uploaded ZIP buffer.
 * Strips common root prefix (e.g. `repo-main/` from GitHub ZIP exports) if present.
 */
export async function extractZipFiles(
  buffer: ArrayBuffer | Uint8Array,
  archiveName = "upload.zip",
): Promise<ZipExtractResult> {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const dataView = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const totalLength = bytes.byteLength;

  if (totalLength < 22) {
    return {
      files: [],
      totalEntriesInZip: 0,
      archiveName,
      skippedFiles: 0,
      error: "Invalid ZIP file: file too small.",
    };
  }

  // 1. Locate End of Central Directory (EOCD) signature: 0x06054b50
  // Search backward from end of file (max comment length is 65535 bytes)
  const maxSearch = Math.min(totalLength, 65535 + 22);
  let eocdOffset = -1;

  for (let i = totalLength - 22; i >= totalLength - maxSearch; i--) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    return {
      files: [],
      totalEntriesInZip: 0,
      archiveName,
      skippedFiles: 0,
      error: "Invalid ZIP archive: End of Central Directory record not found.",
    };
  }

  const totalEntries = dataView.getUint16(eocdOffset + 10, true);
  const cdOffset = dataView.getUint32(eocdOffset + 16, true);

  if (cdOffset >= totalLength) {
    return {
      files: [],
      totalEntriesInZip: totalEntries,
      archiveName,
      skippedFiles: 0,
      error: "Corrupted ZIP archive: central directory offset out of bounds.",
    };
  }

  // 2. Iterate Central Directory entries
  let currentOffset = cdOffset;
  const rawFiles: Array<{
    fileName: string;
    compressionMethod: number;
    compressedSize: number;
    uncompressedSize: number;
    localHeaderOffset: number;
  }> = [];

  const decoder = new TextDecoder("utf-8");

  for (let i = 0; i < totalEntries && currentOffset + 46 <= totalLength; i++) {
    const sig = dataView.getUint32(currentOffset, true);
    if (sig !== 0x02014b50) {
      break;
    }

    const compressionMethod = dataView.getUint16(currentOffset + 10, true);
    const compressedSize = dataView.getUint32(currentOffset + 20, true);
    const uncompressedSize = dataView.getUint32(currentOffset + 24, true);
    const fileNameLength = dataView.getUint16(currentOffset + 28, true);
    const extraFieldLength = dataView.getUint16(currentOffset + 30, true);
    const fileCommentLength = dataView.getUint16(currentOffset + 32, true);
    const localHeaderOffset = dataView.getUint32(currentOffset + 42, true);

    const nameStart = currentOffset + 46;
    const nameBytes = bytes.subarray(nameStart, nameStart + fileNameLength);
    const fileName = decoder.decode(nameBytes);

    rawFiles.push({
      fileName,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
    });

    currentOffset += 46 + fileNameLength + extraFieldLength + fileCommentLength;
  }

  // 3. Detect common single top-level root folder (e.g. "repo-main/" from GitHub download)
  const nonDirPaths = rawFiles.map((f) => f.fileName).filter((name) => !name.endsWith("/"));
  let commonPrefix = "";
  if (nonDirPaths.length > 0) {
    const firstSlash = nonDirPaths[0]!.indexOf("/");
    if (firstSlash !== -1) {
      const candidate = nonDirPaths[0]!.slice(0, firstSlash + 1);
      if (nonDirPaths.every((p) => p.startsWith(candidate))) {
        commonPrefix = candidate;
      }
    }
  }

  // 4. Extract target files
  const extractedFiles: RepoFile[] = [];
  let skipped = 0;

  for (const item of rawFiles) {
    let cleanPath = item.fileName.replace(/\\/g, "/");
    if (commonPrefix && cleanPath.startsWith(commonPrefix)) {
      cleanPath = cleanPath.slice(commonPrefix.length);
    }

    if (!cleanPath || cleanPath.endsWith("/") || !isScannableFile(cleanPath)) {
      skipped++;
      continue;
    }

    // Read from local file header
    const lhOffset = item.localHeaderOffset;
    if (lhOffset + 30 > totalLength) {
      skipped++;
      continue;
    }

    const lhSig = dataView.getUint32(lhOffset, true);
    if (lhSig !== 0x04034b50) {
      skipped++;
      continue;
    }

    const lhNameLen = dataView.getUint16(lhOffset + 26, true);
    const lhExtraLen = dataView.getUint16(lhOffset + 28, true);
    const dataStart = lhOffset + 30 + lhNameLen + lhExtraLen;
    const dataEnd = dataStart + item.compressedSize;

    if (dataEnd > totalLength) {
      skipped++;
      continue;
    }

    const fileBytes = bytes.subarray(dataStart, dataEnd);

    try {
      let content = "";
      if (item.compressionMethod === 0) {
        // Stored (uncompressed)
        content = decoder.decode(fileBytes);
      } else if (item.compressionMethod === 8) {
        // Deflate
        content = await decompressDeflate(fileBytes);
      } else {
        // Unsupported compression method
        skipped++;
        continue;
      }

      // Filter out binary contents that might have sneaked through (contains null bytes)
      if (content.includes("\0")) {
        skipped++;
        continue;
      }

      const sha = await computeSha1(content);
      extractedFiles.push({
        path: cleanPath,
        content,
        sha,
      });
    } catch (e) {
      console.warn(`[zip] Skipping file ${cleanPath} due to read error:`, e);
      skipped++;
    }
  }

  // Sort files by path for deterministic scans
  extractedFiles.sort((a, b) => a.path.localeCompare(b.path));

  return {
    files: extractedFiles,
    totalEntriesInZip: rawFiles.length,
    archiveName,
    skippedFiles: skipped,
  };
}
