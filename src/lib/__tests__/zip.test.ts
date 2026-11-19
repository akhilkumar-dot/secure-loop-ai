import { describe, it, expect } from "vitest";
import zlib from "zlib";
import { isScannableFile, computeSha1, extractZipFiles } from "../zip";

// Helper to construct a standard binary ZIP buffer
function makeTestZip(
  files: Array<{ name: string; content: string; deflate?: boolean }>,
): Uint8Array {
  const parts: Buffer[] = [];
  const cdEntries: Buffer[] = [];
  let offset = 0;

  for (const f of files) {
    const rawContent = Buffer.from(f.content, "utf8");
    const isDeflate = f.deflate ?? true;
    const compContent = isDeflate ? zlib.deflateRawSync(rawContent) : rawContent;
    const method = isDeflate ? 8 : 0;
    const nameBuf = Buffer.from(f.name, "utf8");

    // Local file header (30 bytes + name)
    const lh = Buffer.alloc(30 + nameBuf.length);
    lh.writeUInt32LE(0x04034b50, 0); // signature
    lh.writeUInt16LE(20, 4); // version
    lh.writeUInt16LE(0, 6); // flags
    lh.writeUInt16LE(method, 8); // method
    lh.writeUInt32LE(0, 10); // time/date
    lh.writeUInt32LE(0, 14); // crc32
    lh.writeUInt32LE(compContent.length, 18); // compressed size
    lh.writeUInt32LE(rawContent.length, 22); // uncompressed size
    lh.writeUInt16LE(nameBuf.length, 26); // name length
    lh.writeUInt16LE(0, 28); // extra length
    nameBuf.copy(lh, 30);

    const part = Buffer.concat([lh, compContent]);
    parts.push(part);

    // Central directory header (46 bytes + name)
    const cd = Buffer.alloc(46 + nameBuf.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt32LE(0, 12);
    cd.writeUInt32LE(0, 16);
    cd.writeUInt32LE(compContent.length, 20);
    cd.writeUInt32LE(rawContent.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(offset, 42); // local header offset
    nameBuf.copy(cd, 46);

    cdEntries.push(cd);
    offset += part.length;
  }

  const cdTotalSize = cdEntries.reduce((sum, e) => sum + e.length, 0);
  const cdOffset = offset;

  // EOCD (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdTotalSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return new Uint8Array(Buffer.concat([...parts, ...cdEntries, eocd]));
}

describe("Zip Extractor & File Parser", () => {
  it("isScannableFile correctly filters target extensions and skip patterns", () => {
    // Valid target source files
    expect(isScannableFile("src/index.ts")).toBe(true);
    expect(isScannableFile("app/routes.js")).toBe(true);
    expect(isScannableFile("views/user.ejs")).toBe(true);
    expect(isScannableFile("backend/db.py")).toBe(true);
    expect(isScannableFile("Server.java")).toBe(true);

    // Skipped directories and files
    expect(isScannableFile("node_modules/express/index.js")).toBe(false);
    expect(isScannableFile(".git/config")).toBe(false);
    expect(isScannableFile("__MACOSX/._index.js")).toBe(false);
    expect(isScannableFile(".DS_Store")).toBe(false);
    expect(isScannableFile("bundle.min.js")).toBe(false);
    expect(isScannableFile("package-lock.json")).toBe(false);
    expect(isScannableFile("src/__tests__/app.test.ts")).toBe(false);
    expect(isScannableFile("images/logo.png")).toBe(false);
  });

  it("computeSha1 returns accurate SHA-1 hash", async () => {
    const sha = await computeSha1("hello secureloop");
    expect(sha).toBe("d08e6ac03d913cc3cfd5807f0c3b07e81e1ac38c");
  });

  it("extractZipFiles extracts both stored (method 0) and deflated (method 8) files", async () => {
    const zipData = makeTestZip([
      { name: "index.js", content: "console.log('root file');", deflate: false },
      { name: "src/utils.ts", content: "export const safe = true;", deflate: true },
      { name: "node_modules/bad.js", content: "should be skipped", deflate: false },
      { name: "assets/logo.png", content: "binary", deflate: false },
    ]);

    const result = await extractZipFiles(zipData, "test-archive.zip");

    expect(result.error).toBeUndefined();
    expect(result.archiveName).toBe("test-archive.zip");
    expect(result.totalEntriesInZip).toBe(4);
    expect(result.files.length).toBe(2);

    const indexJs = result.files.find((f) => f.path === "index.js");
    expect(indexJs).toBeDefined();
    expect(indexJs?.content).toBe("console.log('root file');");

    const utilsTs = result.files.find((f) => f.path === "src/utils.ts");
    expect(utilsTs).toBeDefined();
    expect(utilsTs?.content).toBe("export const safe = true;");
  });

  it("strips common GitHub export root directory (e.g. repo-main/)", async () => {
    const zipData = makeTestZip([
      { name: "my-repo-main/server.js", content: "const app = express();", deflate: true },
      { name: "my-repo-main/src/auth.ts", content: "export function auth() {}", deflate: true },
    ]);

    const result = await extractZipFiles(zipData, "my-repo.zip");

    expect(result.files.length).toBe(2);
    expect(result.files[0]?.path).toBe("server.js");
    expect(result.files[1]?.path).toBe("src/auth.ts");
  });

  it("handles corrupted or empty buffer gracefully", async () => {
    const emptyResult = await extractZipFiles(new Uint8Array(10), "empty.zip");
    expect(emptyResult.error).toContain("file too small");

    const badSigResult = await extractZipFiles(new Uint8Array(50), "bad.zip");
    expect(badSigResult.error).toContain("End of Central Directory");
  });
});
