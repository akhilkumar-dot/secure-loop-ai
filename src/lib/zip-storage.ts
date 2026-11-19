/**
 * IndexedDB storage for project ZIP files.
 * Allows uploaded ZIP project contents to persist across page reloads and re-scans.
 */

import type { RepoFile } from "./github";

const DB_NAME = "secureloop_zip_store";
const DB_VERSION = 1;
const STORE_NAME = "project_files";

interface StoredZipProject {
  projectId: string;
  archiveName: string;
  files: RepoFile[];
  savedAt: string;
}

// In-memory fallback if IndexedDB is not available (e.g., in SSR/Node testing)
const memoryCache = new Map<string, StoredZipProject>();

function openDb(): Promise<IDBDatabase | null> {
  if (typeof window === "undefined" || !window.indexedDB) {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    try {
      const request = window.indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "projectId" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => {
        console.warn("[zip-storage] IndexedDB open error:", request.error);
        resolve(null);
      };
    } catch {
      resolve(null);
    }
  });
}

/**
 * Stores extracted ZIP files for a given project.
 */
export async function saveProjectZipFiles(
  projectId: string,
  archiveName: string,
  files: RepoFile[],
): Promise<void> {
  const item: StoredZipProject = {
    projectId,
    archiveName,
    files,
    savedAt: new Date().toISOString(),
  };

  memoryCache.set(projectId, item);

  const db = await openDb();
  if (!db) return;

  return new Promise((resolve, reject) => {
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.put(item);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    } catch (e) {
      resolve();
    }
  });
}

/**
 * Retrieves stored ZIP files for a project.
 */
export async function getProjectZipFiles(
  projectId: string,
): Promise<{ files: RepoFile[]; archiveName: string } | null> {
  if (memoryCache.has(projectId)) {
    const mem = memoryCache.get(projectId)!;
    return { files: mem.files, archiveName: mem.archiveName };
  }

  const db = await openDb();
  if (!db) return null;

  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(projectId);
      req.onsuccess = () => {
        const res = req.result as StoredZipProject | undefined;
        if (res) {
          memoryCache.set(projectId, res);
          resolve({ files: res.files, archiveName: res.archiveName });
        } else {
          resolve(null);
        }
      };
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

/**
 * Deletes stored ZIP files when a project is deleted.
 */
export async function deleteProjectZipFiles(projectId: string): Promise<void> {
  memoryCache.delete(projectId);

  const db = await openDb();
  if (!db) return;

  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(projectId);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}
