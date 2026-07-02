/**
 * File access abstraction for the detectors. Two implementations:
 *   - {@link fsFileProvider}     — walks a checked-out repo on disk (real fs).
 *   - {@link memoryFileProvider} — serves an in-memory {@link RepoFile}[] (tests,
 *     air-gapped callers, or when the orchestrator already has file contents).
 * Detectors depend only on {@link FileProvider}, so every path is fully offline
 * and mockable — no scanner or filesystem is required for unit tests.
 */
import { promises as fsp } from "node:fs";
import nodePath from "node:path";
import type { ScanScope } from "@montr/contracts";

export interface RepoFile {
  /** Repo-relative POSIX path. */
  path: string;
  content: string;
}

export interface FileProvider {
  /** Repo-relative POSIX paths of candidate text files. */
  list(): Promise<string[]>;
  /** File content (utf-8) or null when unreadable/absent. */
  read(path: string): Promise<string | null>;
}

/** Directories never walked (noise, build output, VCS). */
const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  ".turbo",
  ".vercel",
  "dist",
  "build",
  "out",
  "coverage",
]);

/** Extensions worth reading for regex/AST-light detection. */
const TEXT_EXT = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yaml",
  ".yml",
  ".prisma",
  ".env",
  ".toml",
  ".ini",
  ".conf",
]);

const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

/** Skip absurdly large files (minified bundles, vendored blobs). */
const MAX_FILE_BYTES = 512 * 1024;

function extname(p: string): string {
  return nodePath.posix.extname(p).toLowerCase();
}

/** True for a file worth scanning by content-based detectors. */
export function isTextFile(path: string): boolean {
  const base = nodePath.posix.basename(path);
  if (base.startsWith(".env")) return true;
  return TEXT_EXT.has(extname(path));
}

/** True for a JS/TS source module (import-graph + SAST relevant). */
export function isSourceFile(path: string): boolean {
  return SOURCE_EXT.has(extname(path));
}

function toPosix(p: string): string {
  return p.split(nodePath.sep).join("/");
}

/** True if `path` is within `scope` (include/exclude + diff changed-files). */
export function inScope(path: string, scope: ScanScope | undefined): boolean {
  if (!scope) return true;
  const p = path.replace(/^\.\//, "");
  const under = (prefix: string): boolean => {
    const pre = prefix.replace(/^\.\//, "").replace(/\/$/, "");
    return p === pre || p.startsWith(`${pre}/`);
  };
  if (scope.excludePaths.some(under)) return false;
  if (scope.includePaths.length > 0 && !scope.includePaths.some(under)) return false;
  if (scope.mode === "diff" && scope.changedFiles.length > 0) {
    return scope.changedFiles.some((f) => f.replace(/^\.\//, "") === p);
  }
  return true;
}

/** In-memory provider — deterministic, offline, ideal for tests. */
export function memoryFileProvider(files: readonly RepoFile[]): FileProvider {
  const map = new Map<string, string>();
  for (const f of files) map.set(f.path.replace(/^\.\//, ""), f.content);
  return {
    list: () => Promise.resolve([...map.keys()]),
    read: (p) => Promise.resolve(map.get(p.replace(/^\.\//, "")) ?? null),
  };
}

/** A provider that serves nothing (used when neither files nor a repoRoot exist). */
export function emptyFileProvider(): FileProvider {
  return { list: () => Promise.resolve([]), read: () => Promise.resolve(null) };
}

/** Filesystem-backed provider rooted at `repoRoot`. */
export function fsFileProvider(repoRoot: string): FileProvider {
  const root = nodePath.resolve(repoRoot);
  const cache = new Map<string, string | null>();

  async function walk(dir: string, acc: string[]): Promise<void> {
    let entries: import("node:fs").Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const abs = nodePath.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        await walk(abs, acc);
      } else if (entry.isFile()) {
        const rel = toPosix(nodePath.relative(root, abs));
        if (isTextFile(rel)) acc.push(rel);
      }
    }
  }

  return {
    async list(): Promise<string[]> {
      const acc: string[] = [];
      await walk(root, acc);
      acc.sort();
      return acc;
    },
    async read(p: string): Promise<string | null> {
      const rel = p.replace(/^\.\//, "");
      if (cache.has(rel)) return cache.get(rel) ?? null;
      const abs = nodePath.resolve(root, rel);
      // Contain path traversal within the repo root.
      if (!abs.startsWith(root)) {
        cache.set(rel, null);
        return null;
      }
      try {
        const stat = await fsp.stat(abs);
        if (!stat.isFile() || stat.size > MAX_FILE_BYTES) {
          cache.set(rel, null);
          return null;
        }
        const content = await fsp.readFile(abs, "utf8");
        cache.set(rel, content);
        return content;
      } catch {
        cache.set(rel, null);
        return null;
      }
    },
  };
}

/** Read every listed file into memory (used by content-based detectors). */
export async function readAll(
  provider: FileProvider,
  filter: (path: string) => boolean = () => true,
): Promise<RepoFile[]> {
  const paths = (await provider.list()).filter(filter);
  const out: RepoFile[] = [];
  for (const path of paths) {
    const content = await provider.read(path);
    if (content !== null) out.push({ path, content });
  }
  return out;
}
