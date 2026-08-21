/**
 * Shared, read-only detection helpers used across every category in
 * `./categories/`. Everything here reads `FileProvider` content
 * (`@montr/discovery`'s file-access abstraction — see that package's
 * `util/files.ts`) or an `AppMap` (`@montr/contracts`); nothing here writes,
 * patches, or classifies risk — that is explicitly out of scope for this
 * package (see this package's `index.ts` module doc).
 */
import nodePath from "node:path";
import {
  collectImportedPackages,
  isSourceFile,
  readAll,
  resolveInstalledPackages,
  type FileProvider,
  type RepoFile,
} from "@montr/discovery";

export interface DependencySignal {
  present: boolean;
  packageName?: string;
  via?: "resolved" | "import";
}

/**
 * Whether ANY of `packageNames` is a real dependency of the target repo.
 * Prefers the resolved install set (lockfile-preferred, package.json
 * fallback — `@montr/discovery`'s `resolveInstalledPackages`); when that
 * resolves nothing (no lockfile/package.json parsed), falls back to the
 * import-graph presence scan (`collectImportedPackages`) so a monorepo with
 * a hoisted/unresolvable lockfile still gets a real answer instead of a
 * false "missing" verdict.
 */
export async function detectAnyDependency(
  files: FileProvider,
  packageNames: readonly string[],
): Promise<DependencySignal> {
  const resolved = await resolveInstalledPackages(files);
  for (const name of packageNames) {
    if (resolved.packages.some((p) => p.name === name)) {
      return { present: true, packageName: name, via: "resolved" };
    }
  }
  const imported = await collectImportedPackages(files);
  for (const name of packageNames) {
    if (imported.has(name)) return { present: true, packageName: name, via: "import" };
  }
  return { present: false };
}

/** Repo-relative paths (any depth) whose basename is one of `basenames`, shallowest first. */
export async function findFilesByBasename(
  files: FileProvider,
  basenames: readonly string[],
): Promise<string[]> {
  const set = new Set(basenames);
  const list = await files.list();
  return list
    .filter((p) => set.has(nodePath.posix.basename(p)))
    .sort((a, b) => a.split("/").length - b.split("/").length || a.length - b.length);
}

/** Read every source (JS/TS) file into memory — thin wrapper for the category detectors. */
export async function readAllSource(files: FileProvider): Promise<RepoFile[]> {
  return readAll(files, isSourceFile);
}

/** True if `content` matches `re` (a fresh RegExp is used so a `g`-flagged pattern is safe to reuse). */
export function matches(content: string, re: RegExp): boolean {
  const fresh = new RegExp(re.source, re.flags.replace("g", ""));
  return fresh.test(content);
}

/** 1-based line number of the first match of `re` in `content`, or 0 if absent. */
export function lineOfFirstMatch(content: string, re: RegExp): number {
  const fresh = new RegExp(re.source, re.flags.replace("g", ""));
  const m = fresh.exec(content);
  if (!m) return 0;
  let line = 1;
  for (let i = 0; i < m.index; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}
