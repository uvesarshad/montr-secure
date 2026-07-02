import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import fg from "fast-glob";
import { ConfigValidationError } from "@montr/contracts";
import {
  GroundTruthManifestSchema,
  groundTruthManifest as fixturesManifest,
  type GroundTruthFinding,
  type GroundTruthManifest,
} from "@montr/fixtures";

/**
 * Golden-corpus loader (build-plan §4.7). Merges the @montr/fixtures seed repos
 * with the expanded OWASP-Top-10 repos under `corpus/` into one ground-truth
 * manifest for the scorer, resolving each repo to an absolute path and
 * cross-checking the manifest against what is actually on disk (fast-glob).
 */

export interface LoadedRepo {
  name: string;
  kind: "vulnerable" | "clean";
  /** Where the ground-truth labels came from. */
  source: "fixtures" | "corpus";
  /** Absolute path to the repo directory on disk. */
  path: string;
  expectedFindings: GroundTruthFinding[];
}

export interface LoadedCorpus {
  /** Corpus manifest version (`corpus/ground-truth.manifest.json`). */
  version: string;
  /** @montr/fixtures seed-manifest version. */
  fixturesVersion: string;
  repos: LoadedRepo[];
  /** Merged manifest (absolute paths) — hand straight to the scorer. */
  manifest: GroundTruthManifest;
  /** Non-fatal issues (e.g. an on-disk repo not declared in the manifest). */
  warnings: string[];
  /** Absolute monorepo root. */
  root: string;
}

export interface LoadCorpusOptions {
  /** Override the module URL used to locate the repo root (tests). */
  cwdUrl?: string;
  /** Verify every declared repo directory exists on disk (default true). */
  verifyPaths?: boolean;
  /** Include the @montr/fixtures seed repos (default true). */
  includeFixtures?: boolean;
}

/** Walk up from a file path until the pnpm workspace root is found. */
export function findRepoRoot(startPath: string): string {
  let dir = dirname(startPath);
  for (let i = 0; i < 40; i++) {
    if (existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new ConfigValidationError(
    "could not locate the monorepo root (no pnpm-workspace.yaml found above @montr/qa)",
  );
}

async function isDir(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

/** Load, validate, and merge the full golden corpus. */
export async function loadCorpus(opts: LoadCorpusOptions = {}): Promise<LoadedCorpus> {
  const verifyPaths = opts.verifyPaths ?? true;
  const includeFixtures = opts.includeFixtures ?? true;
  const root = findRepoRoot(fileURLToPath(opts.cwdUrl ?? import.meta.url));
  const corpusDir = join(root, "corpus");
  const fixturesDir = join(root, "packages", "fixtures");

  const warnings: string[] = [];
  const repos: LoadedRepo[] = [];
  const seenNames = new Set<string>();

  const addRepo = (repo: LoadedRepo) => {
    if (seenNames.has(repo.name)) {
      throw new ConfigValidationError(`duplicate corpus repo name: "${repo.name}"`);
    }
    seenNames.add(repo.name);
    repos.push(repo);
  };

  // 1. @montr/fixtures seed repos (paths relative to the fixtures package).
  if (includeFixtures) {
    for (const repo of fixturesManifest.repos) {
      addRepo({
        name: repo.name,
        kind: repo.kind,
        source: "fixtures",
        path: resolve(fixturesDir, repo.path),
        expectedFindings: repo.expectedFindings,
      });
    }
  }

  // 2. Expanded corpus repos (corpus/ground-truth.manifest.json).
  const manifestPath = join(corpusDir, "ground-truth.manifest.json");
  let corpusManifest: GroundTruthManifest;
  try {
    const parsed = GroundTruthManifestSchema.safeParse(
      JSON.parse(await readFile(manifestPath, "utf8")),
    );
    if (!parsed.success) {
      throw new ConfigValidationError(
        `corpus manifest failed schema validation: ${parsed.error.issues
          .map((i) => `${i.path.join(".")}: ${i.message}`)
          .join("; ")}`,
      );
    }
    corpusManifest = parsed.data;
  } catch (cause) {
    if (cause instanceof ConfigValidationError) throw cause;
    throw new ConfigValidationError(`could not read/parse corpus manifest: ${manifestPath}`, {
      cause: String(cause),
    });
  }

  for (const repo of corpusManifest.repos) {
    addRepo({
      name: repo.name,
      kind: repo.kind,
      source: "corpus",
      path: resolve(corpusDir, repo.path),
      expectedFindings: repo.expectedFindings,
    });
  }

  // 3. Cross-check the manifest against what is on disk (fast-glob discovery).
  const declaredCorpusDirs = new Set(corpusManifest.repos.map((r) => basename(r.path)));
  const discovered = await fg("*", { cwd: join(corpusDir, "repos"), onlyDirectories: true });
  for (const dir of discovered) {
    if (!declaredCorpusDirs.has(dir)) {
      warnings.push(
        `corpus/repos/${dir} exists on disk but is not declared in ground-truth.manifest.json (it will not be scored)`,
      );
    }
  }

  // 4. Verify declared repos actually exist (fail-safe: a gate over a missing corpus is meaningless).
  if (verifyPaths) {
    for (const repo of repos) {
      if (!(await isDir(repo.path))) {
        throw new ConfigValidationError(
          `corpus repo "${repo.name}" (${repo.source}) not found on disk: ${repo.path}`,
        );
      }
    }
  }

  const manifest: GroundTruthManifest = {
    version: corpusManifest.version,
    repos: repos.map((r) => ({
      name: r.name,
      kind: r.kind,
      path: r.path,
      expectedFindings: r.expectedFindings,
    })),
  };

  return {
    version: corpusManifest.version,
    fixturesVersion: fixturesManifest.version,
    repos,
    manifest,
    warnings,
    root,
  };
}
