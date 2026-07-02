/**
 * Intake & sandboxed workspace management (build-plan §5.1).
 *
 * A local filesystem path is scanned in place (no clone). A git URL is cloned
 * into an isolated sandbox under the workspace root, checked out at `branch`,
 * and ALWAYS cleaned up afterwards (try/finally in build.ts). The commit SHA is
 * read from git when available, else derived as a deterministic content hash so
 * the persisted map stays addressable (DECIDE-2 stale checks need a stable SHA).
 */
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, stat, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, isAbsolute, resolve as resolvePath } from "node:path";
import type { GitClient, Workspace } from "./types.js";

/** Heuristic: does `repo` look like a remote URL (vs a local path)? */
export function isRemoteRepo(repo: string): boolean {
  return /^(https?|git|ssh):\/\//i.test(repo) || /^git@[^:]+:/.test(repo) || repo.endsWith(".git");
}

/**
 * `simple-git`-backed {@link GitClient}. Imported lazily so a local-path scan
 * (the common case + all offline tests) never loads git machinery.
 */
export function createDefaultGitClient(): GitClient {
  type SimpleGitFn = (baseDir?: string) => {
    clone(url: string, dir: string): Promise<unknown>;
    cwd(dir: string): Promise<unknown>;
    checkout(ref: string): Promise<unknown>;
    revparse(args: string[]): Promise<string>;
    raw(args: string[]): Promise<string>;
  };
  const load = async (): Promise<SimpleGitFn> => {
    const mod = (await import("simple-git")) as unknown as {
      simpleGit?: SimpleGitFn;
      default?: SimpleGitFn;
    };
    const fn = mod.simpleGit ?? mod.default;
    if (!fn) throw new Error("simple-git unavailable");
    return fn;
  };
  return {
    async clone(repoUrl, dir) {
      const git = (await load())();
      await git.clone(repoUrl, dir);
    },
    async checkout(dir, branch) {
      const git = (await load())(dir);
      await git.cwd(dir);
      await git.checkout(branch);
    },
    async revparseHead(dir) {
      try {
        const git = (await load())(dir);
        const sha = (await git.revparse(["HEAD"])).trim();
        return sha.length > 0 ? sha : null;
      } catch {
        return null;
      }
    },
    async changedFiles(dir, branch) {
      try {
        const git = (await load())(dir);
        // Files that differ between the diff base and HEAD.
        const out = await git.raw(["diff", "--name-only", `${branch}...HEAD`]);
        return out
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0);
      } catch {
        return [];
      }
    },
  };
}

export interface ResolveWorkspaceOptions {
  git?: GitClient;
  workspaceRoot?: string;
  /** Explicit SHA (skips git/derivation when present). */
  commitSha?: string;
}

/**
 * Resolve the intake target to an on-disk workspace. Never throws for a missing
 * git client on a local path; only URL checkout needs git.
 */
export async function resolveWorkspace(
  repo: string,
  branch: string,
  opts: ResolveWorkspaceOptions = {},
): Promise<Workspace> {
  if (!isRemoteRepo(repo)) {
    const dir = isAbsolute(repo) ? repo : resolvePath(process.cwd(), repo);
    if (!existsSync(dir)) {
      throw new Error(`appmap intake: local repo path does not exist: ${dir}`);
    }
    const git = opts.git;
    const sha = opts.commitSha ?? (git ? await git.revparseHead(dir) : null);
    return {
      dir,
      commitSha: sha ?? "",
      cloned: false,
      cleanup: async () => {
        /* in-place scan: nothing to clean up */
      },
    };
  }

  // Remote: clone into an isolated sandbox we own and will delete.
  const git = opts.git ?? createDefaultGitClient();
  const root = opts.workspaceRoot ?? tmpdir();
  const base = await mkdtemp(join(root, "montr-appmap-"));
  const dir = join(base, "repo");
  await git.clone(repo, dir);
  await git.checkout(dir, branch);
  const sha = opts.commitSha ?? (await git.revparseHead(dir));
  return {
    dir,
    commitSha: sha ?? "",
    cloned: true,
    cleanup: async () => {
      await rm(base, { recursive: true, force: true }).catch(() => undefined);
    },
  };
}

/**
 * Deterministic content-addressed pseudo-SHA (40 hex chars) for workspaces that
 * are not git repos. Stable for identical content, so DECIDE-2 stale detection
 * still distinguishes revisions. Falls back to a random SHA if a file vanishes.
 */
export async function deriveContentSha(dir: string, files: string[]): Promise<string> {
  const hash = createHash("sha256");
  for (const rel of [...files].sort()) {
    const abs = join(dir, rel);
    try {
      const s = await stat(abs);
      hash.update(rel);
      hash.update(String(s.size));
      hash.update(String(Math.floor(s.mtimeMs)));
    } catch {
      hash.update(rel);
    }
  }
  const hex = hash.digest("hex").slice(0, 40);
  return /^[0-9a-f]{7,64}$/i.test(hex) ? hex : randomUUID().replace(/-/g, "").slice(0, 40);
}

/** Read a repo-relative text file; returns null if missing/unreadable. */
export async function readRepoFile(dir: string, rel: string): Promise<string | null> {
  try {
    return await readFile(join(dir, rel), "utf8");
  } catch {
    return null;
  }
}
