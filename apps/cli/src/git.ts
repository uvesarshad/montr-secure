/**
 * Local git introspection for `montr scan` (A15). Every helper is best-effort
 * and NEVER throws — a repo with no git history, a detached HEAD, or `git`
 * missing from PATH degrades to sane fallbacks rather than crashing the CLI.
 */
import { execFileSync } from "node:child_process";
import { basename, resolve } from "node:path";

function git(cwd: string, args: string[]): string | undefined {
  try {
    const out = execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out.length > 0 ? out : undefined;
  } catch {
    return undefined;
  }
}

/** Current branch name, or undefined (detached HEAD / not a git repo). */
export function detectBranch(cwd: string): string | undefined {
  const branch = git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
  return branch && branch !== "HEAD" ? branch : undefined;
}

/** Best-effort `owner/repo` parsed from the `origin` remote; else the directory name. */
export function detectRepoName(cwd: string): string {
  const url = git(cwd, ["config", "--get", "remote.origin.url"]);
  if (url) {
    // Matches both git@host:owner/repo.git and https://host/owner/repo(.git)
    const m = /[:/]([^/]+\/[^/]+?)(?:\.git)?$/.exec(url);
    if (m?.[1]) return m[1];
  }
  return basename(resolve(cwd));
}

/**
 * Repo-relative paths changed between `base` and HEAD (merge-base diff, the
 * same comparison GitHub shows for a PR). Falls back to a plain two-dot diff
 * if the repo has no common ancestor with `base` (e.g. a shallow CI checkout).
 */
export function detectChangedFiles(cwd: string, base: string): string[] {
  const tripleDot = git(cwd, ["diff", "--name-only", `${base}...HEAD`]);
  const out = tripleDot ?? git(cwd, ["diff", "--name-only", base, "HEAD"]);
  if (!out) return [];
  return out
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}
