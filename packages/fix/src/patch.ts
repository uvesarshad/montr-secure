/**
 * Diff-ready patch construction + validation (PRD §7 L4). Patches are real
 * unified diffs (built with the `diff` library) that apply cleanly to the target
 * file; validation ACTUALLY RUNS the generated `.proof-of-fix.test.ts` file
 * through a real `vitest` subprocess against a real temp-directory workspace —
 * once against the pre-patch source (must FAIL — the vulnerability is present)
 * and once against the post-patch source (must PASS — the vulnerability is
 * gone). This is what makes "the proof-of-fix test fails before / passes after"
 * an independently-proven fact rather than a re-statement of the same in-process
 * predicate that produced the patch in the first place.
 */
import { applyPatch, createTwoFilesPatch, parsePatch } from "diff";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface PatchValidation {
  /** The patch applies cleanly to the original source. */
  applies: boolean;
  /** The result of applying the patch (null when it does not apply). */
  appliedSource: string | null;
  /** A REAL `vitest` run of the proof-of-fix test against the ORIGINAL source failed (⇒ the vulnerability is present pre-patch). */
  failsPrePatch: boolean;
  /** A REAL `vitest` run of the proof-of-fix test against the PATCHED source passed (⇒ the vulnerability is gone post-patch). */
  passesPostPatch: boolean;
  /** Number of +/- lines the patch changes. */
  changedLines: number;
  /**
   * Set when a `vitest` subprocess itself could not be launched/completed (binary
   * missing, crash, timeout, unparseable output) — distinct from "the test ran
   * and failed". When set, `failsPrePatch`/`passesPostPatch` are forced `false`
   * so a launch failure can never be silently read as "vulnerability present" or
   * "fix proven" — the caller must treat this validation as inconclusive.
   */
  executionError?: string;
}

export interface ValidatePatchOptions {
  /**
   * Repo-relative path of the file being patched. This is also the path the
   * generated proof test reads via `readFileSync` — real execution requires it
   * to be written at exactly this relative path inside the temp workspace.
   */
  filePath: string;
  /** The exact generated `.proof-of-fix.test.ts` source to execute for real. */
  proofTestCode: string;
  /** Per-`vitest` subprocess timeout, in ms. Default 30_000. */
  timeoutMs?: number;
}

/** Build a unified-diff patch for a single file (git-style a/ b/ headers). */
export function buildUnifiedDiff(filePath: string, original: string, fixed: string): string {
  return createTwoFilesPatch(
    `a/${filePath}`,
    `b/${filePath}`,
    original,
    fixed,
    undefined,
    undefined,
    { context: 3 },
  );
}

/** Count the added/removed lines across every hunk in a unified diff. */
export function countChangedLines(patch: string): number {
  if (patch.length === 0) return 0;
  let n = 0;
  for (const file of parsePatch(patch)) {
    for (const hunk of file.hunks) {
      for (const line of hunk.lines) {
        if (line.startsWith("+") || line.startsWith("-")) n++;
      }
    }
  }
  return n;
}

/** Derive the sibling proof-of-fix test path for a source file (mirrors strategies.ts). */
function proofTestRelPath(filePath: string): string {
  return filePath.replace(/\.(tsx?|jsx?)$/i, "") + ".proof-of-fix.test.ts";
}

/**
 * Walk up from this module's own location to find the monorepo root (the
 * directory containing `pnpm-workspace.yaml`). Works whether this module runs
 * from `src/` (ts-node/vitest) or `dist/` (built) — both sit at the same depth
 * under the repo root.
 */
function findRepoRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error(
        "validatePatch: could not locate the monorepo root (no pnpm-workspace.yaml found above " +
          `${dirname(fileURLToPath(import.meta.url))})`,
      );
    }
    dir = parent;
  }
}

interface ProofRunResult {
  /** true only when vitest actually ran the test and every assertion passed. */
  passed: boolean;
  /** Set on a real launch/execution failure — never inferred from a normal test failure. */
  executionError?: string;
}

interface VitestJsonTestResult {
  message?: unknown;
}

interface VitestJsonReport {
  success?: unknown;
  numTotalTests?: unknown;
  testResults?: unknown;
}

/** The first non-empty per-file failure message in a vitest JSON report, if any. */
function firstFailureMessage(report: VitestJsonReport): string | null {
  const results = Array.isArray(report.testResults) ? report.testResults : [];
  for (const entry of results) {
    if (entry && typeof entry === "object") {
      const message = (entry as VitestJsonTestResult).message;
      if (typeof message === "string" && message.length > 0) return message.slice(0, 2000);
    }
  }
  return null;
}

/**
 * Interpret vitest's `--reporter=json` stdout (a single JSON object, no banner
 * noise). Distinguishes three outcomes:
 *  - `null` — stdout wasn't parseable JSON at all (vitest never produced a report).
 *  - `{ executionError }` — vitest ran but collected ZERO test cases (a
 *    transform/syntax/import error, or the file failed to load) — a launch-time
 *    failure, NOT a normal assertion result, so it must never read as "the test
 *    failed" (⇒ "vulnerability present").
 *  - `{ passed }` — vitest genuinely ran the test(s) and this is the real verdict.
 */
function interpretVitestReport(
  stdout: string,
): { passed: boolean } | { executionError: string } | null {
  const trimmed = stdout.trim();
  if (!trimmed) return null;
  let report: VitestJsonReport;
  try {
    report = JSON.parse(trimmed) as VitestJsonReport;
  } catch {
    return null;
  }
  if (typeof report.success !== "boolean") return null;
  const numTotalTests = typeof report.numTotalTests === "number" ? report.numTotalTests : undefined;
  if (numTotalTests === 0) {
    return {
      executionError: firstFailureMessage(report) ?? "vitest collected zero test cases",
    };
  }
  return { passed: report.success };
}

/**
 * Write `source` + `proofTestCode` into `<workDir>/<filePath>` and
 * `<workDir>/<proof test path>`, then run that ONE test file through a real
 * `vitest` subprocess rooted at `workDir`. `workDir/node_modules` must already
 * be a symlink to the repo's `node_modules` (so `import "vitest"` resolves) —
 * see {@link runProofOfFixTest}.
 */
async function runVitestOnce(
  repoRoot: string,
  workDir: string,
  filePath: string,
  proofTestCode: string,
  source: string,
  timeoutMs: number,
): Promise<ProofRunResult> {
  const testRelPath = proofTestRelPath(filePath);
  const sourceAbs = join(workDir, filePath);
  const testAbs = join(workDir, testRelPath);
  await mkdir(dirname(sourceAbs), { recursive: true });
  await mkdir(dirname(testAbs), { recursive: true });
  await writeFile(sourceAbs, source, "utf8");
  await writeFile(testAbs, proofTestCode, "utf8");

  const vitestBin = join(repoRoot, "node_modules", ".bin", "vitest");

  try {
    const { execa } = await import("execa");
    // The CLI's positional filter must be a RELATIVE path (or substring) — an
    // absolute path is matched literally against the post-glob-discovery file
    // list and never matches, silently yielding "No test files found".
    const res = await execa(vitestBin, ["run", testRelPath, "--reporter=json", "--no-color"], {
      cwd: workDir,
      reject: false,
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.timedOut) {
      return { passed: false, executionError: `vitest timed out after ${timeoutMs}ms` };
    }
    const stdout = typeof res.stdout === "string" ? res.stdout : "";
    const interpreted = interpretVitestReport(stdout);
    if (interpreted === null) {
      const stderr = typeof res.stderr === "string" ? res.stderr.slice(0, 4000) : "";
      return {
        passed: false,
        executionError:
          `vitest exited ${res.exitCode ?? "unknown"} without a parseable JSON report` +
          (stderr ? `: ${stderr}` : ""),
      };
    }
    if ("executionError" in interpreted) {
      return { passed: false, executionError: interpreted.executionError };
    }
    return { passed: interpreted.passed };
  } catch (err) {
    return {
      passed: false,
      executionError:
        `failed to launch vitest (${vitestBin}): ` +
        (err instanceof Error ? err.message : String(err)),
    };
  }
}

/**
 * Real-execution proof: run the proof-of-fix test against `original` (must
 * FAIL) and, if the patch applied, against `appliedSource` (must PASS) — each
 * in its own real temp-directory workspace, in parallel.
 */
async function runProofOfFixTest(
  filePath: string,
  proofTestCode: string,
  original: string,
  appliedSource: string | null,
  timeoutMs: number,
): Promise<{ failsPrePatch: boolean; passesPostPatch: boolean; executionError?: string }> {
  const repoRoot = findRepoRoot();
  const root = await mkdtemp(join(tmpdir(), "montr-fix-validate-"));
  try {
    const preDir = join(root, "pre");
    const postDir = join(root, "post");
    await mkdir(preDir, { recursive: true });
    // Symlink node_modules so `import "vitest"` (and anything else the proof
    // test needs) resolves via normal upward node-module resolution — no repo
    // files are copied or touched, only this disposable temp tree is written.
    await symlink(join(repoRoot, "node_modules"), join(preDir, "node_modules"), "dir");

    const preRun = runVitestOnce(repoRoot, preDir, filePath, proofTestCode, original, timeoutMs);
    let postRun: Promise<ProofRunResult> | null = null;
    if (appliedSource !== null) {
      await mkdir(postDir, { recursive: true });
      await symlink(join(repoRoot, "node_modules"), join(postDir, "node_modules"), "dir");
      postRun = runVitestOnce(repoRoot, postDir, filePath, proofTestCode, appliedSource, timeoutMs);
    }

    const [preResult, postResult] = await Promise.all([preRun, postRun]);
    const errors = [preResult.executionError, postResult?.executionError].filter(
      (e): e is string => typeof e === "string",
    );
    if (errors.length > 0) {
      return { failsPrePatch: false, passesPostPatch: false, executionError: errors.join(" | ") };
    }
    return {
      // The proof test asserts the vulnerability is ABSENT (`not.toMatch(vulnerable)`
      // plus, where defined, `toMatch(safe)`). So "test failed" pre-patch means the
      // vulnerable pattern WAS found ⇒ failsPrePatch = true. "test passed" post-patch
      // means the vulnerable pattern is gone ⇒ passesPostPatch = true.
      failsPrePatch: !preResult.passed,
      passesPostPatch: appliedSource !== null ? (postResult?.passed ?? false) : false,
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

/**
 * Validate a patch by ACTUALLY EXECUTING its generated proof-of-fix test
 * (`options.proofTestCode`) through a real `vitest` subprocess — once against
 * the pre-patch source (must fail) and once against the post-patch source
 * (must pass). A `vitest` launch/execution failure is reported distinctly via
 * `executionError` and never silently treated as "vulnerability still present".
 */
export async function validatePatch(
  original: string,
  patch: string,
  options: ValidatePatchOptions,
): Promise<PatchValidation> {
  const applied = applyPatch(original, patch);
  const applies = applied !== false;
  const appliedSource = applies ? applied : null;
  const changedLines = countChangedLines(patch);

  try {
    const { failsPrePatch, passesPostPatch, executionError } = await runProofOfFixTest(
      options.filePath,
      options.proofTestCode,
      original,
      appliedSource,
      options.timeoutMs ?? 30_000,
    );
    return {
      applies,
      appliedSource,
      failsPrePatch,
      passesPostPatch,
      changedLines,
      ...(executionError ? { executionError } : {}),
    };
  } catch (err) {
    // Anything outside the two subprocess calls themselves (e.g. temp-dir setup
    // failing, repo root not found) is still a launch/environment failure, not a
    // vulnerability verdict.
    return {
      applies,
      appliedSource,
      failsPrePatch: false,
      passesPostPatch: false,
      changedLines,
      executionError: err instanceof Error ? err.message : String(err),
    };
  }
}
