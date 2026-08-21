/**
 * E2 — executable evidence, gating any LLM-originated proposal before it can
 * reach `confirmed`. This is the "autonomy earned by proof, not granted by
 * trust" mechanism (A7/E2): an investigation loop (E1) concluding
 * `confirmed_candidate` is NEVER, by itself, sufficient — `confirm.ts` only
 * promotes the candidate after this module returns REAL evidence:
 *
 *   - a REAL, EXISTING test in the target repo (named by the investigation —
 *     never invented, never generated) that FAILS against the current code,
 *     proving the vulnerable path is exercised and unguarded; or
 *   - a successful live-DAST probe transcript (the existing, unchanged
 *     `live.ts` engine — reused, not duplicated).
 *
 * Deliberately NOT in scope here (see docs/plan/26-08-22-audit-ai-depth.md's
 * E13): a from-scratch ephemeral-container replay that generates and runs a
 * NEW ,synthesized proof-of-fix test. That is materially larger, separately
 * scoped work; this module only ever executes a pre-existing test file the
 * investigation found via its READ-ONLY tools (`investigate-tools.ts`),
 * exactly once, with a bounded timeout, and treats any launch/parse failure
 * as "no evidence" (fail-safe) rather than as a pass or a fail.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface TestRunResult {
  /** True once a real subprocess launched and produced a parseable result. */
  ran: boolean;
  /** Only meaningful when `ran` is true. */
  passed?: boolean;
  /** Human-readable summary for the confirmed-finding proof argument. */
  summary: string;
  /** Set when the subprocess could not be launched or its output could not be parsed. */
  executionError?: string;
}

/** Injectable test-execution seam (mirrors `LiveHttpTransport`/`BrowserDriver`'s convention). */
export interface TestRunner {
  run(repoRoot: string, testFile: string, timeoutMs: number): Promise<TestRunResult>;
}

interface VitestJsonReport {
  success?: boolean;
  numTotalTests?: number;
  testResults?: Array<{
    assertionResults?: Array<{ status?: string; title?: string; failureMessages?: string[] }>;
  }>;
}

function firstFailureSnippet(report: VitestJsonReport): string | undefined {
  for (const file of report.testResults ?? []) {
    for (const a of file.assertionResults ?? []) {
      if (a.status === "failed" && a.failureMessages?.[0]) {
        return a.failureMessages[0].slice(0, 400);
      }
    }
  }
  return undefined;
}

/**
 * Real (default) test runner: executes ONE existing test file, in place, via
 * a real `vitest` subprocess rooted at `repoRoot` — the exact repo checkout
 * the finding came from, never a copy, never a synthesized test (that is
 * E13's job). No shell interpolation (`execFile`, argv array, no `shell:
 * true`); a bounded timeout guarantees this can never hang Layer 3.
 */
export function createDefaultTestRunner(): TestRunner {
  return {
    async run(repoRoot, testFile, timeoutMs) {
      const vitestBin = join(repoRoot, "node_modules", ".bin", "vitest");
      if (!existsSync(vitestBin)) {
        return {
          ran: false,
          summary:
            "vitest binary not found in the target repo's node_modules/.bin; no evidence gathered.",
          executionError: `missing binary: ${vitestBin}`,
        };
      }
      try {
        const { stdout } = await execFileAsync(
          vitestBin,
          ["run", testFile, "--reporter=json", "--no-color"],
          { cwd: repoRoot, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
        );
        const trimmed = stdout.trim();
        if (!trimmed) {
          return {
            ran: false,
            summary: "vitest produced no output.",
            executionError: "empty stdout",
          };
        }
        let report: VitestJsonReport;
        try {
          report = JSON.parse(trimmed) as VitestJsonReport;
        } catch {
          return {
            ran: false,
            summary: "vitest output was not parseable JSON.",
            executionError: "unparseable vitest report",
          };
        }
        if (typeof report.success !== "boolean" || (report.numTotalTests ?? 0) === 0) {
          return {
            ran: false,
            summary: "vitest ran but reported zero collected tests.",
            executionError: "zero tests collected",
          };
        }
        const summary = report.success
          ? `test ${testFile} PASSED against the current code.`
          : `test ${testFile} FAILED against the current code${
              firstFailureSnippet(report) ? `: ${firstFailureSnippet(report)}` : ""
            }`;
        return { ran: true, passed: report.success, summary };
      } catch (err) {
        // execFile throws on non-zero exit OR a timeout — vitest's normal exit
        // code for "tests ran and some failed" is non-zero, so a thrown error
        // here does NOT by itself mean "no evidence"; re-check for a JSON
        // report on the error object (execFile attaches stdout/stderr).
        const asExecErr = err as {
          stdout?: string;
          killed?: boolean;
          signal?: string;
          message?: string;
        };
        if (asExecErr.stdout) {
          try {
            const report = JSON.parse(asExecErr.stdout.trim()) as VitestJsonReport;
            if (typeof report.success === "boolean" && (report.numTotalTests ?? 0) > 0) {
              const summary = report.success
                ? `test ${testFile} PASSED against the current code.`
                : `test ${testFile} FAILED against the current code${
                    firstFailureSnippet(report) ? `: ${firstFailureSnippet(report)}` : ""
                  }`;
              return { ran: true, passed: report.success, summary };
            }
          } catch {
            /* fall through to executionError below */
          }
        }
        const errorMsg = asExecErr.killed
          ? `vitest timed out after ${timeoutMs}ms`
          : (asExecErr.message ?? String(err));
        return {
          ran: false,
          summary: "vitest failed to launch or produce a usable report.",
          executionError: errorMsg,
        };
      }
    },
  };
}

export interface ExecutableEvidence {
  kind: "failing_test" | "live_probe";
  /** Human-readable summary embedded into the eventual `StaticProof.argument`. */
  summary: string;
  testFile?: string;
}

export interface GatherEvidenceOptions {
  repoRoot?: string;
  existingTestFile?: string;
  testRunner?: TestRunner;
  timeoutMs?: number;
}

/**
 * The E2 gate: turn an investigation's claim of "there's an existing test
 * that demonstrates this" into REAL evidence, or nothing. Fail-safe on every
 * axis — no repo root, no named file, a runner that can't launch, or a test
 * that PASSES (meaning it does NOT demonstrate the flaw) all return
 * `undefined`, and `confirm.ts` treats `undefined` exactly like "no evidence"
 * (the candidate stays unconfirmed). This function NEVER throws.
 */
export async function gatherExecutableEvidence(
  opts: GatherEvidenceOptions,
): Promise<ExecutableEvidence | undefined> {
  if (!opts.repoRoot || !opts.existingTestFile) return undefined;
  const runner = opts.testRunner ?? createDefaultTestRunner();
  try {
    const result = await runner.run(opts.repoRoot, opts.existingTestFile, opts.timeoutMs ?? 15_000);
    if (result.ran && result.passed === false) {
      return { kind: "failing_test", summary: result.summary, testFile: opts.existingTestFile };
    }
    return undefined;
  } catch {
    // A test-runner implementation that throws is treated exactly like "no
    // evidence" — this gate can only ever ADD confidence, never subtract it.
    return undefined;
  }
}
