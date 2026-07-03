/**
 * Proof-of-fix test EXECUTOR (build-plan §5.5).
 *
 * Turns "fails-pre-patch / passes-post-patch" from a modeled regex predicate into
 * an EXECUTION-BACKED claim: it actually RUNS the @montr/fix-synthesized proof
 * test against a scratch copy of the file and reports whether the test passes.
 *
 * The proof test only `readFileSync`s the target and regex-asserts on its text —
 * it never imports or executes the (LLM-proposed) fix code, so running it is safe
 * even for an untrusted `source`. `vitest` is NOT required at runtime: the test's
 * `import … from "vitest"` is rewritten to a tiny built-in shim, so the executor
 * runs in the hardened prod worker with only Node.
 *
 * Injectable-runner pattern (mirrors the Semgrep runner): the default spawns Node
 * in a temp dir with a timeout; tests inject a canned runner.
 */
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

export interface ProofRunInput {
  /** The synthesized vitest proof-test source (imports `describe/it/expect` from "vitest"). */
  testCode: string;
  /** Repo-relative path the test `readFileSync`s (e.g. "app/api/users/route.ts"). */
  targetPath: string;
  /** File contents to test against (the ORIGINAL or the PATCHED source). */
  source: string;
  signal?: AbortSignal;
}

/** Runs a proof-of-fix test; resolves true iff the test PASSES against `source`. */
export interface ProofTestRunner {
  run(input: ProofRunInput): Promise<boolean>;
}

/**
 * A minimal `vitest`-compatible shim covering exactly what the synthesized proof
 * tests use: `describe`/`it` run their body immediately (a thrown assertion
 * propagates → non-zero exit), and `expect(x).toMatch` / `.not.toMatch`. No
 * external dependency, so the executor works in the distroless/slim runtime.
 */
const VITEST_SHIM = `
export function describe(_n, fn){ if (typeof fn === "function") fn(); }
describe.todo = function(){};
describe.skip = function(){};
export function it(_n, fn){ if (typeof fn === "function") fn(); }
it.todo = function(){};
it.skip = function(){};
export const test = it;
function toRe(re){ return re instanceof RegExp ? re : new RegExp(String(re)); }
export function expect(actual){
  const s = String(actual);
  const assert = (re, want) => {
    if (toRe(re).test(s) !== want) throw new Error("proof-of-fix assertion failed");
  };
  return { toMatch: (re) => assert(re, true), not: { toMatch: (re) => assert(re, false) } };
}
`;

export interface NodeProofRunnerOptions {
  /** Per-run wall-clock cap (ms). Default 10s. */
  timeoutMs?: number;
  /** Node executable (defaults to the current process's). */
  nodePath?: string;
}

/** Default runner: writes the file + test + shim to a temp dir and runs Node. */
export function createNodeProofRunner(opts: NodeProofRunnerOptions = {}): ProofTestRunner {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const nodePath = opts.nodePath ?? process.execPath;

  return {
    async run(input: ProofRunInput): Promise<boolean> {
      const dir = await mkdtemp(join(tmpdir(), "montr-proof-"));
      try {
        // Write the target file at its repo-relative path (the test reads it by that path).
        const targetAbs = join(dir, input.targetPath);
        await mkdir(dirname(targetAbs), { recursive: true });
        await writeFile(targetAbs, input.source, "utf8");
        await writeFile(join(dir, "vitest-shim.mjs"), VITEST_SHIM, "utf8");
        // Rewrite the test's vitest import to the local shim (no vitest dependency).
        const test = input.testCode.replace(/from\s+["']vitest["']/g, 'from "./vitest-shim.mjs"');
        await writeFile(join(dir, "proof.test.mjs"), test, "utf8");

        return await new Promise<boolean>((resolve) => {
          const child = spawn(nodePath, ["proof.test.mjs"], {
            cwd: dir,
            stdio: "ignore",
            // Minimal env — no inherited secrets; the test needs no network or config.
            env: { PATH: process.env.PATH ?? "" },
            ...(input.signal ? { signal: input.signal } : {}),
          });
          const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
          child.on("error", () => {
            clearTimeout(timer);
            resolve(false);
          });
          child.on("exit", (code) => {
            clearTimeout(timer);
            resolve(code === 0);
          });
        });
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => undefined);
      }
    },
  };
}
