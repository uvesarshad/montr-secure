#!/usr/bin/env node
/**
 * ⛔ THE OWASP Benchmark REAL-MODE scan runner (E14, closes A29).
 *
 * Thin wrapper over `scripts/benchmark-owasp.run.test.ts` (same shape as
 * `scripts/corpus-scan.mjs` over `scripts/corpus-scan.run.test.ts`): drives
 * the REAL apps/worker pipeline (real L0 map, real L1 Semgrep when installed,
 * real L2 correlation, real L3 static confirmation) against the vendored
 * `corpus/owasp-benchmark/` subset, using the FAKE in-process LLM gateway,
 * and writes the resulting confirmed findings to a scan-results file.
 *
 * REQUIRES a real `semgrep` binary on PATH — SAST is a required detector
 * (A4): an unreachable Semgrep fails this run loudly rather than silently
 * scoring an empty "clean" result (see `packages/discovery/src/detectors/sast.ts`).
 *
 * Usage:
 *   node scripts/benchmark-owasp.mjs [--out <path>] [--quiet]
 *
 * `--out <path>` (default: `owasp-benchmark-scan.json` at the repo root):
 *
 *   node scripts/benchmark-owasp.mjs --out owasp-benchmark-scan.json
 *   pnpm --filter @montr/qa qa:owasp-benchmark -- --our-findings owasp-benchmark-scan.json
 *
 * Exit code is the test runner's: 0 = the subset scanned cleanly, non-zero =
 * the pipeline crashed (e.g. Semgrep unavailable) — a real harness failure,
 * never scored as a benchmark run.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const CONFIG = "scripts/benchmark-owasp.vitest.config.ts";
const TEST = "scripts/benchmark-owasp.run.test.ts";
const vitest = fileURLToPath(new URL("../node_modules/.bin/vitest", import.meta.url));

const args = process.argv.slice(2);
let outPath = "owasp-benchmark-scan.json";
let quiet = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (args[i] === "--quiet") quiet = true;
  else {
    console.error(`benchmark-owasp: unknown option: ${args[i]}`);
    process.exit(2);
  }
}

const result = spawnSync(vitest, ["run", "--config", CONFIG, TEST], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    BENCHMARK_SCAN_OUT: outPath,
    ...(quiet ? {} : { BENCHMARK_SCAN_PRINT: "1" }),
  },
});

if (result.error) {
  console.error("benchmark-owasp: failed to launch vitest:", result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
