#!/usr/bin/env node
/**
 * ⛔ THE blue-team detection-corpus REAL-MODE run script (B12 — mirrors
 * `scripts/corpus-scan.mjs`'s exact pattern for the golden-corpus gate).
 *
 * Thin wrapper over `scripts/blue-team-corpus-scan.run.test.ts` (same shape
 * as `scripts/corpus-scan.mjs` over `scripts/corpus-scan.run.test.ts`):
 * drives the REAL B3 detection-rule generator + REAL B5 purple-team
 * evaluator (packages/confirm/src/purple-loop.ts) against every labelled
 * case in the blue-team ground-truth corpus
 * (packages/qa/src/blue-team-corpus.ts), and writes an aggregated
 * results file.
 *
 * Usage:
 *   node scripts/blue-team-corpus-scan.mjs [--out <path>] [--quiet]
 *
 * `--out <path>` (default: `blue-team-scan.json` at the repo root) is where
 * the aggregated `{ results: [{ templateKey, actualFired, evidence }, ...] }`
 * file is written — feed it straight to the blue-team detection gate:
 *
 *   node scripts/blue-team-corpus-scan.mjs --out blue-team-scan.json
 *   pnpm --filter @montr/qa qa:blue-team-corpus -- --findings blue-team-scan.json
 *
 * Exit code is the test runner's: 0 = every labelled case ran cleanly AND
 * matched its ground-truth label, non-zero = either a crash or a real
 * ground-truth trace mismatch (both are real regressions this driver exists
 * to catch — see the run.test.ts's own final `it()`).
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const CONFIG = "scripts/blue-team-corpus-scan.vitest.config.ts";
const TEST = "scripts/blue-team-corpus-scan.run.test.ts";
// Resolve the workspace-local vitest (POSIX bin; the CI/dev hosts are darwin/linux).
const vitest = fileURLToPath(new URL("../node_modules/.bin/vitest", import.meta.url));

const args = process.argv.slice(2);
let outPath = "blue-team-scan.json";
let quiet = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (args[i] === "--quiet") quiet = true;
  else {
    console.error(`blue-team-corpus-scan: unknown option: ${args[i]}`);
    process.exit(2);
  }
}

const result = spawnSync(vitest, ["run", "--config", CONFIG, TEST], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    BLUE_TEAM_CORPUS_SCAN_OUT: outPath,
    ...(quiet ? {} : { BLUE_TEAM_CORPUS_SCAN_PRINT: "1" }),
  },
});

if (result.error) {
  console.error("blue-team-corpus-scan: failed to launch vitest:", result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
