#!/usr/bin/env node
/**
 * ⛔ THE golden-corpus REAL-MODE scan runner (fixes A2 — the CI gate scoring
 * ground truth against itself).
 *
 * Thin wrapper over `scripts/corpus-scan.run.test.ts` (same shape as
 * `scripts/e2e-scan.mjs` over `apps/worker/src/e2e-scan.test.ts`): drives the
 * REAL apps/worker pipeline (real L0 map, real L1 semgrep/gitleaks when
 * installed, real L2 correlation, real L3 static confirmation) with the FAKE
 * in-process LLM gateway across every repo in the golden corpus, and writes
 * an aggregated scan-results file.
 *
 * Usage:
 *   node scripts/corpus-scan.mjs [--out <path>] [--quiet]
 *
 * `--out <path>` (default: `scan.json` at the repo root) is where the
 * aggregated `{ results: [{ repo, confirmed }, ...] }` file is written — feed
 * it straight to the golden-corpus gate:
 *
 *   node scripts/corpus-scan.mjs --out scan.json
 *   pnpm --filter @montr/qa qa:corpus -- --findings scan.json
 *
 * Exit code is the test runner's: 0 = every corpus repo scanned cleanly,
 * non-zero = a repo crashed the pipeline (a real regression, not a score
 * threshold — score regressions are `qa:corpus`'s job, run separately).
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const CONFIG = "scripts/corpus-scan.vitest.config.ts";
const TEST = "scripts/corpus-scan.run.test.ts";
// Resolve vitest's JS entry and run it with the current Node binary. Spawning the
// `.bin/vitest` shim directly breaks on Windows (the shim has no .exe/.cmd here),
// so go through `process.execPath` + the package's `vitest.mjs` — portable on all OSes.
const vitest = fileURLToPath(new URL("../node_modules/vitest/vitest.mjs", import.meta.url));

const args = process.argv.slice(2);
let outPath = "scan.json";
let quiet = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (args[i] === "--quiet") quiet = true;
  else {
    console.error(`corpus-scan: unknown option: ${args[i]}`);
    process.exit(2);
  }
}

const result = spawnSync(process.execPath, [vitest, "run", "--config", CONFIG, TEST], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    CORPUS_SCAN_OUT: outPath,
    ...(quiet ? {} : { CORPUS_SCAN_PRINT: "1" }),
  },
});

if (result.error) {
  console.error("corpus-scan: failed to launch vitest:", result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
