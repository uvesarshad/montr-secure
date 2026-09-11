#!/usr/bin/env node
/**
 * ⛔ THE detection-coverage REAL-MODE scan runner (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md — "Add detection-
 * coverage regression gating in CI, mirroring the existing golden-corpus
 * gate — fail a build when a newly confirmed finding lands on a route with
 * no telemetry"). Mirrors `scripts/corpus-scan.mjs` / `scripts/blue-team-corpus-scan.mjs`'s
 * exact wrapper pattern.
 *
 * Thin wrapper over `scripts/detection-coverage-scan.run.test.ts`: drives the
 * REAL apps/worker pipeline (real L0 map, real L1 semgrep/gitleaks when
 * installed, real L2 correlation, real L3 static confirmation — which, per
 * A7, already persists a real, tri-state `DetectionCoverage` verdict for
 * every confirmed finding via `persistDetectionCoverageForScan`) across every
 * repo in the golden corpus, reads back the REAL persisted rows from the
 * in-memory `StateStore.detectionCoverage` repository, and writes an
 * aggregated results file.
 *
 * Usage:
 *   node scripts/detection-coverage-scan.mjs [--out <path>] [--quiet]
 *
 * `--out <path>` (default: `detection-coverage-scan.json` at the repo root)
 * is where the aggregated
 * `{ results: [{ repo, findingId, category, detected, reasoning }, ...] }`
 * file is written — feed it straight to the detection-coverage gate:
 *
 *   node scripts/detection-coverage-scan.mjs --out detection-coverage-scan.json
 *   pnpm --filter @montr/qa qa:detection-coverage -- --findings detection-coverage-scan.json
 *
 * Exit code is the test runner's: 0 = every corpus repo scanned cleanly,
 * non-zero = a repo crashed the pipeline (a real regression, not a score
 * threshold — score regressions are `qa:detection-coverage`'s job, run
 * separately).
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const CONFIG = "scripts/detection-coverage-scan.vitest.config.ts";
const TEST = "scripts/detection-coverage-scan.run.test.ts";
// Resolve vitest's JS entry and run it with the current Node binary. Spawning the
// `.bin/vitest` shim directly breaks on Windows (the shim has no .exe/.cmd here),
// so go through `process.execPath` + the package's `vitest.mjs` — portable on all OSes.
const vitest = fileURLToPath(new URL("../node_modules/vitest/vitest.mjs", import.meta.url));

const args = process.argv.slice(2);
let outPath = "detection-coverage-scan.json";
let quiet = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (args[i] === "--quiet") quiet = true;
  else {
    console.error(`detection-coverage-scan: unknown option: ${args[i]}`);
    process.exit(2);
  }
}

const result = spawnSync(process.execPath, [vitest, "run", "--config", CONFIG, TEST], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    DETECTION_COVERAGE_SCAN_OUT: outPath,
    ...(quiet ? {} : { DETECTION_COVERAGE_SCAN_PRINT: "1" }),
  },
});

if (result.error) {
  console.error("detection-coverage-scan: failed to launch vitest:", result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
