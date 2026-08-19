#!/usr/bin/env node
/**
 * ⛔ THE self-scan / dogfood runner (build-plan §4.8, §14, §19 DoD "scans
 * itself clean" — fixes A7, the CI self-scan job that was a no-op
 * `grep -qw selfscan` check with no `selfscan` script to find).
 *
 * Thin wrapper over `scripts/selfscan.run.test.ts` (same shape as
 * `scripts/corpus-scan.mjs` over `scripts/corpus-scan.run.test.ts`, and
 * `scripts/e2e-scan.mjs` over `apps/worker/src/e2e-scan.test.ts`): drives the
 * REAL apps/worker pipeline (real L0 map, real L1 semgrep/gitleaks when
 * installed, real L2 correlation, real L3 static confirmation) with the FAKE
 * in-process LLM gateway against THIS repo's OWN source tree — Montr Secure
 * dogfooding its own detection tech on itself, not a synthetic ground-truth
 * echo.
 *
 * Usage:
 *   node scripts/selfscan.mjs [--out <path>] [--quiet]
 *
 * `--out <path>` (default: `selfscan.json` at the repo root) is where the
 * aggregated `{ results: [{ repo: "montr-secure", confirmed }] }` file is
 * written.
 *
 * Exit code is the test runner's: 0 = zero un-allowlisted HIGH/CRITICAL
 * confirmed findings against this repo's own source (the CI blocking gate),
 * non-zero = a real finding surfaced (or the pipeline crashed). See
 * `scripts/selfscan.allowlist.json` for the documented-exception mechanism.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const CONFIG = "scripts/selfscan.vitest.config.ts";
const TEST = "scripts/selfscan.run.test.ts";
// Resolve the workspace-local vitest (POSIX bin; the CI/dev hosts are darwin/linux).
const vitest = fileURLToPath(new URL("../node_modules/.bin/vitest", import.meta.url));

const args = process.argv.slice(2);
let outPath = "selfscan.json";
let quiet = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (args[i] === "--quiet") quiet = true;
  else {
    console.error(`selfscan: unknown option: ${args[i]}`);
    process.exit(2);
  }
}

const result = spawnSync(vitest, ["run", "--config", CONFIG, TEST], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    SELFSCAN_OUT: outPath,
    ...(quiet ? {} : { SELFSCAN_PRINT: "1" }),
  },
});

if (result.error) {
  console.error("selfscan: failed to launch vitest:", result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
