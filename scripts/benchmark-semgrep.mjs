#!/usr/bin/env node
/**
 * ⛔ Competitor head-to-head: raw Semgrep run (E14, closes A29).
 *
 * Runs Semgrep DIRECTLY (no correlation/confirmation post-processing — this is
 * genuinely what a user of bare Semgrep would see) against the vendored
 * `corpus/owasp-benchmark/` subset, using the SAME primary OWASP ruleset this
 * product's own SAST detector uses first
 * (`packages/discovery/src/detectors/sast.ts`'s `DEFAULT_SEMGREP_RULESETS[0]`,
 * `p/owasp-top-ten`) — an apples-to-apples ruleset choice, not a strawman.
 * Writes the raw `semgrep --json` output for
 * `qa:owasp-benchmark --semgrep-json <this file>` to score.
 *
 * Usage:
 *   node scripts/benchmark-semgrep.mjs [--out <path>]
 *
 * Requires a real `semgrep` binary on PATH. If unavailable, exits 3 with a
 * clear message rather than fabricating a result — mirrors this product's own
 * SAST detector's fail-loud posture (A4), just at the shell-script level.
 */
import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const SUBSET_DIR = fileURLToPath(new URL("../corpus/owasp-benchmark", import.meta.url));

const args = process.argv.slice(2);
let outPath = "owasp-benchmark-semgrep.json";
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else {
    console.error(`benchmark-semgrep: unknown option: ${args[i]}`);
    process.exit(2);
  }
}

if (!existsSync(SUBSET_DIR)) {
  console.error(`benchmark-semgrep: vendored subset not found: ${SUBSET_DIR}`);
  process.exit(3);
}

const semgrepArgs = [
  "--json",
  "--quiet",
  "--disable-version-check",
  "--metrics=off",
  "--config",
  "p/owasp-top-ten",
  ".",
];

let result;
try {
  result = spawnSync("semgrep", semgrepArgs, {
    cwd: SUBSET_DIR,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 5 * 60_000,
  });
} catch (err) {
  console.error(`benchmark-semgrep: failed to launch semgrep: ${err.message}`);
  process.exit(3);
}

if (result.error || result.status === null) {
  console.error(
    "benchmark-semgrep: semgrep binary is not reachable on PATH — the competitor comparison " +
      "cannot run in this environment. This is scaffolded, not faked: install semgrep " +
      "(`pip install semgrep` or see https://semgrep.dev/docs/getting-started/) and re-run " +
      "`node scripts/benchmark-semgrep.mjs`, then pass its output to " +
      "`pnpm --filter @montr/qa qa:owasp-benchmark -- --our-findings <ours> --semgrep-json <this file>`.",
  );
  process.exit(3);
}

const stdout = result.stdout ?? "";
if (!stdout.trim()) {
  console.error(`benchmark-semgrep: semgrep produced no output (stderr: ${result.stderr ?? ""})`);
  process.exit(3);
}

let json;
try {
  json = JSON.parse(stdout);
} catch (err) {
  console.error(`benchmark-semgrep: semgrep output was not valid JSON: ${err.message}`);
  process.exit(3);
}

const outFile = outPath.startsWith("/")
  ? outPath
  : fileURLToPath(new URL(outPath, `file://${root}/`));
writeFileSync(outFile, `${JSON.stringify(json, null, 2)}\n`, "utf8");
console.log(
  `benchmark-semgrep: wrote ${json.results?.length ?? 0} raw Semgrep result(s) to ${outFile}`,
);
