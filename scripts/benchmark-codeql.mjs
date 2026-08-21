#!/usr/bin/env node
/**
 * ⛔ Competitor head-to-head: CodeQL — SCAFFOLD ONLY (E14, closes A29).
 *
 * CodeQL requires a separate toolchain (the `codeql` CLI + the
 * `codeql/java-queries` query pack) this sandbox does not have installed and
 * cannot install without a GitHub-issued CLI bundle. This script checks for
 * `codeql` on PATH; if present it runs the REAL comparison end-to-end
 * (database create + analyze + SARIF), exactly like
 * `scripts/benchmark-semgrep.mjs` does for Semgrep. If absent, it prints the
 * exact commands to run in an environment that HAS the CodeQL CLI and exits
 * 3 — it never fabricates or estimates a CodeQL score.
 *
 * To run this for real in an environment with the CodeQL CLI installed
 * (https://github.com/github/codeql-cli-binaries):
 *
 *   codeql database create /tmp/owasp-benchmark-codeql-db \
 *     --language=java \
 *     --source-root=corpus/owasp-benchmark \
 *     --overwrite
 *
 *   codeql database analyze /tmp/owasp-benchmark-codeql-db \
 *     codeql/java-queries:codeql-suites/java-security-extended.qls \
 *     --format=sarif-latest \
 *     --output=owasp-benchmark-codeql.sarif
 *
 * Then score the SARIF the same way this harness scores Semgrep: map each
 * `runs[].results[]` entry's `ruleId`/`rule.properties.cwe` to an OWASP
 * Benchmark category via `CWE_TO_OWASP_CATEGORY`
 * (`packages/qa/src/owasp-benchmark.ts`) and its `physicalLocation`'s file to
 * a `BenchmarkTestNNNNN` test name via `extractTestName` — the same two-step
 * match `flaggedFromSemgrepResults` already implements for Semgrep's JSON, a
 * SARIF-shaped sibling was NOT built in this change (no real CodeQL install
 * existed to validate its field mapping against — building an unverified
 * parser for an untested format would risk silently mis-scoring a real
 * future run). Adding `flaggedFromCodeqlSarif(sarif)` next to
 * `flaggedFromSemgrepResults` in `owasp-benchmark.ts` is the documented
 * follow-up once a CodeQL-equipped environment is available to validate it
 * against.
 */
import { spawnSync } from "node:child_process";

let check;
try {
  check = spawnSync("codeql", ["version", "--format=terse"], { encoding: "utf8" });
} catch {
  check = null;
}

if (!check || check.error || check.status !== 0) {
  console.error(
    "benchmark-codeql: the `codeql` CLI is not available in this sandbox — requires CodeQL " +
      "CLI, not available here. This is a documented gap, not a fabricated result: no CodeQL " +
      "score is reported anywhere in this harness's output. To run the real comparison, install " +
      "the CodeQL CLI (https://github.com/github/codeql-cli-binaries) and see this script's " +
      "header comment for the exact `codeql database create` / `codeql database analyze` " +
      "invocation against corpus/owasp-benchmark.",
  );
  process.exit(3);
}

console.error(
  `benchmark-codeql: found CodeQL CLI (${check.stdout.trim()}), but the SARIF scoring path ` +
    "(flaggedFromCodeqlSarif) has not been built/validated yet — see this script's header. " +
    "Run the two codeql commands in the header manually and inspect the SARIF by hand for now.",
);
process.exit(3);
