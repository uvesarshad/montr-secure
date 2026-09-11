#!/usr/bin/env node
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isMontrError } from "@montr/contracts";
import {
  DEFAULT_DETECTION_COVERAGE_BASELINE,
  evaluateDetectionCoverageBaseline,
  loadDetectionCoverageBaselineFile,
  type DetectionCoverageBaseline,
} from "./detection-coverage-baseline.js";
import { loadDetectionCoverageFindingsFile } from "./detection-coverage-findings-io.js";
import {
  scoreDetectionCoverage,
  type DetectionCoverageEntry,
} from "./detection-coverage-scorer.js";
import {
  formatDetectionCoverageRegression,
  formatDetectionCoverageScore,
  toDetectionCoverageJsonReport,
} from "./detection-coverage-report.js";
import { findRepoRoot } from "./corpus.js";
import { QA_EXIT, exitLabel } from "./exit-codes.js";

/**
 * `qa:detection-coverage` CLI (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md) — the detection-
 * coverage mirror of `qa:corpus`/`qa:blue-team-corpus`. Scores a real
 * detection-coverage run's persisted, tri-state
 * `DetectionCoverage.detected` verdicts (A7) and exits non-zero when the rate
 * of GENUINE gaps (`detected === false` — see `detection-coverage-scorer.ts`'s
 * module header for why `"unknown"` never counts here) regresses against the
 * committed baseline. Metadata-only output (golden rule #1) — mirrors
 * `cli.ts`/`blue-team-cli.ts`'s shape exactly.
 */

const USAGE = `montr-qa-detection-coverage — detection-coverage regression gate

Usage:
  montr-qa-detection-coverage [options]

⛔ Without --findings this is the SYNTHETIC SELF-CHECK (synthetic, always
   fully-covered entries — gapRate is tautologically 0%; it only proves the
   scorer/baseline/exit-code plumbing works). It is NOT the release gate. Run
   it explicitly via \`qa:detection-coverage:selfcheck\` when that is what you
   want. The release gate MUST pass --findings pointing at a REAL run's
   output (see scripts/detection-coverage-scan.mjs), e.g.:
     qa:detection-coverage -- --findings detection-coverage-scan.json

Options:
  --findings <path>   Score a detection-coverage-scan-results JSON file (default: self-check).
  --baseline <path>   Baseline thresholds JSON (default: corpus/detection-coverage-baseline.json, else built-in defaults).
  --json              Emit a machine-readable JSON report instead of text.
  -h, --help          Show this help.

Exit codes: 0 OK · 1 REGRESSION · 2 USAGE · 3 CORPUS_ERROR · 4 RUNTIME_ERROR`;

interface ParsedArgs {
  findings?: string;
  baseline?: string;
  json: boolean;
  help: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = { json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const needValue = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`option ${arg} requires a value`);
      return v;
    };
    // Same pnpm `--` passthrough tolerance as cli.ts/blue-team-cli.ts.
    if (arg === "--") continue;
    switch (arg) {
      case "--findings":
        args.findings = needValue();
        break;
      case "--baseline":
        args.baseline = needValue();
        break;
      case "--json":
        args.json = true;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      default:
        throw new UsageError(`unknown option: ${arg}`);
    }
  }
  return args;
}

async function resolveBaseline(
  explicitPath: string | undefined,
  root: string,
): Promise<DetectionCoverageBaseline> {
  if (explicitPath) return loadDetectionCoverageBaselineFile(explicitPath);
  const defaultPath = join(root, "corpus", "detection-coverage-baseline.json");
  if (existsSync(defaultPath)) return loadDetectionCoverageBaselineFile(defaultPath);
  return DEFAULT_DETECTION_COVERAGE_BASELINE;
}

/**
 * Tautological plumbing self-check: N synthetic, fully-covered entries —
 * never a real measurement. Unlike `qa:corpus`'s `perfectScanner` (echoes the
 * WHOLE golden-corpus manifest) or `qa:blue-team-corpus`'s `selfCheckResults`
 * (echoes the WHOLE `BLUE_TEAM_GROUND_TRUTH` list), this gate has no fixed
 * enumerable ground-truth list to echo — its guard is
 * `minConfirmedFindings`, sized off the REAL corpus's measured finding count
 * (see corpus/detection-coverage-baseline.json). So the self-check sizes
 * itself to the resolved baseline's own `minConfirmedFindings` (never fewer
 * than 1) — it always trivially satisfies whatever guard is committed,
 * exactly like the other two self-checks do by construction.
 */
function selfCheckResults(minConfirmedFindings: number): DetectionCoverageEntry[] {
  const count = Math.max(1, minConfirmedFindings);
  return Array.from({ length: count }, (_, i) => ({
    repo: "selfcheck",
    findingId: `finding_selfcheck_${i}`,
    category: "sql_injection",
    detected: true,
    reasoning:
      "SELF-CHECK — synthetic, always fully covered; not a real evaluator run. Proves the " +
      "scorer/baseline/exit-code plumbing works, nothing about real telemetry coverage.",
  }));
}

/**
 * Run the CLI and return an exit code (does not call process.exit — testable).
 * `out` and `err` are injectable for tests.
 */
export async function run(
  argv: string[],
  out: (s: string) => void = console.log,
  err: (s: string) => void = console.error,
): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (e) {
    err(e instanceof Error ? e.message : String(e));
    err(USAGE);
    return QA_EXIT.USAGE;
  }
  if (args.help) {
    out(USAGE);
    return QA_EXIT.OK;
  }

  try {
    const root = findRepoRoot(fileURLToPath(import.meta.url));
    const baseline = await resolveBaseline(args.baseline, root);

    const selfCheck = !args.findings;
    const entries = args.findings
      ? await loadDetectionCoverageFindingsFile(args.findings)
      : selfCheckResults(baseline.minConfirmedFindings ?? 0);
    const score = scoreDetectionCoverage(entries);
    const regression = evaluateDetectionCoverageBaseline(score, baseline);

    if (args.json) {
      out(JSON.stringify(toDetectionCoverageJsonReport(score, regression), null, 2));
    } else {
      if (selfCheck) {
        out(
          "SELF-CHECK MODE — synthetic fully-covered entry (pass real evaluator output via --findings).",
        );
      }
      out(formatDetectionCoverageScore(score));
      out("");
      out(formatDetectionCoverageRegression(regression));
    }
    return regression.passed ? QA_EXIT.OK : QA_EXIT.REGRESSION;
  } catch (e) {
    if (isMontrError(e)) {
      err(`${e.code}: ${e.message}`);
      return QA_EXIT.CORPUS_ERROR;
    }
    err(`unexpected error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    return QA_EXIT.RUNTIME_ERROR;
  }
}

// Entrypoint guard: only run when invoked directly (never on import).
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  run(process.argv.slice(2))
    .then((code) => {
      if (code !== QA_EXIT.OK)
        console.error(`qa:detection-coverage exit ${code} (${exitLabel(code)})`);
      process.exit(code);
    })
    .catch((e) => {
      console.error(e);
      process.exit(QA_EXIT.RUNTIME_ERROR);
    });
}
