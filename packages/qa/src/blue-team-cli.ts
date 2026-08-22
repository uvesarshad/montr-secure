#!/usr/bin/env node
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isMontrError } from "@montr/contracts";
import {
  BLUE_TEAM_GROUND_TRUTH,
  scoreBlueTeamResults,
  type BlueTeamScenarioResult,
} from "./blue-team-corpus.js";
import {
  DEFAULT_BLUE_TEAM_BASELINE,
  evaluateBlueTeamBaseline,
  loadBlueTeamBaselineFile,
  type BlueTeamBaseline,
} from "./blue-team-baseline.js";
import { loadBlueTeamScanFindingsFile } from "./blue-team-findings-io.js";
import {
  formatBlueTeamScore,
  formatBlueTeamRegression,
  toBlueTeamJsonReport,
} from "./blue-team-report.js";
import { findRepoRoot } from "./corpus.js";
import { QA_EXIT, exitLabel } from "./exit-codes.js";

/**
 * `qa:blue-team-corpus` CLI (B12) — the blue-team mirror of `qa:corpus`.
 * Scores a real blue-team-corpus run's actual-fired verdicts against the
 * committed ground truth (BLUE_TEAM_GROUND_TRUTH) and exits non-zero on a
 * detection-precision/recall regression vs. the committed baseline.
 * Metadata-only output (golden rule #1) — mirrors `cli.ts`'s shape exactly.
 */

const USAGE = `montr-qa-blue-team — blue-team detection-corpus precision/recall gate (B12)

Usage:
  montr-qa-blue-team [options]

⛔ Without --findings this is the SYNTHETIC SELF-CHECK (every labelled
   scenario's actualFired is set to its own expectedFired by construction —
   precision/recall are tautologically 100%; it only proves the
   corpus/scorer/baseline/exit-code plumbing works). It is NOT the release
   gate. Run it explicitly via \`qa:blue-team-corpus:selfcheck\` when that is
   what you want. The release gate MUST pass --findings pointing at a REAL
   run's output (see scripts/blue-team-corpus-scan.mjs), e.g.:
     qa:blue-team-corpus -- --findings blue-team-scan.json

Options:
  --findings <path>   Score a blue-team-scan-results JSON file (default: self-check).
  --baseline <path>   Baseline thresholds JSON (default: corpus/blue-team-baseline.json, else built-in defaults).
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
    // Same pnpm `--` passthrough tolerance as cli.ts (see that file's comment).
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
): Promise<BlueTeamBaseline> {
  if (explicitPath) return loadBlueTeamBaselineFile(explicitPath);
  const defaultPath = join(root, "corpus", "blue-team-baseline.json");
  if (existsSync(defaultPath)) return loadBlueTeamBaselineFile(defaultPath);
  return DEFAULT_BLUE_TEAM_BASELINE;
}

/** Tautological plumbing self-check: actualFired := expectedFired for every labelled case. */
function selfCheckResults(): BlueTeamScenarioResult[] {
  return BLUE_TEAM_GROUND_TRUTH.map((c) => ({
    templateKey: c.templateKey,
    scenarioName: c.templateKey,
    findingCategory: c.findingCategory,
    expectedFired: c.expectedFired,
    actualFired: c.expectedFired,
    evidence: "SELF-CHECK — synthetic, echoes expectedFired; not a real evaluator run.",
    sigmaRulesEvaluated: 1,
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
    const results = args.findings
      ? await loadBlueTeamScanFindingsFile(args.findings)
      : selfCheckResults();
    const score = scoreBlueTeamResults(results);
    const regression = evaluateBlueTeamBaseline(score, baseline);

    if (args.json) {
      out(JSON.stringify(toBlueTeamJsonReport(score, regression), null, 2));
    } else {
      if (selfCheck) {
        out(
          "SELF-CHECK MODE — synthetic echo of expectedFired (pass real evaluator output via --findings).",
        );
      }
      out(formatBlueTeamScore(score));
      out("");
      out(formatBlueTeamRegression(regression));
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
        console.error(`qa:blue-team-corpus exit ${code} (${exitLabel(code)})`);
      process.exit(code);
    })
    .catch((e) => {
      console.error(e);
      process.exit(QA_EXIT.RUNTIME_ERROR);
    });
}
