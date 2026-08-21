#!/usr/bin/env node
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { isMontrError } from "@montr/contracts";
import { createFakeLlmGateway } from "@montr/fixtures";
import { DEFAULT_BASELINE, evaluateBaseline, loadBaselineFile, type Baseline } from "./baseline.js";
import { loadCorpus } from "./corpus.js";
import { QA_EXIT, exitLabel } from "./exit-codes.js";
import { loadScanFindingsFile } from "./findings-io.js";
import { runModelVariance, type ModelScanner } from "./model-variance.js";
import {
  REAL_VARIANCE_BASELINE,
  realConfirmedForRepo,
  realVarianceCorpus,
  realVarianceModelMatrix,
} from "./real-confirmation-scanner.js";
import { perfectScanner, runCorpus } from "./runner.js";
import { formatCorpusScore, formatModelMatrix, formatRegression, toJsonReport } from "./report.js";
import { scoreScanResults } from "./scorer.js";
import { perfectConfirmedForRepo } from "./synthetic.js";
import type { ScoreOptions } from "./types.js";

/**
 * `qa:corpus` CLI (build-plan §4.7). Loads the golden corpus, scores a scan's
 * confirmed findings against ground truth, and exits non-zero on regression vs
 * the committed baseline. Metadata-only output (golden rule #1).
 */

const USAGE = `montr-qa — golden-corpus precision/recall gate

Usage:
  montr-qa [options]

⛔ Without --findings this is the SYNTHETIC SELF-CHECK (perfectScanner echoes
   ground truth back at itself — precision/FP-rate are tautologically perfect;
   it only proves the corpus/scorer/baseline/exit-code plumbing works). It is
   NOT the release gate. Run it explicitly via \`qa:corpus:selfcheck\` when
   that is what you want. The release gate MUST pass --findings pointing at a
   real pipeline's output (see scripts/corpus-scan.mjs), e.g.:
     qa:corpus -- --findings scan.json

Options:
  --findings <path>       Score a scan-results JSON file (default: self-check with a perfect scanner).
  --baseline <path>       Baseline thresholds JSON (default: corpus/baseline.json, else built-in DoD defaults).
  --line-tolerance <n>    Max line drift for a location match (default: 3).
  --variance              Run the model-variance harness (A23): the REAL packages/confirm
                           static-confirmation pipeline against the golden-corpus fixture repos,
                           once per model in the matrix, with a fake (offline, no-provider-spend)
                           gateway that genuinely differentiates behavior by model — never an
                           identical score across models. Prints the per-model matrix.
  --variance-selfcheck    With --variance: use the synthetic perfect-scanner self-check instead
                           (echoes ground truth — ignores which model is passed; every model scores
                           identically. Proves the matrix/scorer/baseline plumbing works, nothing more).
  --no-verify             Do not verify corpus repo directories exist on disk.
  --json                  Emit a machine-readable JSON report instead of text.
  -h, --help              Show this help.

Exit codes: 0 OK · 1 REGRESSION · 2 USAGE · 3 CORPUS_ERROR · 4 RUNTIME_ERROR`;

interface ParsedArgs {
  findings?: string;
  baseline?: string;
  lineTolerance?: number;
  variance: boolean;
  varianceSelfcheck: boolean;
  verify: boolean;
  json: boolean;
  help: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = {
    variance: false,
    varianceSelfcheck: false,
    verify: true,
    json: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const needValue = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`option ${arg} requires a value`);
      return v;
    };
    // `pnpm --filter <pkg> run <script> -- <args>` forwards a literal `--`
    // ahead of <args> when the script itself is a compound command (e.g. this
    // package's `qa:corpus`: `tsc -b && node dist/cli.js`) — pnpm 9.x does not
    // strip its own separator in that shape. Skip any leading `--` no-ops
    // rather than erroring, so the documented invocation
    // (`qa:corpus -- --findings scan.json`, corpus/README.md) actually works.
    if (arg === "--") continue;
    switch (arg) {
      case "--findings":
        args.findings = needValue();
        break;
      case "--baseline":
        args.baseline = needValue();
        break;
      case "--line-tolerance": {
        const n = Number(needValue());
        if (!Number.isInteger(n) || n < 0)
          throw new UsageError("--line-tolerance must be a non-negative integer");
        args.lineTolerance = n;
        break;
      }
      case "--variance":
        args.variance = true;
        break;
      case "--variance-selfcheck":
        args.varianceSelfcheck = true;
        break;
      case "--no-verify":
        args.verify = false;
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

async function resolveBaseline(explicitPath: string | undefined, root: string): Promise<Baseline> {
  if (explicitPath) return loadBaselineFile(explicitPath);
  const defaultPath = join(root, "corpus", "baseline.json");
  if (existsSync(defaultPath)) return loadBaselineFile(defaultPath);
  return DEFAULT_BASELINE;
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
    const corpus = await loadCorpus({ verifyPaths: args.verify });
    for (const w of corpus.warnings) err(`warning: ${w}`);
    const baseline = await resolveBaseline(args.baseline, corpus.root);
    const scoreOptions: ScoreOptions = { lineTolerance: args.lineTolerance };

    if (args.variance) {
      const gateway = createFakeLlmGateway();
      // A23: default is the REAL scanner — packages/confirm's actual static
      // confirmation, run once per model against the golden-corpus fixture
      // repos with a gateway that genuinely differs per model (see
      // real-confirmation-scanner.ts). --variance-selfcheck opts back into the
      // OLD tautological perfect-scanner echo (ignores `model`; every row
      // scores identically) purely as a plumbing smoke check, same convention
      // as `qa:corpus` vs `qa:corpus:selfcheck`.
      const scan: ModelScanner = args.varianceSelfcheck
        ? (repo) => perfectConfirmedForRepo(repo)
        : realConfirmedForRepo;
      const models = args.varianceSelfcheck ? undefined : realVarianceModelMatrix();
      // The real scanner only covers a narrow, hand-fixtured slice of the
      // corpus (see real-confirmation-scanner.ts) — score + gate against that
      // slice, not the full 16-repo corpus/baseline.json (whose
      // minReposScored:14 would fail for reasons unrelated to model quality).
      // --variance-selfcheck keeps the OLD full-corpus/default-baseline shape
      // since the tautological scanner "covers" every repo by construction.
      const varianceCorpus = args.varianceSelfcheck ? corpus : realVarianceCorpus(corpus);
      const varianceBaseline = args.baseline
        ? baseline
        : args.varianceSelfcheck
          ? baseline
          : REAL_VARIANCE_BASELINE;
      const matrix = await runModelVariance({
        corpus: varianceCorpus,
        gateway,
        scan,
        models,
        baseline: varianceBaseline,
        scoreOptions,
      });
      if (!args.json) {
        out(
          args.varianceSelfcheck
            ? "VARIANCE SELF-CHECK MODE — synthetic perfect scanner (ignores `model`; every row is identical by construction). Run --variance without this flag for the real, model-differentiated harness."
            : "VARIANCE MODE — real packages/confirm static confirmation per model (A23).",
        );
      }
      if (args.json) out(JSON.stringify(matrix, null, 2));
      else out(formatModelMatrix(matrix));
      // Gate on floor-or-better models only; below-floor cliffs are informational
      // (see ModelMatrixRow.accuracyCliff — the number to watch, not this exit code).
      const floorRegressed = matrix.rows.some((r) => !r.belowFloor && !r.regression.passed);
      return floorRegressed ? QA_EXIT.REGRESSION : QA_EXIT.OK;
    }

    const selfCheck = !args.findings;
    let scoreInput;
    if (args.findings) {
      const results = await loadScanFindingsFile(args.findings);
      scoreInput = scoreScanResults(results, corpus.manifest, scoreOptions);
    } else {
      scoreInput = (await runCorpus(corpus, perfectScanner, scoreOptions)).score;
    }
    const regression = evaluateBaseline(scoreInput, baseline);

    if (args.json) {
      out(
        JSON.stringify(
          toJsonReport(scoreInput, regression, {
            corpusVersion: corpus.version,
            warnings: corpus.warnings,
          }),
          null,
          2,
        ),
      );
    } else {
      if (selfCheck) {
        out("SELF-CHECK MODE — synthetic perfect scanner (pass real scan output via --findings).");
      }
      out(formatCorpusScore(scoreInput));
      out("");
      out(formatRegression(regression));
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
      if (code !== QA_EXIT.OK) console.error(`qa:corpus exit ${code} (${exitLabel(code)})`);
      process.exit(code);
    })
    .catch((e) => {
      console.error(e);
      process.exit(QA_EXIT.RUNTIME_ERROR);
    });
}
