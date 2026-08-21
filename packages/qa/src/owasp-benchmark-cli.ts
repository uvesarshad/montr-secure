#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { isMontrError } from "@montr/contracts";
import { loadScanFindingsFile } from "./findings-io.js";
import { QA_EXIT, exitLabel } from "./exit-codes.js";
import {
  flaggedFromConfirmedFindings,
  flaggedFromSemgrepResults,
  loadOwaspBenchmark,
  scoreOwaspBenchmark,
  type RawSemgrepJson,
} from "./owasp-benchmark.js";
import {
  formatOwaspBenchmarkComparison,
  formatOwaspBenchmarkScore,
  toOwaspBenchmarkJsonReport,
} from "./owasp-benchmark-report.js";

/**
 * `owasp-benchmark` CLI (E14, closes A29). Scores this product's REAL pipeline
 * output (from `scripts/benchmark-owasp.mjs`) — and, optionally, a raw Semgrep
 * `--json` run (from `scripts/benchmark-semgrep.mjs`) and/or a CodeQL SARIF run
 * — against the vendored OWASP Benchmark subset's OWN ground truth
 * (`corpus/owasp-benchmark/expectedresults-subset.csv`), using OWASP
 * Benchmark's own TPR/FPR/score methodology (never this repo's internal
 * golden-corpus scorer — see owasp-benchmark.ts's header).
 */

const USAGE = `montr-qa-owasp-benchmark — external OWASP Benchmark comparison (E14 / A29)

Usage:
  montr-qa-owasp-benchmark --our-findings <path> [options]

Options:
  --our-findings <path>   REQUIRED. This product's REAL scan-results JSON for the
                           OWASP Benchmark subset (see scripts/benchmark-owasp.mjs),
                           same shape @montr/qa's --findings expects.
  --semgrep-json <path>   Optional: raw \`semgrep --json\` output run directly
                           against corpus/owasp-benchmark (see
                           scripts/benchmark-semgrep.mjs) — scores it as a
                           competitor on the SAME subset/ground truth.
  --json                  Emit a machine-readable JSON report instead of text.
  -h, --help              Show this help.

Exit codes: 0 OK · 2 USAGE · 3 CORPUS_ERROR · 4 RUNTIME_ERROR
(this CLI never exits 1/REGRESSION — it is a comparison report, not a release
gate; see corpus/owasp-benchmark/README.md for why this is scored separately
from the internal \`qa:corpus\` gate.)`;

interface ParsedArgs {
  ourFindings?: string;
  semgrepJson?: string;
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
    if (arg === "--") continue;
    switch (arg) {
      case "--our-findings":
        args.ourFindings = needValue();
        break;
      case "--semgrep-json":
        args.semgrepJson = needValue();
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
  if (!args.ourFindings) {
    err("--our-findings is required (see --help)");
    err(USAGE);
    return QA_EXIT.USAGE;
  }

  try {
    const { cases } = await loadOwaspBenchmark();

    const ourResults = await loadScanFindingsFile(args.ourFindings);
    const ourConfirmed = ourResults.flatMap((r) => r.confirmed);
    const ourFlagged = flaggedFromConfirmedFindings(ourConfirmed);
    const ourScore = scoreOwaspBenchmark(cases, ourFlagged, { toolName: "montr-secure" });

    const scores = [ourScore];

    if (args.semgrepJson) {
      const { readFile } = await import("node:fs/promises");
      let semgrepText: string;
      try {
        semgrepText = await readFile(args.semgrepJson, "utf8");
      } catch (cause) {
        err(`could not read --semgrep-json: ${args.semgrepJson} (${String(cause)})`);
        return QA_EXIT.CORPUS_ERROR;
      }
      let semgrepJson: RawSemgrepJson;
      try {
        semgrepJson = JSON.parse(semgrepText) as RawSemgrepJson;
      } catch (cause) {
        err(`--semgrep-json is not valid JSON: ${args.semgrepJson} (${String(cause)})`);
        return QA_EXIT.CORPUS_ERROR;
      }
      const semgrepFlagged = flaggedFromSemgrepResults(semgrepJson);
      const semgrepScore = scoreOwaspBenchmark(cases, semgrepFlagged, {
        toolName: "semgrep (raw)",
      });
      scores.push(semgrepScore);
    }

    if (args.json) {
      out(JSON.stringify(toOwaspBenchmarkJsonReport(scores), null, 2));
    } else {
      for (const s of scores) {
        out(formatOwaspBenchmarkScore(s));
        out("");
      }
      if (scores.length > 1) {
        out(formatOwaspBenchmarkComparison(scores));
      }
    }
    return QA_EXIT.OK;
  } catch (e) {
    if (isMontrError(e)) {
      err(`${e.code}: ${e.message}`);
      return QA_EXIT.CORPUS_ERROR;
    }
    err(`unexpected error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    return QA_EXIT.RUNTIME_ERROR;
  }
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  run(process.argv.slice(2))
    .then((code) => {
      if (code !== QA_EXIT.OK) console.error(`owasp-benchmark exit ${code} (${exitLabel(code)})`);
      process.exit(code);
    })
    .catch((e) => {
      console.error(e);
      process.exit(QA_EXIT.RUNTIME_ERROR);
    });
}
