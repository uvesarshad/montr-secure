import type { GroundTruthManifest } from "@montr/fixtures";
import {
  DEFAULT_BASELINE,
  evaluateBaseline,
  type Baseline,
  type RegressionResult,
} from "./baseline.js";
import type { LoadedCorpus } from "./corpus.js";
import { runCorpus, type CorpusRun, type CorpusScanner } from "./runner.js";
import { scoreScanResults } from "./scorer.js";
import type { CorpusScore, RepoScanResult, ScoreOptions } from "./types.js";

/**
 * REAL-MODE golden-corpus gate (build-plan §4.7, PRD §15/§19).
 *
 * The synthetic self-check (`perfectScanner`) proves the gate PLUMBING is green
 * before the pipeline lands. This module is the REAL mode: it scores an actual
 * pipeline's ConfirmedFinding[] (per corpus repo) against the ground-truth
 * manifest and grades precision / recall / FP-rate against the committed
 * baseline. Once Layer-0..3 is wired the CI gate measures TRUE accuracy through
 * here (the CLI `--findings` path scores the same way). Deterministic, offline.
 *
 * Metadata-only (golden rule #1): scores + threshold breaches, never code bodies.
 */

export interface GateResult {
  /** Precision / recall / FP-rate vs ground truth. */
  score: CorpusScore;
  /** Pass/fail vs the committed baseline, with every threshold breach. */
  regression: RegressionResult;
}

export interface RealModeOptions {
  /** Regression thresholds (default: {@link DEFAULT_BASELINE} = Phase-1 DoD). */
  baseline?: Baseline;
  /** Matching tolerance + operator FP markers (§15). */
  scoreOptions?: ScoreOptions;
}

/**
 * Grade a real pipeline's confirmed findings (per repo) against the corpus ground
 * truth. This is the core the CI gate runs once the pipeline hands over
 * ConfirmedFinding[]; the CLI `--findings` mode is a thin file-loading wrapper.
 */
export function gradeScanResults(
  results: readonly RepoScanResult[],
  manifest: GroundTruthManifest,
  opts: RealModeOptions = {},
): GateResult {
  const score = scoreScanResults(results, manifest, opts.scoreOptions ?? {});
  const regression = evaluateBaseline(score, opts.baseline ?? DEFAULT_BASELINE);
  return { score, regression };
}

/**
 * Run a LIVE scanner (the real Layer-0..3 pipeline plugs in as the
 * {@link CorpusScanner}) across a loaded corpus, then score + grade it. Keeps the
 * synthetic self-check available via the default scanner in `runQaSuite`.
 */
export async function gradeCorpus(
  corpus: LoadedCorpus,
  scanner: CorpusScanner,
  opts: RealModeOptions = {},
): Promise<GateResult & { run: CorpusRun }> {
  const run = await runCorpus(corpus, scanner, opts.scoreOptions ?? {});
  const regression = evaluateBaseline(run.score, opts.baseline ?? DEFAULT_BASELINE);
  return { score: run.score, regression, run };
}
