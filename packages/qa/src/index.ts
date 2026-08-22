/**
 * @montr/qa — QA harness + golden-corpus gate for Montr Secure (build-plan §4.7).
 *
 * - Golden corpus (vulnerable + clean Next.js/Prisma repos with machine-readable
 *   ground truth) merged from @montr/fixtures + `corpus/`.
 * - Precision/recall scorer with a headline false-positive rate (target < 5%),
 *   per category and per repo.
 * - A §15 regression corpus: operators mark a confirmed finding as a false
 *   positive; the metadata-only record feeds the scorer's precision/FP-rate and
 *   the correlation/confirmation tuning hook (down-rank/skip known FPs).
 * - A committed-baseline regression gate with clear exit codes for CI.
 * - A model-variance harness scaffold that runs the corpus across the gateway's
 *   models (fake adapter for now) and emits a model matrix.
 * - Per-layer metric reporting helpers (findings in/out, demotion/confirmation rate).
 *
 * Metadata-only output — never code/secret bodies (golden rule #1). No provider
 * SDK — model access is via the @montr/contracts LLMGateway interface (golden rule #2).
 */
export * from "./types.js";
export * from "./exit-codes.js";
export * from "./scorer.js";
export * from "./regression-corpus.js";
export * from "./synthetic.js";
export * from "./baseline.js";
export * from "./corpus.js";
export * from "./runner.js";
export * from "./real-mode.js";
export * from "./model-variance.js";
export * from "./real-confirmation-scanner.js";
export * from "./prompt-eval.js";
export * from "./layer-metrics.js";
export * from "./findings-io.js";
export * from "./report.js";
export * from "./owasp-benchmark.js";
export * from "./owasp-benchmark-report.js";
export * from "./blue-team-corpus.js";
export * from "./blue-team-baseline.js";
export * from "./blue-team-findings-io.js";
export * from "./blue-team-report.js";
export { run } from "./cli.js";
export { run as runOwaspBenchmarkCli } from "./owasp-benchmark-cli.js";
export { run as runBlueTeamCorpusCli } from "./blue-team-cli.js";

import {
  DEFAULT_BASELINE,
  evaluateBaseline,
  type Baseline,
  type RegressionResult,
} from "./baseline.js";
import { loadCorpus, type LoadCorpusOptions, type LoadedCorpus } from "./corpus.js";
import { perfectScanner, runCorpus, type CorpusRun, type CorpusScanner } from "./runner.js";
import type { ScoreOptions } from "./types.js";

export interface QaSuiteResult {
  corpus: LoadedCorpus;
  run: CorpusRun;
  regression: RegressionResult;
}

export interface QaSuiteOptions {
  baseline?: Baseline;
  loadOptions?: LoadCorpusOptions;
  scoreOptions?: ScoreOptions;
  /**
   * REAL-MODE: inject the live Layer-0..3 pipeline as the scanner to grade a real
   * scan against ground truth. Defaults to the synthetic {@link perfectScanner}
   * self-check (the fallback that keeps the gate runnable before the pipeline is
   * wired). See also {@link gradeCorpus} / {@link gradeScanResults}.
   */
  scanner?: CorpusScanner;
}

/**
 * Programmatic gate: load the corpus, run a scanner, and grade against the
 * baseline. Defaults to the synthetic perfect scanner (self-check); pass
 * `opts.scanner` (the real pipeline) for REAL mode. Convenience wrapper around
 * {@link loadCorpus} + {@link runCorpus} + {@link evaluateBaseline}; the CLI is
 * the CI entrypoint.
 */
export async function runQaSuite(opts: QaSuiteOptions = {}): Promise<QaSuiteResult> {
  const corpus = await loadCorpus(opts.loadOptions);
  const run = await runCorpus(corpus, opts.scanner ?? perfectScanner, opts.scoreOptions);
  const regression = evaluateBaseline(run.score, opts.baseline ?? DEFAULT_BASELINE);
  return { corpus, run, regression };
}
