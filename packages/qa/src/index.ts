/**
 * @montr/qa — QA harness + golden-corpus gate for Montr Secure (build-plan §4.7).
 *
 * - Golden corpus (vulnerable + clean Next.js/Prisma repos with machine-readable
 *   ground truth) merged from @montr/fixtures + `corpus/`.
 * - Precision/recall scorer with a headline false-positive rate (target < 5%),
 *   per category and per repo.
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
export * from "./synthetic.js";
export * from "./baseline.js";
export * from "./corpus.js";
export * from "./runner.js";
export * from "./model-variance.js";
export * from "./layer-metrics.js";
export * from "./findings-io.js";
export * from "./report.js";
export { run } from "./cli.js";

import {
  DEFAULT_BASELINE,
  evaluateBaseline,
  type Baseline,
  type RegressionResult,
} from "./baseline.js";
import { loadCorpus, type LoadCorpusOptions, type LoadedCorpus } from "./corpus.js";
import { perfectScanner, runCorpus, type CorpusRun } from "./runner.js";
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
}

/**
 * Programmatic self-check: load the corpus, run the perfect scanner, and grade
 * against the baseline. Convenience wrapper around {@link loadCorpus} +
 * {@link runCorpus} + {@link evaluateBaseline}; the CLI is the CI entrypoint.
 */
export async function runQaSuite(opts: QaSuiteOptions = {}): Promise<QaSuiteResult> {
  const corpus = await loadCorpus(opts.loadOptions);
  const run = await runCorpus(corpus, perfectScanner, opts.scoreOptions);
  const regression = evaluateBaseline(run.score, opts.baseline ?? DEFAULT_BASELINE);
  return { corpus, run, regression };
}
