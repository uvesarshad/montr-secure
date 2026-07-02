import type {
  ConfirmedFinding,
  LLMGateway,
  ModelDescriptor,
  ModelTier,
  Provider,
} from "@montr/contracts";
import type { LoadedCorpus, LoadedRepo } from "./corpus.js";
import { scoreScanResults } from "./scorer.js";
import {
  DEFAULT_BASELINE,
  evaluateBaseline,
  type Baseline,
  type RegressionResult,
} from "./baseline.js";
import type { RepoScanResult, ScoreOptions } from "./types.js";
import type { Promisable } from "./runner.js";

/**
 * Model-variance harness scaffold (build-plan §4.7 / §10, PRD §15/§17). Runs the
 * golden corpus across each provider/model reachable through the gateway and
 * emits a model matrix, flagging accuracy cliffs that justify the model floor
 * (DECIDE-3). Uses the @montr/contracts LLMGateway interface only — provider
 * selection is the gateway's job; NO provider SDK here (golden rule #2). Tests
 * drive it with the @montr/fixtures fake adapter.
 */

/** A scan of one repo with a specific model, via the gateway. */
export type ModelScanner = (
  repo: LoadedRepo,
  model: ModelDescriptor,
  gateway: LLMGateway,
) => Promisable<ConfirmedFinding[]>;

export interface ModelScore {
  precision: number;
  recall: number;
  fpRate: number;
  f1: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
}

export interface ModelMatrixRow {
  provider: Provider;
  modelId: string;
  tier: ModelTier;
  belowFloor: boolean;
  score: ModelScore;
  regression: RegressionResult;
  /** Flagged when this model degrades accuracy vs the floor — an "accuracy cliff" (PRD §17). */
  accuracyCliff: boolean;
}

export interface ModelMatrix {
  generatedAt: string;
  corpusVersion: string;
  /** Models at/above the confirmation floor (belowFloor === false). */
  floorModelIds: string[];
  rows: ModelMatrixRow[];
}

export interface ModelVarianceOptions {
  corpus: LoadedCorpus;
  gateway: LLMGateway;
  scan: ModelScanner;
  /** Models to run (default: everything the gateway lists). */
  models?: ModelDescriptor[];
  baseline?: Baseline;
  scoreOptions?: ScoreOptions;
  /** Recall drop below the best floor model that counts as a cliff (default 0.1). */
  cliffMargin?: number;
  /** Injectable clock for deterministic output (default real time). */
  now?: () => string;
}

/** Run the corpus across models and produce the variance matrix. */
export async function runModelVariance(opts: ModelVarianceOptions): Promise<ModelMatrix> {
  const models = opts.models ?? opts.gateway.listModels();
  const baseline = opts.baseline ?? DEFAULT_BASELINE;
  const cliffMargin = opts.cliffMargin ?? 0.1;
  const now = opts.now ?? (() => new Date().toISOString());

  const scored: Array<{ model: ModelDescriptor; score: ModelScore; regression: RegressionResult }> =
    [];
  for (const model of models) {
    const results: RepoScanResult[] = [];
    for (const repo of opts.corpus.repos) {
      results.push({ repo: repo.name, confirmed: await opts.scan(repo, model, opts.gateway) });
    }
    const full = scoreScanResults(results, opts.corpus.manifest, opts.scoreOptions);
    scored.push({
      model,
      score: {
        precision: full.precision,
        recall: full.recall,
        fpRate: full.fpRate,
        f1: full.f1,
        truePositives: full.truePositives,
        falsePositives: full.falsePositives,
        falseNegatives: full.falseNegatives,
      },
      regression: evaluateBaseline(full, baseline),
    });
  }

  // Reference recall: the best among floor-or-better models (fall back to overall best).
  const floorScored = scored.filter((s) => !s.model.belowFloor);
  const bestRecall = (floorScored.length ? floorScored : scored).reduce(
    (max, s) => Math.max(max, s.score.recall),
    0,
  );

  const rows: ModelMatrixRow[] = scored.map(({ model, score, regression }) => ({
    provider: model.provider,
    modelId: model.modelId,
    tier: model.tier,
    belowFloor: model.belowFloor,
    score,
    regression,
    accuracyCliff:
      !regression.passed || (model.belowFloor && score.recall < bestRecall - cliffMargin),
  }));

  return {
    generatedAt: now(),
    corpusVersion: opts.corpus.version,
    floorModelIds: floorScored.map((s) => s.model.modelId),
    rows,
  };
}
