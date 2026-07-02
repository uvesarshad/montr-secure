import {
  CostEstimateSchema,
  RECOMMENDED_MODEL_MATRIX,
  type CostEstimate,
  type CostLineItem,
  type ScanMode,
  type TokenUsage,
} from "@montr/contracts";
import { addUsage, priceUsageUsd, roundUsd, zeroUsage } from "./pricing.js";

/**
 * Pre-scan cost estimator (§6.6, build-plan §4.1). Projects tokens + wall-clock
 * from App-Map size (routes/sinks/files) × scan mode. Deterministic and offline;
 * the ±15% estimate-vs-actual target is validated by the variance helper.
 */

/** Inputs to the pre-scan estimate — derived from the Layer-0 App Map + scan mode. */
export interface EstimateInput {
  scanId: string;
  mode: ScanMode;
  routeCount: number;
  sinkCount: number;
  fileCount: number;
}

export interface EstimateOptions {
  /** Injectable clock for deterministic `createdAt`. */
  now?: () => Date;
  /** Model used to price the non-confirmation LLM layers (default tier). */
  defaultModelId?: string;
  /** Model used to price the confirmation layer (confirmation tier). */
  confirmationModelId?: string;
  /** Fraction of input tokens projected as output. */
  outputRatio?: number;
  /** Estimated tokens processed per wall-clock second (throughput heuristic). */
  tokensPerSecond?: number;
}

/** Full scan = 1×; diff scan touches ~changed files + reachable graph only. */
const MODE_MULTIPLIER: Record<ScanMode, number> = { full: 1, diff: 0.35 };

function lineItem(
  key: string,
  inputTokens: number,
  outputRatio: number,
  modelId: string,
): CostLineItem {
  const outputTokens = Math.round(inputTokens * outputRatio);
  const usage: TokenUsage = {
    inputTokens,
    outputTokens,
    totalTokens: inputTokens + outputTokens,
  };
  return { key, usage, usd: priceUsageUsd(usage, modelId) };
}

/**
 * Project the LLM cost of a scan from its App-Map size and mode. Only the
 * LLM-using layers are modeled (L0 labeling, L2 correlation, L3 confirmation,
 * L5 report) — deterministic tool layers (L1 discovery) burn no tokens.
 */
export function estimateScanCost(input: EstimateInput, opts: EstimateOptions = {}): CostEstimate {
  const mult = MODE_MULTIPLIER[input.mode];
  const outputRatio = opts.outputRatio ?? 0.25;
  const tps = opts.tokensPerSecond ?? 2000;
  const defaultModel = opts.defaultModelId ?? RECOMMENDED_MODEL_MATRIX.default.modelId;
  const confModel = opts.confirmationModelId ?? RECOMMENDED_MODEL_MATRIX.confirmation.modelId;

  const files = Math.max(0, Math.floor(input.fileCount));
  const routes = Math.max(0, Math.floor(input.routeCount));
  const sinks = Math.max(0, Math.floor(input.sinkCount));

  const layer0In = Math.round((files * 300 + routes * 250) * mult);
  const layer2In = Math.round((sinks * 700 + routes * 400) * mult);
  const layer3In = Math.round(sinks * 900 * mult);
  const layer5In = Math.round((routes * 120 + 2000) * mult);

  const byLayer: CostLineItem[] = [
    lineItem("layer0", layer0In, outputRatio, defaultModel),
    lineItem("layer2", layer2In, outputRatio, defaultModel),
    lineItem("layer3", layer3In, outputRatio, confModel),
    lineItem("layer5", layer5In, outputRatio, defaultModel),
  ];

  const usage = byLayer.reduce<TokenUsage>((acc, l) => addUsage(acc, l.usage), zeroUsage());
  const projectedUsd = roundUsd(byLayer.reduce((acc, l) => acc + l.usd, 0));
  const projectedWallClockSeconds = Math.round(usage.totalTokens / tps + 30);

  return CostEstimateSchema.parse({
    scanId: input.scanId,
    mode: input.mode,
    projectedInputTokens: usage.inputTokens,
    projectedOutputTokens: usage.outputTokens,
    projectedTotalTokens: usage.totalTokens,
    projectedUsd,
    projectedWallClockSeconds,
    basis: `files=${files} routes=${routes} sinks=${sinks} × ${input.mode} mode (×${mult})`,
    byLayer,
    createdAt: (opts.now?.() ?? new Date()).toISOString(),
  } satisfies CostEstimate);
}
