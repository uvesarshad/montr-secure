import {
  CostEstimateSchema,
  CostActualSchema,
  CostRollupSchema,
  type CostEstimate,
  type CostActual,
  type CostRollup,
} from "@montr/contracts";
import { SCAN_ID, FIXED_NOW, FIXED_LATER } from "./ids.js";

export const mockCostEstimate: CostEstimate = CostEstimateSchema.parse({
  scanId: SCAN_ID,
  mode: "full",
  projectedInputTokens: 120_000,
  projectedOutputTokens: 30_000,
  projectedTotalTokens: 150_000,
  projectedUsd: 0.66,
  projectedWallClockSeconds: 180,
  basis: "routes×sinks × full-mode multiplier",
  byLayer: [
    {
      key: "layer2",
      usage: { inputTokens: 60_000, outputTokens: 15_000, totalTokens: 75_000 },
      usd: 0.33,
    },
    {
      key: "layer3",
      usage: { inputTokens: 60_000, outputTokens: 15_000, totalTokens: 75_000 },
      usd: 0.33,
    },
  ],
  createdAt: FIXED_NOW,
});

export const mockCostActual: CostActual = CostActualSchema.parse({
  scanId: SCAN_ID,
  usage: { inputTokens: 118_000, outputTokens: 26_000, totalTokens: 144_000 },
  actualUsd: 0.6,
  wallClockSeconds: 172,
  byLayer: [
    {
      key: "layer2",
      usage: { inputTokens: 59_000, outputTokens: 13_000, totalTokens: 72_000 },
      usd: 0.3,
    },
    {
      key: "layer3",
      usage: { inputTokens: 59_000, outputTokens: 13_000, totalTokens: 72_000 },
      usd: 0.3,
    },
  ],
  byModel: [
    {
      key: "claude-sonnet-5",
      usage: { inputTokens: 90_000, outputTokens: 20_000, totalTokens: 110_000 },
      usd: 0.45,
    },
    {
      key: "claude-opus-4-8",
      usage: { inputTokens: 28_000, outputTokens: 6_000, totalTokens: 34_000 },
      usd: 0.15,
    },
  ],
  updatedAt: FIXED_LATER,
});

/** Estimate vs actual — within the ±15% target. */
export const mockCostRollup: CostRollup = CostRollupSchema.parse({
  scanId: SCAN_ID,
  estimate: mockCostEstimate,
  actual: mockCostActual,
  costPerFindingUsd: 0.3,
  variancePct: -0.09,
});
