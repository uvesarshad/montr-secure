/**
 * Cost estimator (build-plan §5.1, golden rule #8): project token spend +
 * wall-clock from App-Map size × scan mode. Delegates the token math to
 * @montr/cost-meter (the single, tested source of pricing) and just derives its
 * inputs (routes/sinks/files) from the built map. The estimator applies the
 * diff-mode discount itself, so FULL map counts are passed for both modes.
 */
import { estimateScanCost } from "@montr/cost-meter";
import type { CostEstimate } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { AppMap, ScanMode } from "@montr/contracts";

export interface EstimateCostInput {
  scanId: string;
  mode: ScanMode;
  appMap: AppMap;
  /** Number of source files scanned (map size proxy). */
  fileCount: number;
  config: MontrConfig;
  now?: () => Date;
}

/** Project the pre-scan cost estimate for the built App Map. */
export function estimateCost(input: EstimateCostInput): CostEstimate {
  const { appMap, config } = input;
  return estimateScanCost(
    {
      scanId: input.scanId,
      mode: input.mode,
      routeCount: appMap.routes.length,
      sinkCount: appMap.taintSinks.length,
      fileCount: input.fileCount,
    },
    {
      ...(input.now ? { now: input.now } : {}),
      defaultModelId: config.llm.modelMatrix.default,
      confirmationModelId: config.llm.modelMatrix.confirmation,
    },
  );
}
