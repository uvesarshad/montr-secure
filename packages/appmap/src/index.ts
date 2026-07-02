/**
 * @montr/appmap — Layer 0: intake, deterministic App Map builders
 * (tree-sitter/ts-morph first, LLM only to fill gaps), and the cost estimator.
 *
 * ⛔ No LLM call fires before the deterministic map exists (§6.1). Emits
 * {AppMap, ScanScope, CostEstimate}. Implementation: WS-E.
 */
import {
  NotImplementedError,
  type Layer0Output,
  type ScanMode,
  type ScanScope,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

export interface BuildAppMapInput {
  clientId: string;
  scanId: string;
  repo: string;
  branch: string;
  mode: ScanMode;
  scope: ScanScope;
  config: MontrConfig;
}

export async function buildAppMap(_input: BuildAppMapInput): Promise<Layer0Output> {
  throw new NotImplementedError("buildAppMap — WS-E");
}
