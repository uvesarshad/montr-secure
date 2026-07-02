/**
 * @montr/discovery — Layer 1: parallel SAST (Semgrep) + secrets/config
 * (gitleaks) + dependency/SCA (OSV/GHSA + reachability) agents.
 *
 * ⛔ Deliberately over-inclusive; Layer-1 output is NEVER surfaced to the user.
 * Deterministic tools detect; the LLM only triages/explains. Implementation: WS-F.
 */
import {
  NotImplementedError,
  type AppMap,
  type Layer1Output,
  type ScanScope,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

export interface RunDiscoveryInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  scope: ScanScope;
  config: MontrConfig;
}

export async function runDiscovery(_input: RunDiscoveryInput): Promise<Layer1Output> {
  throw new NotImplementedError("runDiscovery — WS-F");
}
