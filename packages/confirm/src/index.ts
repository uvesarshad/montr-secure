/**
 * @montr/confirm — Layer 3: turns probable → confirmed. Static data-flow proof
 * ships by default; live DAST is premium and heavily gated.
 *
 * ⛔ Live confirmation only hits an allowlisted staging target, requires
 * approver authorization, honors the kill switch + rate/blast-radius caps, and
 * production is blocked by policy (§11, DECIDE-1). Implementation: WS-H.
 */
import {
  NotImplementedError,
  type AppMap,
  type Layer3Output,
  type ProbableFinding,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

export interface ConfirmInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  probable: ProbableFinding[];
  /** Live DAST toggle — OFF unless staging is authorized by an approver. */
  allowLive: boolean;
  stagingUrl?: string;
  config: MontrConfig;
}

export async function confirmFindings(_input: ConfirmInput): Promise<Layer3Output> {
  throw new NotImplementedError("confirmFindings — WS-H");
}
