/**
 * @montr/correlation — Layer 2: THE MOAT. Cross-references each candidate
 * against the App Map (reachability, exposure, sanitizer-interruption), dedups
 * multi-tool findings into one root cause, and ranks by
 * reachability × exposure × impact. Uncorroborated candidates are DEMOTED to an
 * appendix — never deleted. Implementation: WS-G.
 */
import {
  NotImplementedError,
  type AppMap,
  type CandidateFinding,
  type Layer2Output,
} from "@montr/contracts";

export interface CorrelateInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  candidates: CandidateFinding[];
}

export async function correlate(_input: CorrelateInput): Promise<Layer2Output> {
  throw new NotImplementedError("correlate — WS-G");
}
