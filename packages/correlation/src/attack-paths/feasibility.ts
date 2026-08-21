/**
 * End-to-end path feasibility (B8) — [0,1], factoring in (a) each hop's own
 * confirmation confidence (`proofType`: `live` DAST-proven is the strongest
 * evidence tier the product has, `static` proof-only is weaker — mirrors the
 * same tier ordering `packages/contracts/src/blue-team.ts`'s `DetectionRule.
 * provenance` doc comment already relies on) and (b) the STRUCTURAL strength
 * of the condition connecting each hop (`./conditions.ts`'s
 * `ChainCondition.strength` — an RCE-enables-everything hop is far more
 * certain than a speculative SSRF-into-internal-space hop).
 *
 * The combination is a PRODUCT across every factor (chain reliability =
 * product of link reliabilities), not an average: a chain only holds if
 * EVERY hop and EVERY connecting condition holds, so one weak/speculative
 * link legitimately drags the whole path's score down. An average would let
 * one bogus speculative hop hide behind several strong ones — exactly the
 * "noise" failure mode the ranking exists to avoid.
 */
import type { ConfirmedFinding } from "@montr/contracts";
import { clamp01, round3 } from "../scoring.js";
import type { ChainCondition } from "./conditions.js";

const PROOF_CONFIDENCE: Record<ConfirmedFinding["proofType"], number> = {
  static: 0.7,
  live: 1,
};

/** Confidence weight of a single confirmed finding's own evidence tier. */
export function findingConfidence(f: ConfirmedFinding): number {
  return PROOF_CONFIDENCE[f.proofType];
}

/** Product of every hop's confirmation confidence × every connecting condition's structural strength. */
export function computeFeasibility(
  findings: readonly ConfirmedFinding[],
  conditions: readonly ChainCondition[],
): number {
  let score = 1;
  for (const f of findings) score *= findingConfidence(f);
  for (const c of conditions) score *= c.strength;
  return round3(clamp01(score));
}
