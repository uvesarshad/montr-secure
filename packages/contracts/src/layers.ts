import { z } from "zod";
import { AppMapSchema } from "./appmap.js";
import { ScanScopeSchema } from "./scan.js";
import { CostEstimateSchema } from "./cost.js";
import {
  CandidateFindingSchema,
  ProbableFindingSchema,
  ConfirmedFindingSchema,
  UnconfirmedFindingSchema,
} from "./findings.js";
import { FixSchema, PullRequestSchema } from "./fix.js";
import { ReportSchema } from "./report.js";

/**
 * Layer I/O contracts (§3.2, §7). Each layer consumes the previous layer's
 * typed output and emits its own. Layers hand off ONLY via these shapes; no
 * layer reaches around the orchestrator (§8.1).
 */

/** Layer 0 — Intake & Scoping. */
export const Layer0OutputSchema = z.object({
  appMap: AppMapSchema,
  scope: ScanScopeSchema,
  costEstimate: CostEstimateSchema,
});
export type Layer0Output = z.infer<typeof Layer0OutputSchema>;

/** Layer 1 — Parallel Discovery (candidate pile; never surfaced to the user). */
export const Layer1OutputSchema = z.object({
  candidates: z.array(CandidateFindingSchema).default([]),
});
export type Layer1Output = z.infer<typeof Layer1OutputSchema>;

/** Layer 2 — Correlation (the moat). Demoted candidates are kept, not deleted. */
export const Layer2OutputSchema = z.object({
  probable: z.array(ProbableFindingSchema).default([]),
  demoted: z.array(CandidateFindingSchema).default([]),
});
export type Layer2Output = z.infer<typeof Layer2OutputSchema>;

/** Layer 3 — Exploit Confirmation (probable → confirmed; rest to the appendix). */
export const Layer3OutputSchema = z.object({
  confirmed: z.array(ConfirmedFindingSchema).default([]),
  unconfirmed: z.array(UnconfirmedFindingSchema).default([]),
});
export type Layer3Output = z.infer<typeof Layer3OutputSchema>;

/** Layer 4 — Fix Generation (confirmed findings only). */
export const Layer4OutputSchema = z.object({
  fixes: z.array(FixSchema).default([]),
});
export type Layer4Output = z.infer<typeof Layer4OutputSchema>;

/** Layer 5 — Human Gate & Output (report + gated PRs). */
export const Layer5OutputSchema = z.object({
  report: ReportSchema,
  pullRequests: z.array(PullRequestSchema).default([]),
});
export type Layer5Output = z.infer<typeof Layer5OutputSchema>;
