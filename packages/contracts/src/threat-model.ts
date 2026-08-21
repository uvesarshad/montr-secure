import { z } from "zod";
import { CategorySchema } from "./compliance.js";

/**
 * Threat model (E6 / B7) — derived from the App Map at the end of Layer 0, as a
 * SUB-STEP of Layer 0's own execution rather than a new pipeline layer (see
 * `packages/appmap/src/threat-model.ts`'s module doc for why: `LayerId` is a
 * closed six-member union threaded through `packages/contracts/src/queue.ts`'s
 * `QUEUE_NAMES`/job-data discriminated union, `packages/orchestrator/src/fsm.ts`'s
 * `LAYER_ORDER`, and every layer-keyed `Record<LayerId, ...>` in the codebase —
 * inserting a 7th id would touch all of those plus persistence/resume-token
 * shapes for a step that has no gate, no retry policy of its own, and no reason
 * to be independently resumable).
 *
 * E6's job is to make this DRIVE later-layer scoping (see `ScopeHintsSchema`
 * below); B7 (tracked separately) renders the same shape as a reviewable report
 * section — this type is intentionally shared so either consumer can use it
 * without re-deriving the analysis.
 */

/** A grouping of routes that share a trust level (PRD-shaped, App-Map-grounded). */
export const TrustBoundarySchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  /** Route paths (from `AppMap.routes[].path`) inside this boundary. */
  routePaths: z.array(z.string()).default([]),
});
export type TrustBoundary = z.infer<typeof TrustBoundarySchema>;

/** How plausible a category of vulnerability is, given this app's actual shape. */
export const SurfacePlausibilitySchema = z.enum(["none", "low", "medium", "high"]);
export type SurfacePlausibility = z.infer<typeof SurfacePlausibilitySchema>;

/**
 * One category's plausibility on THIS app, with a rationale grounded in
 * concrete App Map evidence (a taint sink kind, a data store kind, a route
 * count) — never a generic OWASP description. `plausibility: "none"` is a
 * narrow, deliberately rare verdict (see `ScopeHints.zeroSurfaceCategories`).
 */
export const AttackSurfaceEntrySchema = z.object({
  category: CategorySchema,
  plausibility: SurfacePlausibilitySchema,
  rationale: z.string().min(1),
});
export type AttackSurfaceEntry = z.infer<typeof AttackSurfaceEntrySchema>;

/** A concrete, App-Map-grounded abuse-case scenario (not generic boilerplate). */
export const AbuseCaseSchema = z.object({
  title: z.string().min(1),
  description: z.string().min(1),
  /** Route paths this scenario concerns, if any (must exist in `AppMap.routes`). */
  routePaths: z.array(z.string()).default([]),
  categories: z.array(CategorySchema).default([]),
});
export type AbuseCase = z.infer<typeof AbuseCaseSchema>;

/** One category to prioritize, with why. */
export const PriorityCategoryHintSchema = z.object({
  category: CategorySchema,
  rationale: z.string().min(1),
});
export type PriorityCategoryHint = z.infer<typeof PriorityCategoryHintSchema>;

/**
 * Scope hints derived from the threat model — the mechanism that actually
 * DRIVES Layer 1/Layer 3 (E6). ⛔ PRIORITIZATION / FOCUS ONLY: consumers use
 * this to order/annotate work, never to skip a detector or drop a candidate
 * that would otherwise run. `zeroSurfaceCategories` is the one narrow, opt-in
 * exception (documented at each field) — it never causes a consumer to
 * actually skip a check in this change; today it is advisory-only (surfaced as
 * metadata for a future report/UI de-emphasis), so recall can never regress
 * because of a hint being wrong.
 */
export const ScopeHintsSchema = z.object({
  /** Categories worth the deepest investigation first, ordered highest-signal-first. */
  priorityCategories: z.array(PriorityCategoryHintSchema).default([]),
  /** Route paths with the sharpest risk signal (e.g. ORM fan-out behind weak auth). */
  priorityRoutePaths: z.array(z.string()).default([]),
  /**
   * Categories the App Map's structural shape makes implausible (e.g. no
   * `deserialize`-kind taint sink anywhere ⇒ near-zero `insecure_deserialization`
   * surface). Advisory only — see the schema doc above; a consumer MAY use this
   * to de-emphasize in a report, but MUST NOT use it to skip a scan category.
   */
  zeroSurfaceCategories: z.array(CategorySchema).default([]),
});
export type ScopeHints = z.infer<typeof ScopeHintsSchema>;

/**
 * The full threat-model analysis for one scan's App Map (E6/B7). Optional on
 * `AppMap` — see `AppMapSchema.threatModel`'s doc comment for the same
 * in-memory-only persistence caveat A18's `Route.referencedModels` documents.
 */
export const ThreatModelSchema = z.object({
  trustBoundaries: z.array(TrustBoundarySchema).default([]),
  attackSurface: z.array(AttackSurfaceEntrySchema).default([]),
  abuseCases: z.array(AbuseCaseSchema).default([]),
  scopeHints: ScopeHintsSchema,
  /** True iff the LLM was actually invoked and contributed to this result. */
  generatedByLlm: z.boolean().default(false),
});
export type ThreatModel = z.infer<typeof ThreatModelSchema>;
