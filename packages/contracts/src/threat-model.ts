import { z } from "zod";
import { CategorySchema, type Category } from "./compliance.js";

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

/**
 * STRIDE (B7): the six Microsoft threat-modeling categories — Spoofing,
 * Tampering, Repudiation, Information disclosure, Denial of service,
 * Elevation of privilege. Applied per trust boundary and per attack-surface
 * category below, always grounded in real App Map evidence (never a
 * boilerplate six-for-six dump — see {@link CATEGORY_TO_STRIDE}'s doc comment
 * and `packages/appmap/src/threat-model.ts`'s per-boundary derivation).
 */
export const StrideCategorySchema = z.enum([
  "spoofing",
  "tampering",
  "repudiation",
  "information_disclosure",
  "denial_of_service",
  "elevation_of_privilege",
]);
export type StrideCategory = z.infer<typeof StrideCategorySchema>;

export const STRIDE_LABELS: Record<StrideCategory, string> = {
  spoofing: "Spoofing",
  tampering: "Tampering",
  repudiation: "Repudiation",
  information_disclosure: "Information Disclosure",
  denial_of_service: "Denial of Service",
  elevation_of_privilege: "Elevation of Privilege",
};

/**
 * One STRIDE category that genuinely applies to a trust boundary, with a
 * rationale grounded in concrete App Map evidence (which routes, which ORM
 * model, which auth state) — the same "never generic" discipline as
 * {@link AttackSurfaceEntrySchema.shape.rationale}.
 */
export const StrideFindingSchema = z.object({
  category: StrideCategorySchema,
  rationale: z.string().min(1),
});
export type StrideFinding = z.infer<typeof StrideFindingSchema>;

/** A grouping of routes that share a trust level (PRD-shaped, App-Map-grounded). */
export const TrustBoundarySchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  /** Route paths (from `AppMap.routes[].path`) inside this boundary. */
  routePaths: z.array(z.string()).default([]),
  /**
   * STRIDE categories that genuinely apply to THIS boundary (B7), e.g. a
   * public/unresolved-auth boundary whose routes write an ORM model gets
   * Tampering + Elevation of Privilege + Repudiation; a boundary behind
   * resolved authentication with no write fan-out gets `[]` — precision over
   * a mechanical six-for-six dump. See
   * `packages/appmap/src/threat-model.ts`'s `buildTrustBoundaries`.
   */
  stride: z.array(StrideFindingSchema).default([]),
});
export type TrustBoundary = z.infer<typeof TrustBoundarySchema>;

/** How plausible a category of vulnerability is, given this app's actual shape. */
export const SurfacePlausibilitySchema = z.enum(["none", "low", "medium", "high"]);
export type SurfacePlausibility = z.infer<typeof SurfacePlausibilitySchema>;

/**
 * Category -> STRIDE categories that genuinely apply when a finding of this
 * category is plausible on this app (B7). Exhaustive over `Category` (a
 * `Record`, not a partial map) so a newly added `Category` cannot silently
 * ship with no STRIDE classification — the compiler enforces coverage.
 * `other` intentionally maps to `[]`: it is a catch-all bucket with no
 * consistent STRIDE shape, so mapping it to anything would be a guess, not a
 * grounded classification.
 */
export const CATEGORY_TO_STRIDE: Record<Category, readonly StrideCategory[]> = {
  sql_injection: ["tampering", "information_disclosure"],
  nosql_injection: ["tampering", "information_disclosure"],
  command_injection: ["tampering", "elevation_of_privilege"],
  xss: ["spoofing", "tampering", "information_disclosure"],
  ssrf: ["information_disclosure", "elevation_of_privilege"],
  path_traversal: ["information_disclosure", "tampering"],
  insecure_deserialization: ["tampering", "elevation_of_privilege"],
  hardcoded_secret: ["information_disclosure", "elevation_of_privilege"],
  vulnerable_dependency: ["tampering", "elevation_of_privilege"],
  permissive_cors: ["information_disclosure", "tampering"],
  missing_security_headers: ["information_disclosure", "tampering"],
  insecure_cookie: ["spoofing", "information_disclosure"],
  weak_crypto: ["information_disclosure", "tampering"],
  broken_access_control: ["elevation_of_privilege", "information_disclosure"],
  broken_authentication: ["spoofing", "elevation_of_privilege"],
  open_redirect: ["spoofing"],
  xxe: ["information_disclosure", "denial_of_service"],
  csrf: ["spoofing", "tampering"],
  sensitive_data_exposure: ["information_disclosure"],
  insufficient_logging: ["repudiation"],
  idor: ["elevation_of_privilege", "information_disclosure"],
  mass_assignment: ["tampering", "elevation_of_privilege"],
  rate_limit_missing: ["denial_of_service"],
  prompt_injection: ["tampering", "elevation_of_privilege"],
  insecure_configuration: ["tampering", "elevation_of_privilege", "information_disclosure"],
  other: [],
};

/**
 * STRIDE categories for a finding category, suppressed to `[]` when
 * `plausibility` is `"none"` — the same precision discipline `ScopeHints`
 * already applies: a category the App Map's own structural shape rules out
 * (e.g. no deserialize sink anywhere) must never surface a STRIDE tag either.
 */
export function strideForCategory(
  category: Category,
  plausibility: SurfacePlausibility,
): StrideCategory[] {
  return plausibility === "none" ? [] : [...CATEGORY_TO_STRIDE[category]];
}

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
  /** STRIDE categories this entry maps to (B7) — see {@link strideForCategory}. */
  stride: z.array(StrideCategorySchema).default([]),
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
