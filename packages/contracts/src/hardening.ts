import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { SeveritySchema, FrameworkSchema } from "./enums.js";

/**
 * Hardening recommendations (B9) — blue-team CONFIG/INFRA outputs, not code
 * patches. This is a deliberately DIFFERENT capability from Layer 4 fix
 * generation (`@montr/fix`, see packages/fix/src/risk.ts): a
 * `HardeningRecommendation` is advisory-only and is NEVER auto-applied,
 * whereas Layer 4's `Fix` rows carry a `RiskClass` that can permit an
 * automated pull request for low-risk code categories. That distinction is a
 * safety boundary, not a style choice — see `packages/hardening`'s module doc
 * (the standalone generator package that produces this type) for the full
 * architectural-separation rationale. This schema itself carries no
 * auto-apply-related field (no `riskClass`, no diff/patch body) precisely so
 * nothing downstream can mistake a recommendation for a fix.
 *
 * Covers seven categories: security headers, Content-Security-Policy, cookie
 * policy, rate limits, WAF rules, network policy, and framework
 * configuration. Every recommendation must be grounded in a real detected gap
 * (an absent header, an unimported rate-limiter, a missing cookie attribute,
 * ...) — see `HardeningRecommendationSchema.evidence`, which is intentionally
 * `.min(1)`: a recommendation with no cited evidence is not allowed to exist.
 */

export const HardeningCategorySchema = z.enum([
  "security_headers",
  "csp",
  "cookie_policy",
  "rate_limits",
  "waf_rules",
  "network_policy",
  "framework_configuration",
]);
export type HardeningCategory = z.infer<typeof HardeningCategorySchema>;

/**
 * One advisory hardening recommendation. `evidence` names the concrete,
 * repo-grounded signal(s) that justified generating this entry (a file path,
 * a detected/missing dependency, a route, a confirmed finding id, a cookie
 * name, ...) — never a boilerplate justification. `relatedFindingIds`
 * optionally ties a recommendation (typically `waf_rules` or
 * `network_policy`) back to the specific `ConfirmedFinding.id`(s) that
 * grounded it (see ./findings.ts); empty when the recommendation was derived
 * purely from App Map / dependency signals with no specific finding behind
 * it (e.g. a missing security-headers dependency).
 *
 * `id`/`createdAt` mirror B1's persisted-entity shape so a future persistence
 * layer (B10+) can adopt this type unchanged, but `clientId`/`scanId` are
 * deliberately NOT included here — this schema is produced by a pure,
 * scan-context-free generator (`@montr/hardening`) and gains scan/tenant
 * scoping only when a caller persists it, exactly like `CandidateFinding`'s
 * own id is assigned before its `scanId` is known.
 */
export const HardeningRecommendationSchema = z.object({
  id: IdSchema,
  category: HardeningCategorySchema,
  severity: SeveritySchema,
  title: z.string().min(1),
  /** The specific, repo-grounded gap this recommendation closes. */
  gap: z.string().min(1),
  /** The concrete config/snippet to apply (framework-idiomatic, not boilerplate prose). */
  recommendation: z.string().min(1),
  /** Why this matters (impact if left unaddressed). */
  rationale: z.string().min(1),
  /** Concrete, repo-grounded signals that justified this entry. Never empty. */
  evidence: z.array(z.string().min(1)).min(1),
  /** The detected framework this recommendation targets, when category-relevant. */
  framework: FrameworkSchema.optional(),
  /** `ConfirmedFinding.id`(s) this recommendation defends against, when applicable. */
  relatedFindingIds: z.array(IdSchema).default([]),
  createdAt: IsoDateTimeSchema,
});
export type HardeningRecommendation = z.infer<typeof HardeningRecommendationSchema>;
