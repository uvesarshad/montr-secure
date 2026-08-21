/**
 * @montr/hardening — B9: blue-team CONFIG/INFRA hardening recommendations.
 * Security headers, CSP, cookie policy, rate limits, WAF rules, network
 * policy, and framework configuration.
 *
 * ⛔ ARCHITECTURAL BOUNDARY (load-bearing, not a style choice): this package
 * is genuinely SEPARATE from `packages/fix` (Layer 4 code-fix generation),
 * not a new fix "type" flagged differently inside it. It does not import
 * `@montr/fix` anywhere — not `packages/fix/src/risk.ts`'s risk classifier,
 * not `packages/fix/src/generate.ts`'s patch synthesis, nothing. A
 * `HardeningRecommendation` (see `@montr/contracts`'s `hardening.ts`) carries
 * no `RiskClass`, no unified diff, and no PR-eligibility field — there is
 * nothing here for an auto-apply path to even key off. Every recommendation
 * this package produces is advisory-only, surfaced to a human operator, and
 * NEVER auto-applied, in contrast to Layer 4's auto-eligible code fixes
 * (missing security headers, strict cookie attributes, simple dependency
 * bumps — see `packages/fix/src/risk.ts`'s `AUTO_ELIGIBLE_CATEGORIES`),
 * which CAN be opened as an automated pull request for low-risk categories.
 * `tests/boundary.test.ts` in this package asserts this by construction: it
 * greps this package's own source for any `@montr/fix` import and for any
 * `riskClass`/diff-shaped field, and fails if either ever appears.
 *
 * Every recommendation is grounded in a real, detected gap — a missing
 * dependency, a missing cookie attribute, an absent CSP header, a confirmed
 * finding's category — never a boilerplate checklist emitted regardless of
 * what is actually present. See `./categories/*.ts` for the seven detectors,
 * each documenting exactly which signals it checks and which App Map /
 * `@montr/discovery` (import/dependency detection, IaC manifest scanning)
 * infrastructure it reuses, read-only.
 *
 * NOT wired into `packages/report/src/report-builder.ts` yet — that is B10's
 * job in a later wave. `./render.ts` renders a standalone Markdown section
 * that B10 can drop in without touching this package.
 */
export {
  generateHardeningRecommendations,
  type GenerateHardeningRecommendationsInput,
} from "./generate.js";
export { renderHardeningRecommendationsMarkdown } from "./render.js";
export type { RecommendationDraft } from "./types.js";
export { hardeningId } from "./id.js";

export { detectSecurityHeaderGaps } from "./categories/security-headers.js";
export { detectCspGap } from "./categories/csp.js";
export { detectCookiePolicyGaps } from "./categories/cookie-policy.js";
export { detectRateLimitGaps } from "./categories/rate-limits.js";
export { detectWafRuleRecommendations } from "./categories/waf-rules.js";
export { detectNetworkPolicyGaps } from "./categories/network-policy.js";
export { detectFrameworkConfigurationGaps } from "./categories/framework-configuration.js";

export {
  detectAnyDependency,
  findFilesByBasename,
  readAllSource,
  matches,
  lineOfFirstMatch,
  type DependencySignal,
} from "./detect.js";
