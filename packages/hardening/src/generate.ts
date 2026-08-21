/**
 * `generateHardeningRecommendations` — the single entry point of this
 * package. Runs all seven category detectors against a real App Map +
 * repo checkout (via `FileProvider`) + optional confirmed findings, and
 * assembles the drafts into real, schema-validated `HardeningRecommendation`
 * rows (`@montr/contracts`'s `HardeningRecommendationSchema`).
 *
 * ⛔ Architectural boundary (B9, load-bearing — see this package's index.ts
 * module doc): this module has NO auto-apply capability. It never imports
 * `@montr/fix`, never produces a diff/patch, and never assigns a
 * `RiskClass`. Every recommendation is advisory-only by construction — see
 * `HardeningRecommendationSchema`'s doc comment in `@montr/contracts`.
 */
import {
  HardeningRecommendationSchema,
  type ConfirmedFinding,
  type AppMap,
  type HardeningRecommendation,
} from "@montr/contracts";
import type { FileProvider } from "@montr/discovery";
import { detectSecurityHeaderGaps } from "./categories/security-headers.js";
import { detectCspGap } from "./categories/csp.js";
import { detectCookiePolicyGaps } from "./categories/cookie-policy.js";
import { detectRateLimitGaps } from "./categories/rate-limits.js";
import { detectWafRuleRecommendations } from "./categories/waf-rules.js";
import { detectNetworkPolicyGaps } from "./categories/network-policy.js";
import { detectFrameworkConfigurationGaps } from "./categories/framework-configuration.js";
import { hardeningId } from "./id.js";
import type { RecommendationDraft } from "./types.js";

export interface GenerateHardeningRecommendationsInput {
  appMap: AppMap;
  files: FileProvider;
  confirmedFindings?: readonly ConfirmedFinding[];
  /** Injectable for deterministic tests; defaults to the real current time. */
  now?: () => string;
}

export async function generateHardeningRecommendations(
  input: GenerateHardeningRecommendationsInput,
): Promise<HardeningRecommendation[]> {
  const { appMap, files } = input;
  const confirmedFindings = input.confirmedFindings ?? [];
  const now = input.now ?? (() => new Date().toISOString());

  const { drafts: securityHeaderDrafts, signals } = await detectSecurityHeaderGaps(appMap, files);

  const drafts: RecommendationDraft[] = [
    ...securityHeaderDrafts,
    ...(await detectCspGap(appMap, files)),
    ...(await detectCookiePolicyGaps(files)),
    ...(await detectRateLimitGaps(appMap, files, confirmedFindings)),
    ...detectWafRuleRecommendations(confirmedFindings),
    ...(await detectNetworkPolicyGaps(files, confirmedFindings)),
    ...(await detectFrameworkConfigurationGaps(appMap, files, {
      helmetDetected: signals.helmetDetected,
    })),
  ];

  const createdAt = now();
  return drafts.map((draft) => {
    const recommendation: HardeningRecommendation = {
      id: hardeningId(draft),
      category: draft.category,
      severity: draft.severity,
      title: draft.title,
      gap: draft.gap,
      recommendation: draft.recommendation,
      rationale: draft.rationale,
      evidence: draft.evidence,
      framework: draft.framework,
      relatedFindingIds: draft.relatedFindingIds ?? [],
      createdAt,
    };
    // Validates the assembled row against the real schema rather than trusting
    // each detector's shape by construction — a malformed draft fails loudly
    // here instead of silently reaching a caller.
    return HardeningRecommendationSchema.parse(recommendation);
  });
}
