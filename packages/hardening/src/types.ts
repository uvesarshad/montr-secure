import type { Framework, HardeningCategory, Severity } from "@montr/contracts";

/**
 * Everything a category detector needs to produce, before `generate.ts`
 * stamps an `id`/`createdAt` and turns it into a real
 * `HardeningRecommendation` (see `@montr/contracts`'s `hardening.ts`).
 * Deliberately has no `id`/`createdAt` field — those are assignment
 * concerns of the orchestrator, not of a single category detector.
 */
export interface RecommendationDraft {
  category: HardeningCategory;
  severity: Severity;
  title: string;
  gap: string;
  recommendation: string;
  rationale: string;
  /** Concrete, repo-grounded signals. Must be non-empty (enforced by the schema at assembly time). */
  evidence: string[];
  framework?: Framework;
  relatedFindingIds?: string[];
}
