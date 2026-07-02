import type {
  CandidateFinding,
  Category,
  ConfirmedFinding,
  LayerId,
  ProbableFinding,
  UnconfirmedFinding,
} from "@montr/contracts";

/**
 * Per-layer metric reporting helpers (build-plan §4.7 / §10, PRD §15):
 * "findings in/out, demotion rate, confirmation rate". These summarise how the
 * pipeline narrows the deliberately over-inclusive Layer-1 pile down to the
 * headline confirmed findings — the core signal that the moat (Layer 2/3) works.
 *
 * Counts only. Never emits code/secret bodies (golden rule #1) — inputs are
 * contract-typed findings and we read only their categories/ids.
 */

export interface LayerFlow {
  layer: LayerId;
  /** Findings entering the layer (0 for Layer 1, which produces the initial pile). */
  in: number;
  /** Findings emitted by the layer (excludes items demoted to an appendix). */
  out: number;
  /** Findings this layer demoted to an appendix (kept, never deleted — §7 L2/L3). */
  demoted: number;
}

export interface LayerCategoryMetric {
  category: Category;
  candidates: number;
  probable: number;
  confirmed: number;
  unconfirmed: number;
}

export interface PipelineMetricsInput {
  candidates?: readonly CandidateFinding[];
  probable?: readonly ProbableFinding[];
  /** Candidates demoted at Layer 2 (correlation) — kept in the appendix. */
  demoted?: readonly CandidateFinding[];
  confirmed?: readonly ConfirmedFinding[];
  unconfirmed?: readonly UnconfirmedFinding[];
}

export interface PipelineMetrics {
  candidates: number;
  probable: number;
  demotedCandidates: number;
  confirmed: number;
  unconfirmed: number;
  /** Layer-2 consolidation: 1 - probable/candidates (higher = more dedup/narrowing). */
  dedupRate: number;
  /** Layer-3 confirmation: confirmed / (confirmed + unconfirmed). */
  confirmationRate: number;
  /** Layer-3 demotion: unconfirmed / (confirmed + unconfirmed) — probable → appendix. */
  demotionRate: number;
  flows: LayerFlow[];
  perCategory: LayerCategoryMetric[];
}

function rate(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

/** Compute per-layer metrics from whatever layer outputs are available. */
export function computePipelineMetrics(input: PipelineMetricsInput): PipelineMetrics {
  const candidates = input.candidates?.length ?? 0;
  const probable = input.probable?.length ?? 0;
  const demotedCandidates = input.demoted?.length ?? 0;
  const confirmed = input.confirmed?.length ?? 0;
  const unconfirmed = input.unconfirmed?.length ?? 0;
  const l3Input = confirmed + unconfirmed;

  const perCategory = new Map<Category, LayerCategoryMetric>();
  const ensure = (category: Category): LayerCategoryMetric => {
    let m = perCategory.get(category);
    if (!m) {
      m = { category, candidates: 0, probable: 0, confirmed: 0, unconfirmed: 0 };
      perCategory.set(category, m);
    }
    return m;
  };
  for (const c of input.candidates ?? []) ensure(c.category).candidates++;
  for (const p of input.probable ?? []) ensure(p.category).probable++;
  for (const c of input.confirmed ?? []) ensure(c.category).confirmed++;
  for (const u of input.unconfirmed ?? []) ensure(u.category).unconfirmed++;

  const flows: LayerFlow[] = [
    { layer: "layer1", in: 0, out: candidates, demoted: 0 },
    { layer: "layer2", in: candidates, out: probable, demoted: demotedCandidates },
    { layer: "layer3", in: l3Input, out: confirmed, demoted: unconfirmed },
  ];

  return {
    candidates,
    probable,
    demotedCandidates,
    confirmed,
    unconfirmed,
    dedupRate: candidates > 0 ? Math.max(0, 1 - probable / candidates) : 0,
    confirmationRate: rate(confirmed, l3Input),
    demotionRate: rate(unconfirmed, l3Input),
    flows,
    perCategory: [...perCategory.values()].sort((a, b) => a.category.localeCompare(b.category)),
  };
}
