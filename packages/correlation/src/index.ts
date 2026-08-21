/**
 * @montr/correlation — Layer 2: THE MOAT (build-plan §5.3, PRD §7).
 *
 * Cross-references each Layer-1 candidate against the App Map (route existence,
 * auth/exposure, taint source→sink reachability with sanitizer interruption),
 * DEDUPLICATES multi-tool duplicates into one root cause (`mergedCandidateIds`),
 * RANKS by reachability × exposure × impact (not raw CVSS), and DEMOTES
 * uncorroborated candidates to an appendix — never deletes them. Emits
 * `ProbableFinding[]`, each with a reachability + exploit hypothesis.
 *
 * Deterministic-first: the App Map grounding is authoritative for existence,
 * exposure, and demotion; the LLM (via @montr/llm-gateway) only refines the
 * hypotheses and nudges ranking, grounded in that structure. Implementation: WS-G.
 */
export { correlate, type CorrelateInput } from "./correlate.js";

// §15 false-positive tuning hook — inject the regression corpus (from @montr/qa)
// to down-rank/demote known false positives. Additive + fail-safe.
export type { FalsePositiveTuning, FalsePositiveSignal } from "./tuning.js";

// Pure building blocks — exported for the orchestrator, tests, and future stacks
// (the engine is stack-agnostic by design, build-plan §7).
export { AppMapIndex, groundCandidate, extractPackageName, type Grounding } from "./grounding.js";
export { groupCandidates, type RootCauseGroup } from "./dedup.js";
export {
  scoreGrounding,
  combinedScore,
  reachabilityScoreFor,
  exposureScoreFor,
  impactScoreFor,
  clamp01,
  round3,
  type ScoreTriple,
} from "./scoring.js";
export { reachabilityHypothesis, exploitHypothesis } from "./hypotheses.js";
export {
  buildCorrelationFacts,
  buildCorrelationRequest,
  parseCorrelationResponse,
  blendScore,
  type CorrelationFacts,
  type ParsedCorrelation,
} from "./llm.js";
export {
  classifyCategory,
  humanize,
  CATEGORY_IMPACT_BASE,
  SEVERITY_WEIGHT,
  INJECTION_CATEGORIES,
  CONFIG_CATEGORIES,
  SECRET_CATEGORIES,
  DEPENDENCY_CATEGORIES,
  ACCESS_CATEGORIES,
  type FindingClass,
} from "./taxonomy.js";
export { fnv1a, makeRootCauseId, makeProbableId } from "./hash.js";

// B8 — attack-path graph across confirmed findings (kill-chain discovery).
// Operates on Layer 3's ConfirmedFinding[] output, not Layer 2's candidates —
// see ./attack-paths/index.ts for the full design rationale.
export * from "./attack-paths/index.js";
