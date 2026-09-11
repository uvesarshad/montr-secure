/**
 * Layer 2 — Correlation, THE MOAT (build-plan §5.3, PRD §7). Cross-references
 * every candidate against the App Map, DEDUPLICATES multi-tool duplicates into
 * one root cause, RANKS by reachability × exposure × impact (not raw CVSS), and
 * DEMOTES uncorroborated candidates to an appendix — never deletes them. Emits
 * ProbableFinding[] each with a reachability + exploit hypothesis.
 *
 * Deterministic-first (golden rule #6): the App Map grounding decides existence,
 * exposure, and demotion. The LLM (via @montr/llm-gateway) only refines the
 * hypotheses and nudges ranking, grounded in that structure. No LLM call fires
 * before the App Map exists; every promotion/demotion/LLM call is audit-logged
 * with metadata only (golden rule #1).
 */
import {
  Layer2OutputSchema,
  ProbableFindingSchema,
  type AppMap,
  type AuditEventInput,
  type CandidateFinding,
  type Layer2Output,
  type LLMGateway,
  type ProbableFinding,
} from "@montr/contracts";
import {
  createNullLogger,
  getMetrics,
  type AuditLogClient,
  type Logger,
  type MontrMetrics,
} from "@montr/telemetry";
import type { SemanticMatch } from "@montr/semantic-index";
import { AppMapIndex } from "./grounding.js";
import { groupCandidates, type RootCauseGroup } from "./dedup.js";
import { round3, scoreGrounding, type ScoreTriple } from "./scoring.js";
import { exploitHypothesis, reachabilityHypothesis } from "./hypotheses.js";
import { SEVERITY_WEIGHT } from "./taxonomy.js";
import { makeProbableId, makeRootCauseId } from "./hash.js";
import {
  blendScore,
  buildCorrelationFacts,
  buildCorrelationRequest,
  parseCorrelationResponse,
} from "./llm.js";
import type { FalsePositiveTuning } from "./tuning.js";
import type { PriorConfirmedShapes } from "./prior-shapes.js";

/** A9 — semantic-code-search callback (`@montr/semantic-index`'s `querySemanticIndex`), injected structurally — see `CorrelateInput.semanticSearch`'s doc comment. */
export type SemanticSearchFn = (queryText: string, topK?: number) => Promise<SemanticMatch[]>;

const DEFAULT_LLM_TRUST = 0.5;
const DEFAULT_LLM_MAX_DELTA = 0.2;
const CORRELATION_ACTOR = "layer2-correlation";

export interface CorrelateInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  candidates: CandidateFinding[];
  /** LLM gateway for semantic reasoning. Omit to run deterministic-only. */
  gateway?: LLMGateway;
  /** Audit sink — when provided, every promotion/demotion/LLM call is logged. */
  audit?: AuditLogClient;
  /** Metrics collector (defaults to the process-wide one). */
  metrics?: MontrMetrics;
  logger?: Logger;
  /** ISO timestamp stamped on emitted findings (tests inject a fixed value). */
  now?: string;
  /** Use the gateway when present (default true). */
  useLlm?: boolean;
  /** Trust placed in the LLM's score nudge, [0,1] (default 0.5). */
  llmScoreTrust?: number;
  /** Max absolute delta the LLM may nudge a score (default 0.2). */
  llmScoreMaxDelta?: number;
  /** Audit actor id (default "layer2-correlation"). */
  actorId?: string;
  /**
   * ⛔ §15 regression-corpus tuning (fail-safe). When supplied, a candidate whose
   * (category, file, line) matches an operator-marked known false positive is
   * DEMOTED to the appendix (kept, never deleted) instead of promoted. Additive:
   * omit to run without corpus feedback. Never promotes; never relaxes a guardrail.
   */
  fpTuning?: FalsePositiveTuning;
  /**
   * A9 — optional semantic-code-search callback (`@montr/semantic-index`'s
   * `querySemanticIndex`, injected structurally — this package never imports
   * `@montr/llm-gateway`/`@montr/state-store`'s embeddings/pgvector
   * machinery directly, mirroring `ConfirmDeps.semanticSearch`'s convention
   * in `@montr/confirm`). When supplied, a promoted candidate's own evidence
   * snippet is used to retrieve structurally/semantically similar code
   * elsewhere in the repo; when that surfaces a genuinely different location,
   * a plain-language, PURELY INFORMATIONAL sentence naming it is appended to
   * the finding's reachability hypothesis — grounding a candidate against
   * similar code, per the audit's own framing. Deliberately never feeds into
   * `scoring.ts`'s numeric reachability/exposure/impact formula: that formula
   * is calibrated against the golden corpus (see taxonomy.ts's AGENT NOTE on
   * `CATEGORY_IMPACT_BASE`) and semantic similarity is not a corpus-validated
   * scoring signal. Degrades SILENTLY on any error (no pgvector, no
   * embeddings-capable provider key, timeout, zero matches) — an unavailable
   * or failing index can never fail or slow down a scan's actual scoring, and
   * never demotes/promotes a finding on its own.
   */
  semanticSearch?: SemanticSearchFn;
  /**
   * E8 extension — optional confirmed-exploit-shape priors (learned-facts
   * mechanism, `packages/state-store/src/learned-facts.ts`'s
   * `confirmed_exploit_shape` type, recorded automatically by
   * `apps/worker/src/runners.ts`'s `recordConfirmedExploitShapes` whenever
   * Layer 3 genuinely confirms a finding on real proof). When a promoted
   * candidate's (category, location) structurally matches a shape this repo
   * has confirmed exploitable before, a short, factual, PURELY INFORMATIONAL
   * sentence is appended to the finding's reachability hypothesis, and the
   * candidate is listed first among any findings otherwise perfectly tied on
   * every corpus-calibrated score (see `comparePending`) — see
   * `./prior-shapes.ts`'s header comment for the full, narrow contract.
   * Deliberately never feeds `scoring.ts`'s numeric reachability/exposure/
   * impact formula, mirroring `semanticSearch`'s identical precedent above
   * and for the identical reason (golden-corpus calibration). Absent (every
   * existing caller/test) ⇒ byte-identical to before this feature — a repo
   * scanned for the first time has no learned facts yet, so this is a no-op
   * the first time regardless.
   */
  priorConfirmedShapes?: PriorConfirmedShapes;
}

/** Cap on semantic-search matches surfaced per candidate — informational only, never a scoring input. */
const SEMANTIC_GROUNDING_TOP_K = 3;
/** Below this cosine similarity, a match is too weak to be worth citing in a hypothesis. */
const SEMANTIC_GROUNDING_MIN_SIMILARITY = 0.75;

/**
 * A9 — best-effort semantic grounding: retrieve code elsewhere in the repo
 * structurally/semantically similar to this candidate's own evidence, and
 * render a short, factual sentence naming the strongest OTHER locations
 * found (excluding the candidate's own file, which trivially "matches
 * itself"). Returns `undefined` on any error or when nothing distinct and
 * similar enough was found — the caller appends it only when present, so a
 * disabled/unavailable/quiet index changes nothing about the hypothesis text.
 */
async function semanticGroundingNote(
  semanticSearch: SemanticSearchFn,
  rep: CandidateFinding,
  logger: Logger,
): Promise<string | undefined> {
  const queryText = rep.evidenceSnippet?.trim() || `${rep.category} at ${rep.location.file}`;
  let matches: SemanticMatch[];
  try {
    matches = await semanticSearch(queryText, SEMANTIC_GROUNDING_TOP_K);
  } catch (err) {
    logger.warn("correlation.semantic_search.failed", {
      message: err instanceof Error ? err.message : "unknown",
    });
    return undefined;
  }
  const elsewhere = matches.filter(
    (m) => m.similarity >= SEMANTIC_GROUNDING_MIN_SIMILARITY && m.file !== rep.location.file,
  );
  if (elsewhere.length === 0) return undefined;
  const cites = elsewhere
    .map((m) => `${m.file}:${m.startLine}${m.symbolName ? ` (${m.symbolName})` : ""}`)
    .join(", ");
  return (
    ` A semantic search over the repository's code index found structurally similar code at ` +
    `${cites} — worth checking whether the same pattern recurs there.`
  );
}

interface PendingProbable {
  build: (rank: number) => ProbableFinding;
  combined: number;
  impact: number;
  reach: number;
  severity: number;
  category: string;
  rootCauseId: string;
  /** E8 extension — see `comparePending`'s doc comment. Rank-tie-break only,
   * never a component of `combined`/`impact`/`reach` above. */
  priorShapeMatched: boolean;
}

/**
 * Run Layer-2 correlation. Pure with respect to inputs (no global state beyond
 * the optional shared metrics); deterministic given the same App Map, candidates,
 * gateway, and `now`.
 */
export async function correlate(input: CorrelateInput): Promise<Layer2Output> {
  const { clientId, scanId, appMap, candidates } = input;
  // Golden rule #6: nothing (least of all an LLM call) happens without the map.
  if (!appMap || !appMap.id) {
    throw new Error("correlate: an App Map is required before correlation can run");
  }

  const metrics = input.metrics ?? getMetrics();
  const logger = input.logger ?? createNullLogger();
  const useLlm = (input.useLlm ?? true) && input.gateway !== undefined;
  const trust = clampUnit(input.llmScoreTrust ?? DEFAULT_LLM_TRUST);
  const maxDelta = clampUnit(input.llmScoreMaxDelta ?? DEFAULT_LLM_MAX_DELTA);
  const now = input.now ?? new Date().toISOString();
  const actor = { type: "agent" as const, id: input.actorId ?? CORRELATION_ACTOR };

  metrics.recordFindingsIn("layer2", candidates.length);

  const index = new AppMapIndex(appMap);
  const groups = groupCandidates(candidates, index);

  const pending: PendingProbable[] = [];
  const demotedCandidates: CandidateFinding[] = [];
  const demotedAudits: AuditEventInput[] = [];

  for (const group of groups) {
    const { grounding: g, representative: rep } = group;

    // ⛔ §15 FP loop: an operator-marked known false positive is demoted to the
    // appendix (kept, never deleted) before promotion — fail-safe, additive.
    const knownFalsePositive =
      input.fpTuning?.isKnownFalsePositive({
        category: rep.category,
        file: rep.location.file,
        line: rep.location.line,
        ...(rep.ruleId ? { ruleId: rep.ruleId } : {}),
      }) ?? false;

    if (g.demote || knownFalsePositive) {
      // Never delete — keep every raw candidate in the appendix.
      for (const c of group.candidates) demotedCandidates.push(c);
      const reason = knownFalsePositive
        ? g.demote
          ? `${g.demoteReason ?? "uncorroborated"}; also matches a known false positive in the regression corpus (§15)`
          : "matches a known false positive in the regression corpus (§15)"
        : (g.demoteReason ?? "uncorroborated by the App Map");
      if (input.audit) {
        demotedAudits.push({
          clientId,
          scanId,
          actor,
          action: "finding.demoted",
          targetType: "candidate",
          summary: `${rep.category} demoted: ${reason}`,
          metadata: {
            category: rep.category,
            reason,
            knownFalsePositive,
            corroborationBasis: g.corroborationBasis,
            candidateIds: group.candidates.map((c) => c.id),
          },
        });
      }
      continue;
    }

    const base = scoreGrounding(rep, g);
    let reach = base.reachabilityScore;
    let impact = base.impactScore;
    const exposureScore = base.exposureScore;
    let reachHypo = reachabilityHypothesis(rep, g);
    let exploitHypo = exploitHypothesis(rep, g, appMap);

    if (useLlm && input.gateway) {
      const enriched = await runLlmEnrichment({
        gateway: input.gateway,
        rep,
        members: group.candidates,
        grounding: g,
        base: { ...base, reachabilityHypothesis: reachHypo, exploitHypothesis: exploitHypo },
        scanId,
        clientId,
        metrics,
        audit: input.audit,
        actor,
        logger,
        trust,
        maxDelta,
      });
      reach = enriched.reach;
      impact = enriched.impact;
      reachHypo = enriched.reachHypothesis;
      exploitHypo = enriched.exploitHypothesis;
    }

    // A9 — best-effort semantic grounding (informational only — see
    // `CorrelateInput.semanticSearch`'s doc comment; never touches reach/
    // impact/exposure). Runs after LLM enrichment so the note is appended to
    // whichever hypothesis text is final for this candidate.
    if (input.semanticSearch) {
      const note = await semanticGroundingNote(input.semanticSearch, rep, logger);
      if (note) reachHypo = `${reachHypo}${note}`;
    }

    // E8 extension — informational-only confirmed-exploit-shape prior (see
    // `CorrelateInput.priorConfirmedShapes`'s doc comment). Never touches
    // reach/impact/exposureScore; only the hypothesis text and, below, the
    // rank tie-break order.
    const priorShapeMatched =
      input.priorConfirmedShapes?.matches({ category: rep.category, file: rep.location.file }) ??
      false;
    if (priorShapeMatched) {
      reachHypo =
        `${reachHypo} A structurally similar ${rep.category} finding elsewhere in this ` +
        "repository was confirmed exploitable in an earlier scan — treat this as a " +
        "stronger-than-usual candidate worth prioritizing (informational prior; verify independently).";
    }

    const rootCauseId = makeRootCauseId(scanId, rep.category, group.key);
    const id = makeProbableId(scanId, rootCauseId);
    const mergedCandidateIds = group.candidates.map((c) => c.id);
    const combined = reach * exposureScore * impact;

    pending.push({
      combined,
      impact,
      reach,
      severity: SEVERITY_WEIGHT[rep.rawSeverity],
      category: rep.category,
      rootCauseId,
      priorShapeMatched,
      build: (rank: number): ProbableFinding =>
        ProbableFindingSchema.parse({
          id,
          scanId,
          clientId,
          rootCauseId,
          category: rep.category,
          mergedCandidateIds,
          reachabilityHypothesis: reachHypo,
          exploitHypothesis: exploitHypo,
          exposure: g.exposure,
          ...(g.authGate ? { authGate: g.authGate } : {}),
          ...(g.routeId ? { routeId: g.routeId } : {}),
          location: rep.location,
          reachabilityScore: round3(reach),
          exposureScore: round3(exposureScore),
          impactScore: round3(impact),
          rank,
          status: "probable",
          createdAt: now,
        }),
    });
  }

  // Rank by reachability × exposure × impact, with deterministic tie-breaks.
  pending.sort(comparePending);
  const probable = pending.map((p, i) => p.build(i + 1));

  // --- Metrics.
  metrics.recordFindingsOut("layer2", probable.length);
  if (demotedCandidates.length > 0) metrics.recordDemotion(demotedCandidates.length);
  metrics.observeDemotionRatio(candidates.length, demotedCandidates.length);

  // --- Audit (metadata only, never code bodies).
  if (input.audit) {
    for (const p of probable) {
      await input.audit.append({
        clientId,
        scanId,
        actor,
        action: "finding.promoted_probable",
        targetType: "finding",
        targetId: p.id,
        summary: `${p.category} promoted to probable (rank ${p.rank})`,
        metadata: {
          category: p.category,
          rank: p.rank,
          exposure: p.exposure,
          reachabilityScore: p.reachabilityScore,
          exposureScore: p.exposureScore,
          impactScore: p.impactScore,
          mergedCandidateIds: p.mergedCandidateIds,
        },
      });
    }
    for (const event of demotedAudits) await input.audit.append(event);
  }

  logger.info("correlation.done", {
    scanId,
    candidatesIn: candidates.length,
    probableOut: probable.length,
    demoted: demotedCandidates.length,
    llmUsed: useLlm,
  });

  return Layer2OutputSchema.parse({ probable, demoted: demotedCandidates });
}

interface LlmEnrichmentArgs {
  gateway: LLMGateway;
  rep: CandidateFinding;
  members: CandidateFinding[];
  grounding: RootCauseGroup["grounding"];
  base: ScoreTriple & { reachabilityHypothesis: string; exploitHypothesis: string };
  scanId: string;
  clientId: string;
  metrics: MontrMetrics;
  audit?: AuditLogClient;
  actor: { type: "agent"; id: string };
  logger: Logger;
  trust: number;
  maxDelta: number;
}

interface LlmEnrichmentResult {
  reach: number;
  impact: number;
  reachHypothesis: string;
  exploitHypothesis: string;
}

/** One correlation LLM call, with fail-safe fallback to the deterministic base. */
async function runLlmEnrichment(args: LlmEnrichmentArgs): Promise<LlmEnrichmentResult> {
  const { base } = args;
  const fallback: LlmEnrichmentResult = {
    reach: base.reachabilityScore,
    impact: base.impactScore,
    reachHypothesis: base.reachabilityHypothesis,
    exploitHypothesis: base.exploitHypothesis,
  };

  try {
    const facts = buildCorrelationFacts(args.rep, args.members, args.grounding, base);
    const request = buildCorrelationRequest(facts, {
      scanId: args.scanId,
      clientId: args.clientId,
    });
    // Prompt registry (§8.2, §15): resolve the DB-versioned template for this
    // prompt name when one is active; otherwise the hardcoded SYSTEM_PROMPT
    // from llm.ts (resolvePrompt's `fallback` arg) is used unchanged.
    if (request.system) {
      request.system =
        (await args.gateway.resolvePrompt?.("correlation.system", request.system, {
          clientId: args.clientId,
        })) ?? request.system;
    }
    const response = await args.gateway.complete(request);
    args.metrics.recordLlmCall({ purpose: "correlation" });

    if (args.audit) {
      await args.audit.append({
        clientId: args.clientId,
        scanId: args.scanId,
        actor: args.actor,
        action: "llm.call",
        targetType: "finding",
        summary: "correlation reasoning (metadata only)",
        // Metadata ONLY — never the prompt or any code body (golden rule #1).
        metadata: {
          purpose: "correlation",
          model: response.model,
          provider: response.provider,
          inputTokens: response.usage.inputTokens,
          outputTokens: response.usage.outputTokens,
          latencyMs: response.latencyMs,
        },
      });
    }

    const parsed = parseCorrelationResponse(response.content);
    if (!parsed) return fallback;
    return {
      reach: blendScore(
        base.reachabilityScore,
        parsed.reachabilityScore,
        args.trust,
        args.maxDelta,
      ),
      impact: blendScore(base.impactScore, parsed.impactScore, args.trust, args.maxDelta),
      reachHypothesis: parsed.reachabilityHypothesis ?? base.reachabilityHypothesis,
      exploitHypothesis: parsed.exploitHypothesis ?? base.exploitHypothesis,
    };
  } catch (err) {
    // Uncertainty resolves toward the deterministic result (golden rule #4).
    args.logger.warn("correlation.llm_failed", {
      scanId: args.scanId,
      error: err instanceof Error ? err.message : String(err),
    });
    return fallback;
  }
}

function comparePending(a: PendingProbable, b: PendingProbable): number {
  if (b.combined !== a.combined) return b.combined - a.combined;
  if (b.impact !== a.impact) return b.impact - a.impact;
  if (b.reach !== a.reach) return b.reach - a.reach;
  if (b.severity !== a.severity) return b.severity - a.severity;
  // E8 extension: applied strictly AFTER every corpus-calibrated score above
  // — only breaks a tie between findings otherwise perfectly equal on all
  // four. Never changes reachabilityScore/exposureScore/impactScore, only
  // which of two equally-scored findings is listed first.
  if (a.priorShapeMatched !== b.priorShapeMatched) return a.priorShapeMatched ? -1 : 1;
  if (a.category !== b.category) return a.category < b.category ? -1 : 1;
  return a.rootCauseId < b.rootCauseId ? -1 : a.rootCauseId > b.rootCauseId ? 1 : 0;
}

function clampUnit(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(1, Math.max(0, n));
}
