import type {
  LLMGateway,
  LLMRequest,
  LLMResponse,
  LLMStreamEvent,
  ModelDescriptor,
  ModelTier,
} from "@montr/contracts";
import {
  InMemoryPromptVersionRegistry,
  resolvePromptTemplate,
  type PromptVersionSource,
} from "@montr/llm-gateway";
import { createFakeLlmGateway } from "@montr/fixtures";
import { confirmedForRepoWithGateway } from "./real-confirmation-scanner.js";
import { scoreScanResults } from "./scorer.js";
import { evaluateBaseline, type Baseline, type RegressionResult } from "./baseline.js";
import type { LoadedCorpus } from "./corpus.js";
import type { CorpusScore, RepoScanResult } from "./types.js";

/**
 * E15 — eval-driven prompt optimization. Wires the prompt VERSION registry
 * (`@montr/llm-gateway`'s `PromptVersionSource` + `resolvePromptTemplate`,
 * extended additively for E15 with `resolvePromptVersionTemplate` /
 * `InMemoryPromptVersionRegistry`) to the golden-corpus scorer, so a
 * candidate prompt VERSION for a specific call site (e.g. Layer 3
 * confirmation's system prompt) can be A/B'd against the currently-active
 * version on real ground truth before it is ever promoted — closing A10's
 * "prompt registry has zero readers that change scan outcomes" gap one step
 * further: PRD §15's aspiration ("prompt tuning is measured, not vibes") made
 * real, mirroring `corpus/baseline.json`'s CI-gate shape but as a relative
 * A/B comparison instead of a fixed external floor.
 *
 * Scope, mirroring A23's `real-confirmation-scanner.ts` (the pattern this
 * module reuses): runs the REAL `@montr/confirm` static-confirmation engine,
 * unmodified, against the two `@montr/fixtures` sample repos that ship a
 * hand-built AppMap + ProbableFinding[] fixture today — the same scope
 * `realVarianceCorpus` narrows to. A caller passes that corpus in explicitly
 * (this module does no filesystem I/O of its own), exactly like
 * `runModelVariance`'s `ModelVarianceOptions.corpus`.
 *
 * Prompt-content sensitivity: `@montr/fixtures`' `FakeLlmAdapter` returns a
 * FIXED canned response per call purpose — it is intentionally NOT sensitive
 * to prompt text (a fake adapter cannot "read" an LLM prompt the way a real
 * model would). To make prompt VERSION actually change the scored outcome —
 * required for this harness to mean anything — {@link PromptEvalGateway}
 * below judges the RESOLVED system-prompt text against a small, explicit
 * {@link PromptQualityRubric} (keyword markers a rigorous confirmation review
 * prompt should carry) and picks the confirm/veto canned response
 * accordingly. This generalizes A23's `gatewayForModel` (which varies the
 * canned response by MODEL tier) to vary it by PROMPT VERSION instead — same
 * honest-offline-simulation convention, same
 * `createFakeLlmGateway({ cannedByPurpose })` building block, different axis.
 * It is not a stand-in for a real semantic prompt-quality judge (that needs a
 * real model call, which this offline gate deliberately does not make); it is
 * a deterministic, reproducible, and — per {@link DEFAULT_PROMPT_RUBRIC}'s doc
 * comment — REALITY-GROUNDED proxy sufficient to prove the wiring: a better
 * prompt version scores higher, a worse one scores lower, and the regression
 * gate below correctly promotes/rejects based on that.
 */

/** A prompt VERSION passes when it mentions at least this fraction of `requiredMarkers`. */
export interface PromptQualityRubric {
  /** Keyword markers a rigorous prompt should mention (case-insensitive substring match). */
  requiredMarkers: readonly string[];
  /** Fraction of `requiredMarkers` required to pass (default 1 — ALL of them, fail-safe). */
  minMarkerFraction?: number;
}

/**
 * Grounded in the REAL confirmation-review system prompt
 * (`packages/confirm/src/static.ts`'s `runLlmReview` hardcoded fallback,
 * "confirm.static_review.system"): "You are a security exploit-confirmation
 * reviewer. Judge exploitability conservatively from the static data-flow.
 * When uncertain, set confirmed=false." — every one of these three markers is
 * present in that real string, so the DEFAULT rubric scores TODAY'S active
 * production prompt as passing (a rubric that failed the status quo would be
 * useless for regression-gating candidates against it).
 */
export const DEFAULT_PROMPT_RUBRIC: PromptQualityRubric = {
  requiredMarkers: ["exploitab", "conservativ", "uncertain"],
};

/** Fraction of `rubric.requiredMarkers` present (case-insensitive substring) in `template`. */
export function scorePromptQuality(
  template: string,
  rubric: PromptQualityRubric = DEFAULT_PROMPT_RUBRIC,
): number {
  if (rubric.requiredMarkers.length === 0) return 1;
  const lower = template.toLowerCase();
  const hits = rubric.requiredMarkers.filter((m) => lower.includes(m.toLowerCase())).length;
  return hits / rubric.requiredMarkers.length;
}

/** Whether `template` meets `rubric`'s pass threshold (default: ALL markers present). */
export function promptMeetsRubric(
  template: string,
  rubric: PromptQualityRubric = DEFAULT_PROMPT_RUBRIC,
): boolean {
  const minFraction = rubric.minMarkerFraction ?? 1;
  return scorePromptQuality(template, rubric) >= minFraction - 1e-9;
}

const CONFIRM_CANNED =
  '{"confirmed":true,"argument":"static data-flow proof independently judged exploitable"}';
const VETO_CANNED =
  '{"confirmed":false,"argument":"insufficient confidence to confirm exploitability with this prompt version"}';

/**
 * A gateway that resolves `promptName` through a REAL `PromptVersionSource`
 * (`resolvePrompt`, identical to production's `gateway.resolvePrompt` call —
 * so `@montr/confirm`'s `runLlmReview`, unmodified, genuinely round-trips
 * through the registry exactly as it would in production) and judges the
 * resolved template against `rubric` to pick the confirmation-purpose canned
 * response. Every other purpose falls back to `@montr/fixtures`' standard
 * canned defaults (this harness only targets ONE call site's prompt).
 */
export class PromptEvalGateway implements LLMGateway {
  constructor(
    private readonly source: PromptVersionSource,
    private readonly promptName: string,
    private readonly systemFallback: string,
    private readonly rubric: PromptQualityRubric = DEFAULT_PROMPT_RUBRIC,
    private readonly clientId: string | null = null,
  ) {}

  resolveModel(tierOrId: ModelTier | string): ModelDescriptor {
    return createFakeLlmGateway().resolveModel(tierOrId);
  }

  listModels(): ModelDescriptor[] {
    return createFakeLlmGateway().listModels();
  }

  async resolvePrompt(
    name: string,
    fallback: string,
    opts: { clientId?: string | null } = {},
  ): Promise<string> {
    return resolvePromptTemplate(this.source, name, fallback, {
      clientId: opts.clientId ?? this.clientId,
    });
  }

  async complete(request: LLMRequest): Promise<LLMResponse> {
    if (request.metadata.purpose !== "confirmation") {
      return createFakeLlmGateway().complete(request);
    }
    const resolved = await this.resolvePrompt(this.promptName, this.systemFallback, {
      clientId: this.clientId,
    });
    const content = promptMeetsRubric(resolved, this.rubric) ? CONFIRM_CANNED : VETO_CANNED;
    return createFakeLlmGateway({ cannedByPurpose: { confirmation: content } }).complete(request);
  }

  async *stream(request: LLMRequest): AsyncGenerator<LLMStreamEvent, void, unknown> {
    const response = await this.complete(request);
    yield { type: "text_delta", text: response.content };
    yield { type: "message_done", usage: response.usage, stopReason: response.stopReason };
  }

  estimateTokens(request: LLMRequest): Promise<number> {
    // FakeLlmAdapter always implements this (LLMGateway declares it optional
    // only for gateways that genuinely can't offer it) — non-null assertion
    // is safe here, not a real possibility of undefined.
    return createFakeLlmGateway().estimateTokens!(request);
  }
}

/** One candidate-vs-active prompt evaluation input. */
export interface PromptEvalOptions {
  /** Prompt registry key, e.g. "confirm.static_review.system" (§8.2). */
  promptName: string;
  /** The hardcoded fallback the real call site passes to `resolvePrompt` — used identically here. */
  systemFallback: string;
  /** Today's active prompt text (the baseline to beat). */
  activeTemplate: string;
  /** The prompt version under evaluation. */
  candidateTemplate: string;
  /** Golden-corpus scope to score against (caller-supplied — no FS I/O here; see module header). */
  corpus: LoadedCorpus;
  rubric?: PromptQualityRubric;
  /**
   * Optional external regression floor. Default: a RELATIVE gate built from
   * the active version's OWN measured score on this corpus (the candidate
   * must not fall below what's live today) — mirrors
   * `corpus/baseline.json`/`evaluateBaseline`'s shape, but computed from the
   * live A/B run rather than a fixed committed file.
   */
  baseline?: Baseline;
  clientId?: string | null;
}

export interface PromptEvalScore {
  template: string;
  corpusScore: CorpusScore;
}

export interface PromptEvalResult {
  promptName: string;
  active: PromptEvalScore;
  candidate: PromptEvalScore;
  /** Candidate scored against a baseline derived from (or supplied for) the active version. */
  regression: RegressionResult;
  /** "promote" when the candidate does not regress the gate; "reject" otherwise. */
  verdict: "promote" | "reject";
  reasons: string[];
}

async function scoreVersion(corpus: LoadedCorpus, gateway: LLMGateway): Promise<CorpusScore> {
  const results: RepoScanResult[] = [];
  for (const repo of corpus.repos) {
    results.push({ repo: repo.name, confirmed: await confirmedForRepoWithGateway(repo, gateway) });
  }
  return scoreScanResults(results, corpus.manifest);
}

/**
 * A/B a candidate prompt VERSION against the currently-active version on the
 * golden corpus, and apply a regression gate (candidate must not score worse
 * than active). This is the CORE mechanism E15 asks for: a real call site
 * (`@montr/confirm`'s `runLlmReview`, unmodified) resolves its prompt through
 * the SAME `PromptVersionSource` seam production uses, run twice — once with
 * each version marked active in an isolated {@link InMemoryPromptVersionRegistry}
 * — and scored with the SAME scorer `corpus/baseline.json`'s CI gate uses.
 */
export async function evaluatePromptCandidate(opts: PromptEvalOptions): Promise<PromptEvalResult> {
  const rubric = opts.rubric ?? DEFAULT_PROMPT_RUBRIC;
  const clientId = opts.clientId ?? null;
  const registry = new InMemoryPromptVersionRegistry();
  const activeRow = registry.createVersion({
    name: opts.promptName,
    template: opts.activeTemplate,
    clientId,
  });
  const candidateRow = registry.createVersion({
    name: opts.promptName,
    template: opts.candidateTemplate,
    clientId,
  });

  registry.markActive(activeRow.id);
  const activeScore = await scoreVersion(
    opts.corpus,
    new PromptEvalGateway(registry, opts.promptName, opts.systemFallback, rubric, clientId),
  );

  registry.markActive(candidateRow.id);
  const candidateScore = await scoreVersion(
    opts.corpus,
    new PromptEvalGateway(registry, opts.promptName, opts.systemFallback, rubric, clientId),
  );

  const gateBaseline: Baseline = opts.baseline ?? {
    fpRateMax: activeScore.fpRate,
    precisionMin: activeScore.precision,
    recallMin: activeScore.recall,
  };
  const regression = evaluateBaseline(candidateScore, gateBaseline);
  const reasons = regression.violations.map(
    (v) =>
      `${v.scope}.${v.metric}: candidate ${v.actual} ${v.direction === "min" ? "<" : ">"} active's ${v.threshold}`,
  );

  return {
    promptName: opts.promptName,
    active: { template: opts.activeTemplate, corpusScore: activeScore },
    candidate: { template: opts.candidateTemplate, corpusScore: candidateScore },
    regression,
    verdict: regression.passed ? "promote" : "reject",
    reasons,
  };
}
