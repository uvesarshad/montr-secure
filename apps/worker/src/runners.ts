/**
 * apps/worker — the six orchestrator `LayerRunner` adapters (build-plan §8.1,
 * Wave-2 carry-over 6–8).
 *
 * Each adapter converts the orchestrator's `LayerContext<L>` into the layer's
 * NATIVE input (drawn from `ctx.priorOutputs` in-process, falling back to the
 * durable state store on a resumed/distributed run), invokes the layer's PURE
 * function, and returns that function's output — which already IS the exact
 * `@montr/contracts` `Layer*Output`. The layers close over the shared
 * `@montr/llm-gateway`; the `LayerContext` deliberately hands NO gateway to
 * layers, so the gateway is injected here.
 *
 * ⛔ Persistence division of labour (honored to avoid double-writes): the pure
 * layer functions NEVER write finding/fix rows — `orchestrator/persist.ts` owns
 * every store write. So we call `runDiscovery` (not `runDiscoveryToStore`) and
 * `createLayer0Runner({ persist: false })` (its default). The `audit` sink we
 * pass to the layers records append-only metadata events (golden rule #7), which
 * is a different concern from the entity persistence the orchestrator owns.
 */
import {
  MontrError,
  type AppMap,
  type CandidateFinding,
  type ConfirmedFinding,
  type CostEstimate,
  type HardeningRecommendation,
  type LLMGateway,
  type LLMPurpose,
  type PurpleTeamScenarioSummaryEntryShape,
  type RedTeamScenario,
} from "@montr/contracts";
import type { CostMeter } from "@montr/cost-meter";
import { buildCostRollup } from "@montr/cost-meter";
import type { LayerContext, LayerRunners } from "@montr/orchestrator";
import type { FalsePositiveMarkSignal, LearnedFact } from "@montr/state-store";

import { createLayer0Runner, persistDetectionCoverageForScan } from "@montr/appmap";
import {
  fsFileProvider,
  runDiscovery,
  type DiscoveryDeps,
  type GitleaksRunner,
  type SemgrepRunner,
} from "@montr/discovery";
import { correlate } from "@montr/correlation";
import {
  confirmFindings,
  defaultTransport,
  REDTEAM_CATEGORY_TO_FINDING_CATEGORIES,
  summarizePurpleTeamRun,
  verifyScenarioDetection,
  type ConfirmDeps,
  type ConfirmInput,
  type PurpleTeamRunEntry,
} from "@montr/confirm";
import {
  createFsSourceReader,
  createMapSourceReader,
  generateFixes,
  type SourceReader,
} from "@montr/fix";
import { generateHardeningRecommendations } from "@montr/hardening";
import { buildReport, generateDetectionRules, type PullRequestOpener } from "@montr/report";
import type { EmbeddingProviderAdapter } from "@montr/llm-gateway";
import type { CodeChunkRepository } from "@montr/state-store";
import { buildSemanticIndex, querySemanticIndex } from "@montr/semantic-index";

/* ------------------------------- options ------------------------------- */

/** Injectable seams shared by the layer adapters. */
export interface LayerRunnerOptions {
  /** ⛔ The one LLM egress path (golden rule #2). Injected into every LLM-using layer. */
  gateway: LLMGateway;
  /** Root for Layer-0 sandboxed clones of remote repos (temp dir by default). */
  workspaceRoot?: string;
  /**
   * Resolve the checked-out repo root for a scan — used by Layer 1 (real
   * Semgrep/gitleaks/SCA scanners) and Layer 4 (on-disk source for patch
   * generation). Default: the scan's `repo` when it is a LOCAL path (a mounted
   * checkout), else `undefined` (remote clones are cleaned up by Layer 0, so
   * discovery degrades to empty + a warning and fixes fall back to advisory —
   * fail-safe). Override to point at a shared workspace.
   */
  resolveRepoRoot?: (ctx: LayerContext) => string | undefined;
  /** Override the Layer-4 source reader (else fs-at-repoRoot, else empty map). */
  sourceReader?: (ctx: LayerContext<"layer4">) => SourceReader;
  /** ⛔ Auto-fix PR opener (Layer 5). Absent ⇒ pure path, NO PRs opened. */
  opener?: PullRequestOpener;
  /** Base branch auto-fix PRs target (Layer 5). Defaults per the report layer. */
  baseBranch?: string;
  /** Injectable Semgrep runner (Layer 1). Default shells out to the binary. */
  semgrep?: SemgrepRunner;
  /** Injectable gitleaks runner (Layer 1). Default shells out to the binary. */
  gitleaks?: GitleaksRunner;
  /** Deterministic ISO clock (tests). Default: layer wall-clock. */
  now?: () => string;
  /**
   * A9 — semantic codebase index (`@montr/semantic-index`). Absent (default)
   * ⇒ no index is built in Layer 0 and Layer 3's investigation loop gets no
   * `semanticSearch` capability — today's behavior, unchanged. Present ⇒
   * Layer 0 builds the index alongside the App Map (best-effort, see
   * `packages/appmap/src/build.ts`'s `semanticIndex` hook — any failure, e.g.
   * a missing `pgvector` extension, is logged and swallowed, never fails the
   * scan) and Layer 3 gets a real `semanticSearch` callback wired into
   * `ConfirmDeps`. Constructed in `apps/worker/src/main.ts`, gated on
   * `config.semanticIndex.enabled` AND the configured `llm.provider` having a
   * real embeddings adapter (`azure`/`openai` today).
   */
  semanticIndex?: {
    embeddingAdapter: EmbeddingProviderAdapter;
    embeddingModel: string;
    codeChunkRepository: CodeChunkRepository;
    /** Passed through to `buildSemanticIndex`'s `batchSize`. Optional. */
    batchSize?: number;
  };
}

/* ------------------------------- helpers ------------------------------- */

/** Same heuristic Layer 0 uses to tell a remote URL from a local path. */
function isRemoteRepo(repo: string): boolean {
  return /^(https?|git|ssh):\/\//i.test(repo) || /^git@[^:]+:/.test(repo) || repo.endsWith(".git");
}

function defaultRepoRoot(ctx: LayerContext): string | undefined {
  const repo = ctx.scan.repo;
  return repo && !isRemoteRepo(repo) ? repo : undefined;
}

/**
 * The App Map is Layer 0's output. Prefer the in-process cache; otherwise read
 * the persisted map by id (resume/distributed path). Throwing here fails the
 * layer loudly rather than running correlation/confirmation on nothing.
 */
async function resolveAppMap(ctx: LayerContext): Promise<AppMap> {
  const cached = ctx.priorOutputs.layer0?.appMap;
  if (cached) return cached;
  const jobAppMapId = (ctx.job as { appMapId?: string }).appMapId;
  const id = ctx.scan.appMapId ?? jobAppMapId;
  if (id) {
    const persisted = await ctx.store.appMaps.get(ctx.clientId, id);
    if (persisted) return persisted;
  }
  throw new MontrError("INTERNAL", `${ctx.job.layer}: App Map not found for scan ${ctx.scanId}`);
}

/** Cost estimate is stamped onto the scan when Layer 0 is persisted. */
function resolveEstimate(ctx: LayerContext): CostEstimate {
  const estimate = ctx.scan.costEstimate ?? ctx.priorOutputs.layer0?.costEstimate;
  if (!estimate) {
    throw new MontrError("INTERNAL", `layer5: cost estimate unavailable for scan ${ctx.scanId}`);
  }
  return estimate;
}

/** Post-scan actuals for the report rollup; never let a meter hiccup fail L5. */
function safeActual(meter: CostMeter): ReturnType<CostMeter["actual"]> | undefined {
  try {
    return meter.actual();
  } catch {
    return undefined;
  }
}

/** Dedupe candidates by id (demoted ⊆ the L1 pile, so this collapses overlaps). */
function dedupeCandidates(candidates: CandidateFinding[]): CandidateFinding[] {
  const byId = new Map<string, CandidateFinding>();
  for (const c of candidates) if (!byId.has(c.id)) byId.set(c.id, c);
  return [...byId.values()];
}

function defaultSourceReader(opts: LayerRunnerOptions, ctx: LayerContext<"layer4">): SourceReader {
  const root = (opts.resolveRepoRoot ?? defaultRepoRoot)(ctx);
  return root ? createFsSourceReader(root) : createMapSourceReader({});
}

/**
 * §15 FP-feedback tuning loop (A10). Loads this client's prior operator
 * false-positive marks (persisted via the audit log — `store.falsePositiveMarks`
 * reads back `finding.marked_false_positive` events, see
 * packages/state-store/src/repositories.ts's FalsePositiveMarkRepositoryImpl)
 * and wraps them in the `isKnownFalsePositive` seam both
 * @montr/correlation's `CorrelateInput.fpTuning` and @montr/confirm's
 * `ConfirmDeps.fpTuning` accept (structurally-identical interfaces, see each
 * package's tuning.ts). Fail-safe: a store hiccup here degrades to "no prior
 * FP marks", never blocks the layer.
 */
async function loadFpTuning(ctx: LayerContext): Promise<{
  isKnownFalsePositive(signal: {
    category: string;
    file: string;
    line: number;
    ruleId?: string;
  }): boolean;
}> {
  let marks: FalsePositiveMarkSignal[] = [];
  try {
    marks = await ctx.store.falsePositiveMarks.listByClient(ctx.clientId);
  } catch (err) {
    ctx.logger?.warn?.("worker.fp_tuning.load_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
  }
  return {
    isKnownFalsePositive(signal) {
      return marks.some(
        (m) =>
          m.category === signal.category &&
          m.file === signal.file &&
          m.line === signal.line &&
          (m.ruleId === undefined || m.ruleId === signal.ruleId),
      );
    },
  };
}

/* --------------------- §15 cross-scan memory (E8) --------------------- */

/**
 * Purposes whose prompts may receive this repo's accumulated learned-fact
 * context — exactly Layer 1 (triage), Layer 2 (correlation), and Layer 3
 * (confirmation), per E8's own scope. Layer 0 (`appmap_labeling`) and Layer 4
 * (`fix_generation`) are deliberately excluded.
 */
const LEARNED_FACT_INJECTABLE_PURPOSES = new Set<LLMPurpose>([
  "triage",
  "correlation",
  "confirmation",
]);

/**
 * Caps the TOTAL number of learned-fact + FP-mark lines appended to a
 * prompt's context, so an old, heavily-annotated repo can never blow the
 * token budget. Deliberately small and constant: this is orienting context
 * for the model, not a data dump. N=10 keeps the appended block comfortably
 * under roughly 500 tokens even at each line's max clipped length (~220
 * chars) — negligible next to correlation/confirmation's 2048/4096-token
 * output caps (A8) and nowhere near the smallest real context window (200k).
 */
const LEARNED_FACT_CONTEXT_LIMIT = 10;

/** Render one persisted {@link LearnedFact} as a single context line, clipped
 * to keep any one fact from dominating the bounded block. */
function formatLearnedFact(fact: LearnedFact): string {
  const kind = fact.type.replace(/_/g, " ");
  const detail = Object.entries(fact.content)
    .slice(0, 5)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(", ");
  const clipped = detail.length > 200 ? `${detail.slice(0, 200)}…` : detail;
  return `- [${kind}] ${clipped}`;
}

/** Render one prior operator FP mark (A10 data, reused — never duplicated
 * into the LearnedFact table, see LearnedFactType's schema doc comment) as a
 * context line. */
function formatFpMarkAsContext(mark: FalsePositiveMarkSignal): string {
  const rule = mark.ruleId ? ` (rule ${mark.ruleId})` : "";
  return (
    `- [confirmed false positive] ${mark.category} at ${mark.file}:${mark.line}${rule} — ` +
    "an operator previously confirmed this exact finding-shape is not a real vulnerability."
  );
}

/**
 * §15 cross-scan memory (E8) — the READ/injection path. Loads this client's
 * repo-scoped learned facts (custom sanitizers, framework idioms, operator
 * decisions — packages/state-store/src/learned-facts.ts) plus this client's
 * prior FP marks (A10's `falsePositiveMarks`, client-scoped — reused here as
 * the `confirmed_false_positive` fact class rather than duplicated into the
 * new table), formatted as ONE bounded, additive context block. Returns
 * `undefined` when there is nothing to say, so a repo scanned for the first
 * time (or a client store with nothing recorded) produces a byte-identical
 * prompt to before this change (regression safety). Fail-safe: a store
 * hiccup here degrades to "no context", never blocks the layer — mirrors
 * {@link loadFpTuning}.
 */
async function loadLearnedFactsContext(
  ctx: LayerContext,
  repo: string,
): Promise<string | undefined> {
  let facts: LearnedFact[] = [];
  try {
    facts = await ctx.store.learnedFacts.listByRepo(ctx.clientId, repo, LEARNED_FACT_CONTEXT_LIMIT);
  } catch (err) {
    ctx.logger?.warn?.("worker.learned_facts.load_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
  }
  let fpMarks: FalsePositiveMarkSignal[] = [];
  try {
    fpMarks = await ctx.store.falsePositiveMarks.listByClient(ctx.clientId);
  } catch {
    // loadFpTuning already warns on this failure path when it runs in the
    // same layer (L2/L3) — avoid a duplicate log line here.
  }

  const factLines = facts.map(formatLearnedFact);
  // Repo-scoped, dated LearnedFact rows are prioritized over the coarser,
  // client-wide FP-mark signal (FalsePositiveMarkRepository has no repo
  // scoping, by A10's own design — see that repository's doc comment): FP
  // marks only fill whatever of the shared budget the repo-specific facts
  // didn't use, never crowd them out.
  const remaining = Math.max(0, LEARNED_FACT_CONTEXT_LIMIT - factLines.length);
  const fpLines = fpMarks.slice(0, remaining).map(formatFpMarkAsContext);

  const lines = [...factLines, ...fpLines];
  if (lines.length === 0) return undefined;

  return [
    "Prior knowledge about this repository from earlier scans (additive context " +
      "only — verify independently; never treat as a substitute for your own analysis):",
    ...lines,
  ].join("\n");
}

/**
 * Wrap a gateway so Layer 1/2/3 prompts (see
 * {@link LEARNED_FACT_INJECTABLE_PURPOSES}) get this scan's client+repo
 * learned-fact context appended to their system prompt — ADDITIVELY: the
 * resolved template (A10's `resolvePrompt`, already run by each real call
 * site before `complete()` is invoked) is never replaced, only extended, and
 * a request for a different client or a non-injectable purpose passes through
 * completely unchanged. This never touches confirm/correlate/discovery
 * logic — it is never allowed to suppress or override a finding on its own
 * (golden rule #4); it only gives the model more context to reason with.
 *
 * `packages/correlation/src/**`, `packages/confirm/src/**`, and
 * `packages/discovery/src/triage.ts` are out of this change's file scope, so
 * injection happens at the ONE seam every real LLM call already funnels
 * through — the gateway itself — rather than editing those three modules'
 * prompt-building code directly. A future change WITH access to those files
 * could instead thread a typed `learnedFactsContext?: string` field through
 * `CorrelateInput`/`ConfirmDeps`/discovery's triage deps and append it inside
 * each module's own prompt builder (e.g. right where each already appends
 * `fpTuning`-derived context) — functionally equivalent, just closer to the
 * source; documented here as the alternative wiring point.
 *
 * The context is computed AT MOST ONCE per wrapped gateway (memoized), not
 * once per `complete()` call, since a layer may issue several LLM calls
 * against the same scan+repo (e.g. discovery's triage runs per candidate).
 */
function withLearnedFactsContext(gateway: LLMGateway, ctx: LayerContext, repo: string): LLMGateway {
  let contextPromise: Promise<string | undefined> | undefined;
  const getContext = (): Promise<string | undefined> => {
    if (!contextPromise) contextPromise = loadLearnedFactsContext(ctx, repo);
    return contextPromise;
  };

  const wrapped: LLMGateway = {
    listModels: () => gateway.listModels(),
    resolveModel: (tierOrId) => gateway.resolveModel(tierOrId),
    async complete(request) {
      if (
        !LEARNED_FACT_INJECTABLE_PURPOSES.has(request.metadata.purpose) ||
        request.metadata.clientId !== ctx.clientId
      ) {
        return gateway.complete(request);
      }
      const context = await getContext();
      if (!context) return gateway.complete(request);
      return gateway.complete({
        ...request,
        system: request.system ? `${request.system}\n\n${context}` : context,
      });
    },
    // stream() is deliberately NOT intercepted — no real layer calls it today
    // (A10's documented unconsumed seam); adding untested surface here would
    // be speculative.
    stream: (request) => gateway.stream(request),
  };
  if (gateway.estimateTokens) {
    const estimate = gateway.estimateTokens.bind(gateway);
    wrapped.estimateTokens = (request) => estimate(request);
  }
  if (gateway.resolvePrompt) {
    const resolve = gateway.resolvePrompt.bind(gateway);
    wrapped.resolvePrompt = (name, fallback, resolveOpts) => resolve(name, fallback, resolveOpts);
  }
  return wrapped;
}

/* --------------------- A8 purple-team verification loop --------------------- */

/**
 * Category-based scenario selection (A8) — mirrors
 * `packages/qa/src/blue-team-corpus.ts`'s own hand-traced "which scenario
 * verifies which finding category" pattern, generalized into a runtime rule:
 * the first ENABLED scenario in the client's real catalogue whose coarse
 * `RedTeamCategory` maps (via `@montr/confirm`'s
 * `REDTEAM_CATEGORY_TO_FINDING_CATEGORIES`) to the finding's category. No
 * match ⇒ `undefined` — a finding with no corresponding scenario is simply
 * skipped, never assigned an arbitrary one.
 */
function selectScenarioForFinding(
  scenarios: readonly RedTeamScenario[],
  finding: ConfirmedFinding,
): RedTeamScenario | undefined {
  return scenarios.find((s) =>
    REDTEAM_CATEGORY_TO_FINDING_CATEGORIES[s.category]?.includes(finding.category),
  );
}

/**
 * A8 — wires `packages/confirm/src/purple-loop.ts`'s purple-team verification
 * loop into the pipeline. Runs at Layer 3 (not Layer 5) because it needs the
 * SAME approver-gated live-DAST authorization (`ctx.job.allowLive` /
 * `ctx.job.stagingUrl`) that this layer's own live confirmation path already
 * uses — `Layer5JobData` carries no such field, so Layer 5 has no legitimate
 * authorization signal to run a live scenario against. Reuses the identical
 * gated call shape `purple-loop.ts` demonstrates (`assertScenarioAuthorized`
 * + `ScopeGuard`, via `runScenario`) and the SAME real transport Layer 3's
 * own live-DAST probing uses (`@montr/confirm`'s exported `defaultTransport`)
 * — no new egress path.
 *
 * Skipped entirely when `allowLive` is false: a scenario run with no
 * transport-worthy authorization only ever produces an empty transcript,
 * which would score every candidate rule "undetected" and misleadingly read
 * as a real detection gap rather than "never actually run". Best-effort per
 * (finding, scenario) pair — a guardrail refusal or store hiccup for one pair
 * is logged and skipped, never aborts confirmation for the rest of the scan.
 */
async function runPurpleTeamVerification(
  ctx: LayerContext<"layer3">,
  opts: LayerRunnerOptions,
  appMap: AppMap,
  confirmed: readonly ConfirmedFinding[],
): Promise<PurpleTeamScenarioSummaryEntryShape[]> {
  if (!ctx.job.allowLive || confirmed.length === 0) return [];

  let scenarios: RedTeamScenario[] = [];
  try {
    scenarios = (await ctx.store.redTeamScenarios.list(ctx.clientId)).filter((s) => s.enabled);
  } catch (err) {
    ctx.logger?.warn?.("worker.purple_team.scenario_list_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
  if (scenarios.length === 0) return [];

  const transport = await defaultTransport();
  const entries: PurpleTeamRunEntry[] = [];

  for (const finding of confirmed) {
    const scenario = selectScenarioForFinding(scenarios, finding);
    if (!scenario) continue;
    try {
      // Rules generated in-memory here (pure) purely to give the loop
      // candidate `DetectionRule`s to evaluate the transcript against —
      // mirrors the SAME generation `buildBlueTeamReport` performs at Layer
      // 5 (packages/report/src/report-builder.ts), never persisted here.
      const rules = generateDetectionRules(finding, {
        appMap,
        ...(opts.now ? { now: opts.now } : {}),
      });
      const verified = await verifyScenarioDetection(
        ctx.store,
        ctx.clientId,
        {
          scenario,
          finding,
          config: ctx.config,
          allowLive: ctx.job.allowLive,
          ...(ctx.job.stagingUrl !== undefined ? { targetOverride: ctx.job.stagingUrl } : {}),
        },
        {
          transport,
          detectionRules: rules,
          signal: ctx.signal,
          logger: ctx.logger,
          ...(opts.now ? { now: opts.now } : {}),
        },
      );
      entries.push({ scenario, finding, result: verified.scenarioResult });
    } catch (err) {
      ctx.logger?.warn?.("worker.purple_team.verification_failed", {
        scenarioId: scenario.id,
        findingId: finding.id,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return summarizePurpleTeamRun(ctx.scanId, entries).entries;
}

/* ------------------------------- runners ------------------------------- */

/**
 * Build the full set of orchestrator layer runners wired to the REAL layer
 * functions. The orchestrator drives them; `orchestrator/persist.ts` persists
 * their outputs. Every runner is pure w.r.t. store writes (see the file header).
 */
export function createLayerRunners(opts: LayerRunnerOptions): LayerRunners {
  const semanticIndexOpts = opts.semanticIndex;
  const layer0Runner = createLayer0Runner({
    gateway: opts.gateway,
    ...(opts.workspaceRoot ? { workspaceRoot: opts.workspaceRoot } : {}),
    // persist:false (default) — the orchestrator owns store.appMaps.create.
    // A9 — best-effort semantic-index build hook, threaded straight through
    // to packages/appmap/src/build.ts's `semanticIndex` dep (structural, see
    // that file's doc comment for why @montr/appmap cannot import
    // @montr/semantic-index directly). Absent unless `opts.semanticIndex` was
    // constructed in apps/worker/src/main.ts (config-gated, off by default).
    ...(semanticIndexOpts
      ? {
          semanticIndex: (input: {
            dir: string;
            clientId: string;
            appMapId: string;
            repo: string;
            commitSha: string;
          }) =>
            buildSemanticIndex({
              dir: input.dir,
              clientId: input.clientId,
              appMapId: input.appMapId,
              repo: input.repo,
              commitSha: input.commitSha,
              embeddingAdapter: semanticIndexOpts.embeddingAdapter,
              embeddingModel: semanticIndexOpts.embeddingModel,
              repository: semanticIndexOpts.codeChunkRepository,
              ...(semanticIndexOpts.batchSize ? { batchSize: semanticIndexOpts.batchSize } : {}),
            }),
        }
      : {}),
  });

  return {
    // L0 — Intake & Scoping. Reuses the appmap adapter (structurally compatible).
    layer0: (ctx) => layer0Runner(ctx),

    // L1 — Parallel Discovery. Input: App Map + scope. Emits the candidate pile.
    layer1: async (ctx) => {
      const appMap = await resolveAppMap(ctx);
      const repoRoot = (opts.resolveRepoRoot ?? defaultRepoRoot)(ctx);
      // §15 cross-scan memory (E8): this client+repo's accumulated learned
      // facts are appended as additive context to discovery's triage prompt
      // (purpose "triage") — see withLearnedFactsContext.
      const deps: DiscoveryDeps = {
        logger: ctx.logger,
        signal: ctx.signal,
        gateway: withLearnedFactsContext(opts.gateway, ctx, ctx.scan.repo),
        ...(opts.semgrep ? { semgrep: opts.semgrep } : {}),
        ...(opts.gitleaks ? { gitleaks: opts.gitleaks } : {}),
        ...(opts.now ? { now: opts.now } : {}),
      };
      return runDiscovery({
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        appMap,
        scope: ctx.scan.scope,
        config: ctx.config,
        ...(repoRoot ? { repoRoot } : {}),
        deps,
      });
    },

    // L2 — Correlation (THE MOAT). Input: App Map + candidates. Emits probable.
    layer2: async (ctx) => {
      const appMap = await resolveAppMap(ctx);
      const candidates =
        ctx.priorOutputs.layer1?.candidates ??
        (await ctx.store.candidates.listByScan(ctx.clientId, ctx.scanId));
      // §15 FP-feedback loop (A10): prior operator FP marks for this client
      // down-rank a repeat of the same finding-shape — see loadFpTuning.
      const fpTuning = await loadFpTuning(ctx);
      // §15 cross-scan memory (E8): additive learned-fact context on top of
      // correlation's prompt (purpose "correlation") — see withLearnedFactsContext.
      return correlate({
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        appMap,
        candidates,
        gateway: withLearnedFactsContext(opts.gateway, ctx, ctx.scan.repo),
        audit: ctx.store.audit,
        logger: ctx.logger,
        fpTuning,
        // A9 — best-effort semantic grounding (informational hypothesis text
        // only — see CorrelateInput.semanticSearch's doc comment). Absent
        // unless `opts.semanticIndex` was constructed (config-gated, off by
        // default).
        ...(semanticIndexOpts
          ? {
              semanticSearch: (queryText: string, topK?: number) =>
                querySemanticIndex({
                  queryText,
                  clientId: ctx.clientId,
                  repo: appMap.repo,
                  commitSha: appMap.commitSha,
                  ...(topK ? { topK } : {}),
                  embeddingAdapter: semanticIndexOpts.embeddingAdapter,
                  embeddingModel: semanticIndexOpts.embeddingModel,
                  repository: semanticIndexOpts.codeChunkRepository,
                }),
            }
          : {}),
        ...(opts.now ? { now: opts.now() } : {}),
      });
    },

    // L3 — Exploit Confirmation. Input: App Map + probable. Emits confirmed + unconfirmed.
    layer3: async (ctx) => {
      const appMap = await resolveAppMap(ctx);
      const probable =
        ctx.priorOutputs.layer2?.probable ??
        (await ctx.store.probable.listByScan(ctx.clientId, ctx.scanId));
      const input: ConfirmInput = {
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        appMap,
        probable,
        // ⛔ Live-DAST toggle + target are the orchestrator's approver-gated job
        // fields; the layer independently re-enforces every guardrail (§11).
        allowLive: ctx.job.allowLive,
        ...(ctx.job.stagingUrl !== undefined ? { stagingUrl: ctx.job.stagingUrl } : {}),
        config: ctx.config,
      };
      // §15 FP-feedback loop (A10): prior operator FP marks for this client
      // route a repeat of the same finding-shape to the appendix — see loadFpTuning.
      const fpTuning = await loadFpTuning(ctx);
      // §15 cross-scan memory (E8): additive learned-fact context on top of
      // confirmation's prompt (purpose "confirmation") — see withLearnedFactsContext.
      const deps: ConfirmDeps = {
        llm: withLearnedFactsContext(opts.gateway, ctx, ctx.scan.repo),
        signal: ctx.signal,
        audit: ctx.store.audit,
        logger: ctx.logger,
        fpTuning,
        // E10: threads the orchestrator's real progress-event sink (A5's
        // EventBus → GET /scans/:id/progress → the console's already-built
        // LayerProgress) into the E1 investigation loop's per-turn narrative,
        // identically to how signal/logger are passed straight through above.
        emitProgress: ctx.emitProgress,
        // A3 (2026-09-12) — production wiring for the E1/E2/E4 agentic
        // investigation loop + adversarial verifier panel, populated from
        // `@montr/config`'s `confirmation.investigation` (mirrors A5's
        // `fixGeneration.agentLoop` wiring convention exactly). ON by
        // default (owner decision — see ConfirmationInvestigationConfigSchema's
        // doc comment, packages/config/src/schema.ts), scoped to unconfirmed
        // high/critical findings only via `severities` — confirm.ts's
        // isEligibleForInvestigation gate skips the loop entirely (zero extra
        // LLM spend) for anything outside that list.
        investigation: {
          enabled: ctx.config.confirmation.investigation.enabled,
          maxTurns: ctx.config.confirmation.investigation.maxTurns,
          verifierCount: ctx.config.confirmation.investigation.verifierCount,
          severities: ctx.config.confirmation.investigation.severities,
        },
        // A9 — real `semantic_search` capability for the E1 investigation
        // loop's tool set (investigate-tools.ts), scoped to this scan's own
        // client/repo/commit. Absent unless `opts.semanticIndex` was
        // constructed (config-gated, off by default) — the loop's
        // `semantic_search` tool then degrades to an honest "not available"
        // result (see investigate-tools.ts), never a crash.
        ...(semanticIndexOpts
          ? {
              semanticSearch: (queryText: string, topK?: number) =>
                querySemanticIndex({
                  queryText,
                  clientId: ctx.clientId,
                  repo: appMap.repo,
                  commitSha: appMap.commitSha,
                  ...(topK ? { topK } : {}),
                  embeddingAdapter: semanticIndexOpts.embeddingAdapter,
                  embeddingModel: semanticIndexOpts.embeddingModel,
                  repository: semanticIndexOpts.codeChunkRepository,
                }),
            }
          : {}),
        ...(opts.now ? { now: opts.now } : {}),
      };
      const result = await confirmFindings(input, deps);

      // A7 — persist the tri-state detection-coverage gap-analysis verdict
      // (B6, packages/appmap/src/coverage-analysis.ts) for every confirmed
      // finding now that both the App Map and confirmed findings exist.
      // Best-effort: a store hiccup here must never fail exploit confirmation
      // itself (mirrors loadFpTuning's fail-safe discipline above).
      if (result.confirmed.length > 0) {
        try {
          await persistDetectionCoverageForScan(
            appMap,
            result.confirmed,
            {
              detectionCoverage: ctx.store.detectionCoverage,
              detectionRules: ctx.store.detectionRules,
            },
            opts.now ? { now: () => new Date(opts.now!()) } : {},
          );
        } catch (err) {
          ctx.logger?.warn?.("worker.detection_coverage.persist_failed", {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      // A8 — purple-team verification loop (B5, packages/confirm/src/purple-loop.ts).
      // See runPurpleTeamVerification's own doc comment for why this runs
      // here (Layer 3) rather than Layer 5, and why it's gated on allowLive.
      // Any coverage row A7 just created above is found-and-updated in place
      // (verifyScenarioDetection's findOrCreateDetectionCoverage), so the two
      // features compose into one coherent DetectionCoverage row per finding.
      const purpleTeamEntries = await runPurpleTeamVerification(
        ctx,
        opts,
        appMap,
        result.confirmed,
      );

      return { ...result, purpleTeamEntries };
    },

    // L4 — Fix Generation. Input: confirmed findings. Emits proposed fixes.
    layer4: async (ctx) => {
      const confirmed =
        ctx.priorOutputs.layer3?.confirmed ??
        (await ctx.store.confirmed.listByScan(ctx.clientId, ctx.scanId));
      const source = (opts.sourceReader ?? ((c) => defaultSourceReader(opts, c)))(ctx);
      // A5 — bounded agentic fix loop: OFF by default (`ctx.config.fixGeneration
      // .agentLoop.enabled` is false unless an operator explicitly configures
      // it — see FixAgentLoopConfigSchema in @montr/config). `agentLoop` is
      // populated on the layer4 context ONLY when configured; left absent
      // otherwise so the unconfigured path is the exact single-shot call
      // `generateOne` always ran (see generate.ts's `ctx.agentLoop?.enabled`
      // branch — byte-for-byte unchanged default request shape).
      const agentLoopConfig = ctx.config.fixGeneration.agentLoop;
      // A12: maxToolCalls now defaults to a small non-zero value (@montr/config's
      // FixAgentLoopConfigSchema), so this only fires when an operator has
      // explicitly overridden MONTR_FIX_AGENT_LOOP_MAX_TOOL_CALLS back to 0 —
      // flag it plainly, since the loop then retries but the model can never
      // read sibling files, which is easy to mistake for the feature's full
      // behavior.
      if (agentLoopConfig.enabled && agentLoopConfig.maxToolCalls === 0) {
        ctx.logger?.warn?.("worker.fix_agent_loop.no_tool_calls", {
          message:
            "MONTR_FIX_AGENT_LOOP_ENABLED is true but MONTR_FIX_AGENT_LOOP_MAX_TOOL_CALLS is 0: the fix agent loop will retry failed proposals but the model cannot read sibling/imported files (no read_file tool exposed).",
        });
      }
      return generateFixes({
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        gateway: opts.gateway,
        source,
        audit: ctx.store.audit,
        // ⛔ Categories forced to human review regardless of the toggle (§11).
        humanRequiredCategoriesAlways: ctx.config.autoFix.humanRequiredCategoriesAlways,
        ...(opts.now ? { now: opts.now } : {}),
        ...(agentLoopConfig.enabled
          ? {
              agentLoop: {
                enabled: true,
                maxIterations: agentLoopConfig.maxIterations,
                maxToolCalls: agentLoopConfig.maxToolCalls,
              },
            }
          : {}),
        confirmed,
      });
    },

    // L5 — Human Gate & Output. Input: confirmed + unconfirmed + fixes. Emits report + PRs.
    layer5: async (ctx) => {
      // A2 — resolve the App Map exactly like Layers 1-3 already do. Without
      // this, buildReport's appMap input was always undefined and
      // buildBlueTeamReport's detection-coverage/attack-path/threat-model
      // sections rendered permanently empty (see packages/report/src/
      // report-builder.ts's buildBlueTeamReport).
      const appMap = await resolveAppMap(ctx);
      const confirmed =
        ctx.priorOutputs.layer3?.confirmed ??
        (await ctx.store.confirmed.listByScan(ctx.clientId, ctx.scanId));
      const unconfirmed =
        ctx.priorOutputs.layer3?.unconfirmed ??
        (await ctx.store.unconfirmed.listByScan(ctx.clientId, ctx.scanId));
      const fixes =
        ctx.priorOutputs.layer4?.fixes ??
        (await ctx.store.fixes.listByScan(ctx.clientId, ctx.scanId));
      const candidates =
        ctx.priorOutputs.layer1?.candidates ??
        (await ctx.store.candidates.listByScan(ctx.clientId, ctx.scanId));
      // ⛔ The Layer-2 DEMOTED appendix lives ONLY in the in-process cache — the
      // persist division persists `probable`, never `demoted`. Merge it (deduped)
      // into the candidate pile that derives `toolsConsolidated`; on a resumed
      // run the cache is empty and the store's L1 pile (a superset) is used.
      const demoted = ctx.priorOutputs.layer2?.demoted ?? [];
      const candidatePile = demoted.length
        ? dedupeCandidates([...candidates, ...demoted])
        : candidates;

      // A8 — purple-team entries computed at Layer 3 (see
      // runPurpleTeamVerification) travel through the in-process priorOutputs
      // cache only (Layer3Output.purpleTeamEntries is deliberately not
      // persisted — see that schema field's doc comment in
      // packages/contracts/src/layers.ts); `[]` on a resumed/distributed run,
      // mirroring `demoted` immediately above — never fabricated.
      const purpleTeamEntries = ctx.priorOutputs.layer3?.purpleTeamEntries ?? [];

      // A13 — advisory hardening recommendations (B9, packages/hardening).
      // `generateHardeningRecommendations` needs a real `FileProvider` over
      // the repo checkout, which is why buildReport takes this precomputed
      // rather than generating it internally — see BuildReportInput
      // .hardeningRecommendations's doc comment. Same repoRoot resolution
      // Layer 1/4 already use; no local checkout (a remote repo Layer 0
      // already cleaned up) degrades to an honest empty list, never a guess.
      const repoRoot = (opts.resolveRepoRoot ?? defaultRepoRoot)(ctx);
      let hardeningRecommendations: HardeningRecommendation[] = [];
      if (repoRoot) {
        try {
          hardeningRecommendations = await generateHardeningRecommendations({
            appMap,
            files: fsFileProvider(repoRoot),
            confirmedFindings: confirmed,
            ...(opts.now ? { now: opts.now } : {}),
          });
        } catch (err) {
          ctx.logger?.warn?.("worker.hardening.generate_failed", {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      const costRollup = buildCostRollup(
        ctx.scanId,
        resolveEstimate(ctx),
        safeActual(ctx.costMeter),
        confirmed.length,
      );

      return buildReport({
        scan: ctx.scan,
        confirmed,
        unconfirmed,
        fixes,
        costRollup,
        // ⛔ Even ON, PRs open ONLY for auto-eligible fixes and only after the
        // gate passed — the orchestrator sets `autoApply` from the fix-gate state.
        autoApply: ctx.job.autoApply,
        candidates: candidatePile,
        audit: ctx.store.audit,
        logger: ctx.logger,
        appMap,
        hardeningRecommendations,
        purpleTeamEntries,
        ...(opts.opener ? { opener: opts.opener } : {}),
        ...(opts.baseBranch ? { baseBranch: opts.baseBranch } : {}),
        ...(opts.now ? { generatedAt: opts.now() } : {}),
      });
    },
  };
}
