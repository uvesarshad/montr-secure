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
  type CostEstimate,
  type LLMGateway,
  type LLMPurpose,
} from "@montr/contracts";
import type { CostMeter } from "@montr/cost-meter";
import { buildCostRollup } from "@montr/cost-meter";
import type { LayerContext, LayerRunners } from "@montr/orchestrator";
import type { FalsePositiveMarkSignal, LearnedFact } from "@montr/state-store";

import { createLayer0Runner } from "@montr/appmap";
import {
  runDiscovery,
  type DiscoveryDeps,
  type GitleaksRunner,
  type SemgrepRunner,
} from "@montr/discovery";
import { correlate } from "@montr/correlation";
import { confirmFindings, type ConfirmDeps, type ConfirmInput } from "@montr/confirm";
import {
  createFsSourceReader,
  createMapSourceReader,
  generateFixes,
  type SourceReader,
} from "@montr/fix";
import { buildReport, type PullRequestOpener } from "@montr/report";

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

/* ------------------------------- runners ------------------------------- */

/**
 * Build the full set of orchestrator layer runners wired to the REAL layer
 * functions. The orchestrator drives them; `orchestrator/persist.ts` persists
 * their outputs. Every runner is pure w.r.t. store writes (see the file header).
 */
export function createLayerRunners(opts: LayerRunnerOptions): LayerRunners {
  const layer0Runner = createLayer0Runner({
    gateway: opts.gateway,
    ...(opts.workspaceRoot ? { workspaceRoot: opts.workspaceRoot } : {}),
    // persist:false (default) — the orchestrator owns store.appMaps.create.
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
        ...(opts.now ? { now: opts.now } : {}),
      };
      return confirmFindings(input, deps);
    },

    // L4 — Fix Generation. Input: confirmed findings. Emits proposed fixes.
    layer4: async (ctx) => {
      const confirmed =
        ctx.priorOutputs.layer3?.confirmed ??
        (await ctx.store.confirmed.listByScan(ctx.clientId, ctx.scanId));
      const source = (opts.sourceReader ?? ((c) => defaultSourceReader(opts, c)))(ctx);
      return generateFixes({
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        gateway: opts.gateway,
        source,
        audit: ctx.store.audit,
        // ⛔ Categories forced to human review regardless of the toggle (§11).
        humanRequiredCategoriesAlways: ctx.config.autoFix.humanRequiredCategoriesAlways,
        ...(opts.now ? { now: opts.now } : {}),
        confirmed,
      });
    },

    // L5 — Human Gate & Output. Input: confirmed + unconfirmed + fixes. Emits report + PRs.
    layer5: async (ctx) => {
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
        ...(opts.opener ? { opener: opts.opener } : {}),
        ...(opts.baseBranch ? { baseBranch: opts.baseBranch } : {}),
        ...(opts.now ? { generatedAt: opts.now() } : {}),
      });
    },
  };
}
