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
} from "@montr/contracts";
import type { CostMeter } from "@montr/cost-meter";
import { buildCostRollup } from "@montr/cost-meter";
import type { LayerContext, LayerRunners } from "@montr/orchestrator";

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
      const deps: DiscoveryDeps = {
        logger: ctx.logger,
        signal: ctx.signal,
        gateway: opts.gateway,
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
      return correlate({
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        appMap,
        candidates,
        gateway: opts.gateway,
        audit: ctx.store.audit,
        logger: ctx.logger,
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
      const deps: ConfirmDeps = {
        llm: opts.gateway,
        signal: ctx.signal,
        audit: ctx.store.audit,
        logger: ctx.logger,
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
