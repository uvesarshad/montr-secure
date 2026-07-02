/**
 * Orchestrator-facing Layer 0 runner adapter (build-plan §8.1, runner contract).
 *
 * apps/worker wires the REAL layer function, closing over the @montr/llm-gateway
 * (the LayerContext deliberately does NOT hand a gateway to layers). This factory
 * produces a runner structurally compatible with the orchestrator's
 * `LayerRunner<"layer0">` WITHOUT importing @montr/orchestrator (no reverse dep).
 *
 * Persistence division of labor: by default the runner does NOT create the map
 * (the orchestrator's persist step owns `store.appMaps.create`; the store's
 * `create` throws on a duplicate id, so double-persist is unsafe). The runner
 * still performs the DECIDE-2 stale-commit invalidation (additive + safe). Pass
 * `persist: true` only for STANDALONE use where nothing else persists the map.
 */
import type { Layer0Output, Layer0JobData, LLMGateway, Scan } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { AppMapRepository } from "@montr/state-store";
import type { AuditLogClient } from "@montr/telemetry";
import type { Logger } from "@montr/telemetry";
import { buildAppMap } from "./build.js";

/**
 * The subset of the orchestrator's `LayerContext<"layer0">` Layer 0 uses. The
 * real context is structurally assignable to this.
 */
export interface Layer0Context {
  readonly scanId: string;
  readonly clientId: string;
  readonly scan: Pick<Scan, "commitSha">;
  readonly job: Pick<Layer0JobData, "repo" | "branch" | "mode" | "scope">;
  readonly config: MontrConfig;
  readonly logger: Logger;
  readonly store: { appMaps: AppMapRepository; audit: AuditLogClient };
  readonly signal: AbortSignal;
  emitProgress?(phase: string, pct: number, message?: string): void;
}

export interface Layer0RunnerOptions {
  /** ⛔ The LLM gateway for the semantic pass. Absent ⇒ deterministic-only map. */
  gateway?: LLMGateway;
  /**
   * Persist inside Layer 0 (create + DECIDE-2 + audit). Default false: the
   * orchestrator persists; the runner only invalidates stale maps.
   */
  persist?: boolean;
  /** Workspace root for sandboxed clones of remote repos. */
  workspaceRoot?: string;
}

/** Build a Layer 0 runner compatible with the orchestrator's `LayerRunner`. */
export function createLayer0Runner(
  opts: Layer0RunnerOptions = {},
): (ctx: Layer0Context) => Promise<Layer0Output> {
  const persist = opts.persist ?? false;
  return async (ctx: Layer0Context): Promise<Layer0Output> => {
    const output = await buildAppMap(
      {
        clientId: ctx.clientId,
        scanId: ctx.scanId,
        repo: ctx.job.repo,
        branch: ctx.job.branch,
        mode: ctx.job.mode,
        scope: ctx.job.scope,
        config: ctx.config,
        ...(ctx.scan.commitSha ? { commitSha: ctx.scan.commitSha } : {}),
      },
      {
        ...(opts.gateway ? { gateway: opts.gateway } : {}),
        logger: ctx.logger,
        signal: ctx.signal,
        ...(opts.workspaceRoot ? { workspaceRoot: opts.workspaceRoot } : {}),
        ...(ctx.emitProgress
          ? { onProgress: (phase, pct, message) => ctx.emitProgress?.(phase, pct, message) }
          : {}),
        // Persist only when explicitly asked (avoids double-create with the
        // orchestrator). DECIDE-2 stale invalidation is still applied below.
        ...(persist ? { appMaps: ctx.store.appMaps, audit: ctx.store.audit } : {}),
      },
    );

    if (!persist) {
      // DECIDE-2: additively invalidate prior maps on a different commit. Safe to
      // run before the orchestrator persists the new map (it isn't stored yet).
      try {
        const count = await ctx.store.appMaps.invalidateStaleForCommit(
          ctx.clientId,
          output.appMap.repo,
          output.appMap.commitSha,
        );
        if (count > 0) ctx.logger.info("appmap.invalidated", { count });
      } catch (err) {
        ctx.logger.warn("appmap.invalidate.failed", {
          message: err instanceof Error ? err.message : "unknown",
        });
      }
    }

    return output;
  };
}
