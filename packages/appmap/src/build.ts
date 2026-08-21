/**
 * Layer 0 orchestration (build-plan §5.1). Runs the DETERMINISTIC App Map
 * builders first, THEN (and only then) the LLM semantic pass, then computes the
 * scope + cost estimate, persists per-client with DECIDE-2 stale invalidation,
 * and emits the exact {AppMap, ScanScope, CostEstimate} Layer0Output contract.
 *
 * ⛔ Ordering is the safety-critical invariant: `labelAuthBoundaries` receives an
 * already-built map, so no LLM call can precede the deterministic map (golden
 * rule #6). The sandboxed workspace is always cleaned up (try/finally).
 */
import { AppMapSchema, Layer0OutputSchema } from "@montr/contracts";
import type { AppMap, Layer0Output, ScanScope } from "@montr/contracts";
import { createNullLogger } from "@montr/telemetry";
import type { BuildAppMapDeps, BuildAppMapInput } from "./types.js";
import { deriveContentSha, resolveWorkspace } from "./workspace.js";
import { collectFiles, createProject } from "./sources.js";
import { buildDeterministicPieces } from "./languages/registry.js";
import { computeDiffScope } from "./diff.js";
import { labelAuthBoundaries } from "./llm.js";
import { deriveThreatModel } from "./threat-model.js";
import { buildTelemetrySurfaces } from "./telemetry-surfaces.js";
import { estimateCost } from "./cost.js";
import { findReusableAppMap, persistAppMap } from "./persist.js";

/**
 * Build the App Map, scope, and cost estimate for a scan. Every external
 * collaborator is injected via `deps`, so this runs fully offline in tests.
 */
export async function buildAppMap(
  input: BuildAppMapInput,
  deps: BuildAppMapDeps = {},
): Promise<Layer0Output> {
  const logger = deps.logger ?? createNullLogger();
  const now = deps.now ?? (() => new Date());
  const progress = deps.onProgress ?? (() => undefined);
  const clientId = input.clientId;
  const appMapId = input.appMapId ?? `appmap_${input.scanId}`;

  progress("intake", 5, "resolving workspace");
  const workspace = await resolveWorkspace(input.repo, input.branch, {
    ...(deps.git ? { git: deps.git } : {}),
    ...(deps.workspaceRoot ? { workspaceRoot: deps.workspaceRoot } : {}),
    ...(input.commitSha ? { commitSha: input.commitSha } : {}),
  });

  try {
    progress("scan", 15, "collecting files");
    const inv = await collectFiles(workspace.dir);
    const commitSha =
      workspace.commitSha ||
      input.commitSha ||
      (await deriveContentSha(workspace.dir, inv.sourceFiles));

    // DECIDE-2: reuse a fresh, non-stale persisted map for this exact commit.
    if (deps.appMaps) {
      const reusable = await findReusableAppMap(deps.appMaps, clientId, input.repo, commitSha);
      if (reusable) {
        logger.info("appmap.reused", { repo: input.repo, commitSha });
        progress("done", 100, "reused persisted map");
        // A diff scope is scan-specific, so it is recomputed even on reuse; the
        // import graph it needs is the only thing rebuilt (map builders skipped).
        const reuseProject =
          input.mode === "diff" ? createProject(workspace.dir, inv.sourceFiles) : undefined;
        return finalize(
          reusable,
          input,
          inv.sourceFiles.length,
          reuseProject,
          reuseProject ? workspace.dir : undefined,
        );
      }
    }

    // Detect the stacks present and run their analyzers, merging the
    // language-agnostic App-Map pieces (routes/models/surfaces/taint). Phase 1
    // ships the `typescript` analyzer; python/java plug in under
    // languages/<lang>/ WITHOUT touching this dispatcher (build-plan §7 Wave 4).
    progress("detect", 25, "language detection + deterministic parse");
    const pieces = await buildDeterministicPieces({
      dir: workspace.dir,
      inventory: inv,
      logger,
      ...(deps.signal ? { signal: deps.signal } : {}),
    });
    progress("taint", 75, "routes + models + surfaces + taint");

    // Assemble + validate the DETERMINISTIC map (no LLM has run yet).
    let appMap: AppMap = AppMapSchema.parse({
      id: appMapId,
      clientId,
      scanId: input.scanId,
      repo: input.repo,
      branch: input.branch,
      commitSha,
      createdAt: now().toISOString(),
      languages: pieces.languages,
      frameworks: pieces.frameworks,
      entrypoints: pieces.entrypoints,
      routes: pieces.routes,
      dataStores: pieces.dataStores,
      ormModels: pieces.ormModels,
      thirdPartyCalls: pieces.thirdPartyCalls,
      envSecretSurfaces: pieces.envSecretSurfaces,
      taintSources: pieces.taintSources,
      taintSinks: pieces.taintSinks,
      taintFlows: pieces.taintFlows,
      stale: false,
      rebuildPolicy: "rebuild_on_stale_commit",
    } satisfies AppMap);

    // ⛔ ONLY NOW: the LLM semantic pass (auth boundaries + gap fill).
    progress("semantic", 85, "auth-boundary labeling");
    const labeled = await labelAuthBoundaries(appMap, deps.gateway, {
      scanId: input.scanId,
      clientId,
      ...(deps.signal ? { signal: deps.signal } : {}),
      logger,
    });
    appMap = labeled.appMap;

    // E6 — Layer 0.5 threat-model derivation, as a SUB-STEP of Layer 0 (see
    // threat-model.ts's module doc for why this is not a new pipeline layer).
    // Runs AFTER auth-boundary labeling (the threat model's trust boundaries
    // are grounded in the final, LLM-filled `authState`), still strictly
    // before persistence. Always attaches a result — the deterministic
    // baseline requires no gateway — so this never gates on the LLM being
    // available.
    progress("threat-model", 88, "threat-model derivation");
    const threatModelResult = await deriveThreatModel(appMap, deps.gateway, {
      scanId: input.scanId,
      clientId,
      ...(deps.signal ? { signal: deps.signal } : {}),
      logger,
    });
    appMap = { ...appMap, threatModel: threatModelResult.threatModel };

    // B6 — telemetry-surfaces detection, another additional Layer 0 step
    // (same convention as the threat model above): deterministic, no LLM,
    // never fails the scan. Runs after routes are final so per-route logging
    // detection sees the complete, merged route set.
    progress("telemetry-surfaces", 90, "telemetry-surfaces detection");
    const telemetrySurfaces = await buildTelemetrySurfaces(appMap, {
      dir: workspace.dir,
      inventory: inv,
      logger,
    });
    appMap = { ...appMap, telemetrySurfaces };

    // Persist (per-client, encrypted) with DECIDE-2 stale invalidation + audit.
    if (deps.appMaps) {
      progress("persist", 92, "persisting map");
      appMap = await persistAppMap(appMap, {
        appMaps: deps.appMaps,
        ...(deps.audit ? { audit: deps.audit } : {}),
        scanId: input.scanId,
      });
    }

    progress("done", 100, "map complete");
    // A diff scope needs the TS/JS import graph; build it lazily so full-mode
    // scans never pay for it. Mirrors the reuse path above (symmetric).
    const diffProject =
      input.mode === "diff" ? createProject(workspace.dir, inv.sourceFiles) : undefined;
    return finalize(
      appMap,
      input,
      inv.sourceFiles.length,
      diffProject,
      diffProject ? workspace.dir : undefined,
    );
  } finally {
    await workspace.cleanup();
  }
}

/** Compute the scope + cost estimate and emit the validated Layer0Output. */
function finalize(
  appMap: AppMap,
  input: BuildAppMapInput,
  fileCount: number,
  project?: import("ts-morph").Project,
  dir?: string,
): Layer0Output {
  const base = input.scope;
  let scope: ScanScope;

  if (input.mode === "diff" && project && dir) {
    const changedFiles = input.changedFiles ?? base.changedFiles ?? [];
    const diff = computeDiffScope(project, dir, filesFromProject(project, dir), changedFiles);
    scope = {
      ...base,
      mode: "diff",
      includePaths: diff.reachable.length > 0 ? diff.reachable : base.includePaths,
      changedFiles: diff.changedFiles,
      reachableFromChanges: true,
      routeCount: appMap.routes.length,
      fileCount: diff.reachable.length > 0 ? diff.reachable.length : fileCount,
    };
  } else {
    scope = {
      ...base,
      mode: input.mode,
      reachableFromChanges: false,
      routeCount: appMap.routes.length,
      fileCount,
    };
  }

  const costEstimate = estimateCost({
    scanId: input.scanId,
    mode: input.mode,
    appMap,
    fileCount,
    config: input.config,
  });

  return Layer0OutputSchema.parse({ appMap, scope, costEstimate } satisfies Layer0Output);
}

/** Repo-relative source paths currently loaded in the project. */
function filesFromProject(project: import("ts-morph").Project, dir: string): string[] {
  return project.getSourceFiles().map((sf) => {
    const abs = sf.getFilePath();
    return (abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs).replace(
      /\\/g,
      "/",
    );
  });
}
