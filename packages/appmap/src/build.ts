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
import { collectFiles, createProject, detectFrameworks, detectLanguages } from "./sources.js";
import { scanRoutes } from "./routes.js";
import { scanPrisma } from "./prisma.js";
import { scanThirdPartyCalls, scanEnvSecretSurfaces } from "./surfaces.js";
import { scanTaint } from "./taint.js";
import { computeDiffScope } from "./diff.js";
import { labelAuthBoundaries } from "./llm.js";
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

    progress("detect", 25, "language + framework detection");
    const languages = detectLanguages(inv.sourceFiles);
    const frameworks = detectFrameworks(inv);

    const project = createProject(workspace.dir, inv.sourceFiles);

    progress("routes", 40, "route introspection");
    const { routes, entrypoints, routeIdsByFile } = scanRoutes(project, workspace.dir);

    progress("datastores", 55, "prisma models");
    const { dataStores, ormModels } = await scanPrisma(workspace.dir, inv.prismaSchemas);

    progress("surfaces", 65, "third-party + env/secret surface");
    const thirdPartyCalls = scanThirdPartyCalls(project, workspace.dir);
    const envSecretSurfaces = await scanEnvSecretSurfaces(project, workspace.dir, inv.envFiles);

    progress("taint", 75, "taint sources + sinks");
    const { taintSources, taintSinks } = scanTaint(project, workspace.dir, routeIdsByFile);

    // Assemble + validate the DETERMINISTIC map (no LLM has run yet).
    let appMap: AppMap = AppMapSchema.parse({
      id: appMapId,
      clientId,
      scanId: input.scanId,
      repo: input.repo,
      branch: input.branch,
      commitSha,
      createdAt: now().toISOString(),
      languages,
      frameworks,
      entrypoints,
      routes,
      dataStores,
      ormModels,
      thirdPartyCalls,
      envSecretSurfaces,
      taintSources,
      taintSinks,
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
    return finalize(appMap, input, inv.sourceFiles.length, project, workspace.dir);
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
