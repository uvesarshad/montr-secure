/**
 * TypeScript / JavaScript App-Map analyzer (Phase-1 host stack).
 *
 * Wraps the deterministic ts-morph / Next.js / Prisma builders behind the
 * {@link LanguageAnalyzer} seam. This is the reference implementation the
 * Python and JVM analyzers mirror: detect the stack, then emit the
 * language-agnostic App-Map pieces (routes, orm_models, third_party,
 * env_surface, taint sources/sinks). NO LLM runs here (golden rule #6) — the
 * semantic pass happens later in `build.ts` on the assembled map.
 */
import { createProject, detectFrameworks, detectLanguages } from "../../sources.js";
import { scanRoutes } from "./routes.js";
import type { FnLike } from "./routes.js";
import { scanExpressRoutes } from "./express.js";
import { scanFastifyRoutes } from "./fastify.js";
import { scanPrisma } from "./prisma.js";
import { scanEnvSecretSurfaces, scanThirdPartyCalls } from "./surfaces.js";
import { scanTaint } from "./taint.js";
import { scanTaintFlows } from "./callgraph.js";
import { linkRouteModels } from "./route-models.js";
import type { AnalyzerInput, AppMapContribution, LanguageAnalyzer } from "../types.js";
import type { Entrypoint, Route } from "@montr/contracts";

/** The pieces every per-framework route scanner (Next.js/Express/Fastify) returns. */
interface RouteScan {
  routes: Route[];
  entrypoints: Entrypoint[];
  routeIdsByFile: Map<string, string[]>;
  handlersByRouteId: Map<string, FnLike>;
}

/**
 * Merge route scans from however many framework scanners ran (usually exactly
 * one — Next.js XOR Express XOR Fastify — but nothing stops a monorepo repo
 * from declaring more than one framework dependency, so this stays correct
 * for that case too). De-dupes by `${method} ${path}`, first-scan-wins, same
 * as each individual scanner's own internal dedup.
 */
function mergeRouteScans(scans: RouteScan[]): RouteScan {
  if (scans.length === 1) return scans[0]!;
  const routes: Route[] = [];
  const entrypoints: Entrypoint[] = [];
  const routeIdsByFile = new Map<string, string[]>();
  const handlersByRouteId = new Map<string, FnLike>();
  const seen = new Set<string>();

  for (const s of scans) {
    for (const r of s.routes) {
      const key = `${r.method} ${r.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      routes.push(r);
    }
    entrypoints.push(...s.entrypoints);
    for (const [file, ids] of s.routeIdsByFile) {
      routeIdsByFile.set(file, [...(routeIdsByFile.get(file) ?? []), ...ids]);
    }
    for (const [id, fn] of s.handlersByRouteId) {
      if (!handlersByRouteId.has(id)) handlersByRouteId.set(id, fn);
    }
  }

  routes.sort((a, b) =>
    a.isApiRoute === b.isApiRoute
      ? a.path.localeCompare(b.path) || a.method.localeCompare(b.method)
      : a.isApiRoute
        ? -1
        : 1,
  );
  entrypoints.sort((a, b) => a.name.localeCompare(b.name));
  return { routes, entrypoints, routeIdsByFile, handlersByRouteId };
}

const TS_JS_SOURCE_RE = /\.(tsx?|jsx?|mjs|cjs)$/i;

/** Does the repo carry TS/JS code (or a Node/Prisma manifest) worth analyzing? */
function hasTypescriptSurface(input: AnalyzerInput): boolean {
  const inv = input.inventory;
  return (
    inv.sourceFiles.some((f) => TS_JS_SOURCE_RE.test(f)) ||
    inv.hasPackageJson ||
    inv.hasNextConfig ||
    inv.prismaSchemas.length > 0
  );
}

export const typescriptAnalyzer: LanguageAnalyzer = {
  id: "typescript",

  detect(input: AnalyzerInput): boolean {
    return hasTypescriptSurface(input);
  },

  async analyze(input: AnalyzerInput): Promise<AppMapContribution> {
    const { dir, inventory } = input;

    // A shared ts-morph Project over the TS/JS surface (syntactic, offline).
    const project = createProject(dir, inventory.sourceFiles);
    const frameworks = detectFrameworks(inventory);

    // Route extraction: Next.js is always attempted (cheap — it only matches
    // `app/`/`pages/` file layout); Express/Fastify only run when their
    // package.json dependency was actually detected, so their receiver-
    // agnostic `.get(path, ...)`-shaped matching never fires on a repo that
    // isn't that framework (A17 — Express/Fastify previously had detection
    // but no extractor, so they always contributed zero routes).
    const scans: RouteScan[] = [scanRoutes(project, dir)];
    if (frameworks.includes("express")) scans.push(scanExpressRoutes(project, dir));
    if (frameworks.includes("fastify")) scans.push(scanFastifyRoutes(project, dir));
    const merged = mergeRouteScans(scans);

    const { dataStores, ormModels } = await scanPrisma(dir, inventory.prismaSchemas);
    const thirdPartyCalls = scanThirdPartyCalls(project, dir);
    const envSecretSurfaces = await scanEnvSecretSurfaces(project, dir, inventory.envFiles);
    const { taintSources, taintSinks } = scanTaint(project, dir, merged.routeIdsByFile);
    // Bounded interprocedural extension (see callgraph.ts) — resolves 1-2 hop
    // taint flows across function/file boundaries that the same-file
    // taintSources/taintSinks catalog above cannot express by itself. Layer 2
    // (@montr/correlation) still falls back to its same-file proximity
    // heuristic for everything not resolved here.
    const taintFlows = scanTaintFlows(project, dir);
    // A18 — link each route to the ORM model(s) its handler statically
    // queries (direct Prisma calls + one hop through a local function — see
    // route-models.ts for the exact resolution boundary).
    const routes = linkRouteModels(
      project,
      dir,
      merged.routes,
      ormModels,
      merged.handlersByRouteId,
    );

    return {
      languages: detectLanguages(inventory.sourceFiles),
      frameworks,
      entrypoints: merged.entrypoints,
      routes,
      dataStores,
      ormModels,
      thirdPartyCalls,
      envSecretSurfaces,
      taintSources,
      taintSinks,
      taintFlows,
    };
  },
};

// Re-export the deterministic builders so `@montr/appmap` keeps exposing them
// (focused reuse + testing) even though they now live behind the plugin.
export { scanRoutes, type RouteScanResult, type FnLike } from "./routes.js";
export { scanExpressRoutes, type ExpressScanResult } from "./express.js";
export { scanFastifyRoutes, type FastifyScanResult } from "./fastify.js";
export { scanPrisma, type PrismaScanResult } from "./prisma.js";
export { scanThirdPartyCalls, scanEnvSecretSurfaces } from "./surfaces.js";
export { scanTaint, type TaintScanResult } from "./taint.js";
export { scanTaintFlows } from "./callgraph.js";
export { linkRouteModels } from "./route-models.js";
