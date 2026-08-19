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
import { scanPrisma } from "./prisma.js";
import { scanEnvSecretSurfaces, scanThirdPartyCalls } from "./surfaces.js";
import { scanTaint } from "./taint.js";
import { scanTaintFlows } from "./callgraph.js";
import type { AnalyzerInput, AppMapContribution, LanguageAnalyzer } from "../types.js";

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

    const { routes, entrypoints, routeIdsByFile } = scanRoutes(project, dir);
    const { dataStores, ormModels } = await scanPrisma(dir, inventory.prismaSchemas);
    const thirdPartyCalls = scanThirdPartyCalls(project, dir);
    const envSecretSurfaces = await scanEnvSecretSurfaces(project, dir, inventory.envFiles);
    const { taintSources, taintSinks } = scanTaint(project, dir, routeIdsByFile);
    // Bounded interprocedural extension (see callgraph.ts) — resolves 1-2 hop
    // taint flows across function/file boundaries that the same-file
    // taintSources/taintSinks catalog above cannot express by itself. Layer 2
    // (@montr/correlation) still falls back to its same-file proximity
    // heuristic for everything not resolved here.
    const taintFlows = scanTaintFlows(project, dir);

    return {
      languages: detectLanguages(inventory.sourceFiles),
      frameworks: detectFrameworks(inventory),
      entrypoints,
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
export { scanRoutes, type RouteScanResult } from "./routes.js";
export { scanPrisma, type PrismaScanResult } from "./prisma.js";
export { scanThirdPartyCalls, scanEnvSecretSurfaces } from "./surfaces.js";
export { scanTaint, type TaintScanResult } from "./taint.js";
export { scanTaintFlows } from "./callgraph.js";
