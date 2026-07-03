/**
 * @montr/appmap — Layer 0: Intake & Scoping (build-plan §5.1, PRD §7 Layer 0).
 *
 * Builds the App Map that is the substrate for correlation (Layer 2). DETERMINISTIC
 * builders run first — language/framework detection, Next.js route introspection
 * (app + pages routers, API routes) via ts-morph, Prisma DMMF models, third-party
 * + env/secret surfaces, and the taint source/sink catalog. ⛔ ONLY THEN does an
 * LLM semantic pass label auth boundaries + fill gaps (golden rule #6 — no LLM
 * call before the map exists). Emits the exact {AppMap, ScanScope, CostEstimate}
 * Layer0Output. Persists per-client (encrypted) with DECIDE-2 stale-commit
 * invalidation, and projects cost via @montr/cost-meter.
 */

// Primary entry point + orchestrator adapter.
export { buildAppMap } from "./build.js";
export { createLayer0Runner } from "./runner.js";
export type { Layer0Context, Layer0RunnerOptions } from "./runner.js";
export type {
  BuildAppMapInput,
  BuildAppMapDeps,
  GitClient,
  Workspace,
  DeterministicResult,
} from "./types.js";

// Intake / workspace.
export {
  resolveWorkspace,
  createDefaultGitClient,
  deriveContentSha,
  readRepoFile,
  isRemoteRepo,
} from "./workspace.js";

// Shared deterministic file/detection helpers (exported for reuse + testing).
export { collectFiles, detectLanguages, detectFrameworks, createProject } from "./sources.js";
export type { FileInventory } from "./sources.js";

// The TypeScript/JS App-Map builders now live behind the `typescript` language
// plugin; re-exported here so the package surface is unchanged.
export {
  scanRoutes,
  scanPrisma,
  scanThirdPartyCalls,
  scanEnvSecretSurfaces,
  scanTaint,
} from "./languages/typescript/index.js";
export type {
  RouteScanResult,
  PrismaScanResult,
  TaintScanResult,
} from "./languages/typescript/index.js";

// ⛔ Language-plugin architecture (Layer 0 stack breadth — build-plan §7 Wave 4).
// A new stack adds an analyzer under languages/<lang>/ and is appended to
// LANGUAGE_ANALYZERS — correlation/fix/report stay stack-agnostic.
export {
  buildDeterministicPieces,
  mergeContributions,
  LANGUAGE_ANALYZERS,
} from "./languages/registry.js";
export { typescriptAnalyzer } from "./languages/typescript/index.js";
export { pythonAnalyzer } from "./languages/python/index.js";
export { javaAnalyzer } from "./languages/java/index.js";
export { emptyContribution } from "./languages/types.js";
export type { LanguageAnalyzer, AnalyzerInput, AppMapContribution } from "./languages/types.js";
export { computeDiffScope } from "./diff.js";
export type { DiffScope } from "./diff.js";

// Semantic pass, cost, persistence.
export { labelAuthBoundaries } from "./llm.js";
export type { AuthLabelOptions, AuthLabelResult } from "./llm.js";
export { estimateCost } from "./cost.js";
export type { EstimateCostInput } from "./cost.js";
export { persistAppMap, findReusableAppMap } from "./persist.js";
export type { PersistOptions } from "./persist.js";
