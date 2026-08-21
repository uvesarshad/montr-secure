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

// ⛔ E5 (semantic codebase index) reuse seam: the Python/Java web-tree-sitter
// parser loaders + null-safe AST helpers, previously internal to
// languages/{python,java}/. Re-exported (additive only — no behavior change)
// so packages/semantic-index's AST chunker can parse the SAME grammars
// through the SAME loaders rather than duplicating WASM-loading logic; the
// TypeScript equivalent (`createProject`, ts-morph) was already exported
// above. See packages/semantic-index/src/chunk.ts.
export {
  getPythonParser,
  parseModule as parsePythonModule,
  lineOf as pythonLineOf,
  descendants as pythonDescendants,
} from "./languages/python/parser.js";
export type { ParsedModule as ParsedPythonModule } from "./languages/python/parser.js";
export {
  getJavaParser,
  parseJava,
  lineOf as javaLineOf,
  descendantsOfType as javaDescendantsOfType,
} from "./languages/java/parser.js";
export type { TSNode as JavaSyntaxNode } from "./languages/java/parser.js";

// The TypeScript/JS App-Map builders now live behind the `typescript` language
// plugin; re-exported here so the package surface is unchanged.
export {
  scanRoutes,
  scanExpressRoutes,
  scanFastifyRoutes,
  scanPrisma,
  scanThirdPartyCalls,
  scanEnvSecretSurfaces,
  scanTaint,
  linkRouteModels,
} from "./languages/typescript/index.js";
export type {
  RouteScanResult,
  ExpressScanResult,
  FastifyScanResult,
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
// ⛔ E6 — threat-model derivation (Layer 0.5 as a Layer-0 sub-step, see the
// module doc). `buildDeterministicThreatModel`/`buildAttackSurfaceBaseline`/
// `buildTrustBoundaries` are exported for standalone/test use; `deriveThreatModel`
// is the full (deterministic + optional LLM enrichment) entry point `build.ts` calls.
export {
  deriveThreatModel,
  buildDeterministicThreatModel,
  buildAttackSurfaceBaseline,
  buildTrustBoundaries,
} from "./threat-model.js";
export type { ThreatModelOptions, ThreatModelResult } from "./threat-model.js";
// B6 — telemetry-surfaces detection (Layer 0 sub-step, see the module doc):
// repo-level structured-logging/APM detection + per-route (TS/JS) logging-
// call detection, combined by `buildTelemetrySurfaces` (the entry point
// `build.ts` calls) into `AppMap.telemetrySurfaces`.
export {
  buildTelemetrySurfaces,
  detectRepoTelemetry,
  detectRouteTelemetry,
} from "./telemetry-surfaces.js";
export type { BuildTelemetrySurfacesOptions } from "./telemetry-surfaces.js";
// B6 — detection-coverage gap analysis: given a confirmed finding + the App
// Map's telemetry surfaces + any existing `DetectionRule`s, derive a
// tri-state `DetectionCoverage` verdict. See the module doc for exactly what
// each verdict requires.
export {
  evaluateCoverageForFinding,
  routeForFinding,
  buildDetectionCoverage,
  persistDetectionCoverageForScan,
} from "./coverage-analysis.js";
export type { CoverageVerdict, PersistDetectionCoverageDeps } from "./coverage-analysis.js";
export { estimateCost } from "./cost.js";
export type { EstimateCostInput } from "./cost.js";
export { persistAppMap, findReusableAppMap } from "./persist.js";
export type { PersistOptions } from "./persist.js";
