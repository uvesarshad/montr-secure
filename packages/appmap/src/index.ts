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

// Deterministic builders (exported for reuse + focused testing).
export { collectFiles, detectLanguages, detectFrameworks, createProject } from "./sources.js";
export type { FileInventory } from "./sources.js";
export { scanRoutes } from "./routes.js";
export type { RouteScanResult } from "./routes.js";
export { scanPrisma } from "./prisma.js";
export type { PrismaScanResult } from "./prisma.js";
export { scanThirdPartyCalls, scanEnvSecretSurfaces } from "./surfaces.js";
export { scanTaint } from "./taint.js";
export type { TaintScanResult } from "./taint.js";
export { computeDiffScope } from "./diff.js";
export type { DiffScope } from "./diff.js";

// Semantic pass, cost, persistence.
export { labelAuthBoundaries } from "./llm.js";
export type { AuthLabelOptions, AuthLabelResult } from "./llm.js";
export { estimateCost } from "./cost.js";
export type { EstimateCostInput } from "./cost.js";
export { persistAppMap, findReusableAppMap } from "./persist.js";
export type { PersistOptions } from "./persist.js";
