/**
 * @montr/confirm — Layer 3: turns probable → confirmed. Static data-flow proof
 * ships by default; live DAST is premium and heavily gated (build-plan §5.4).
 *
 * ⛔ Live confirmation only hits an allowlisted STAGING target, requires approver
 * authorization, honors the kill switch + rate/blast-radius caps, blocks
 * production by policy, and routes all outbound through @montr/security's egress
 * guard (§11, DECIDE-1). Static confirmation fires NO requests. Owner: WS-H.
 *
 * Primary entry point: {@link confirmFindings} — consumes the correlation output
 * (ProbableFinding[]) + the App Map and emits the frozen `Layer3Output`
 * { confirmed: ConfirmedFinding[], unconfirmed: UnconfirmedFinding[] }.
 */
export { confirmFindings } from "./confirm.js";

export type {
  ConfirmInput,
  ConfirmDeps,
  AuditSink,
  EgressGuardLike,
  ConfirmLogger,
  LiveHttpTransport,
  LiveHttpRequest,
  LiveHttpResponse,
  BrowserDriver,
  BrowserLoginRequest,
  AuthenticatedSession,
  StaticConfirmOutcome,
  LiveConfirmOutcome,
  InvestigationConfig,
} from "./types.js";

// §15 false-positive tuning hook — inject the regression corpus (from @montr/qa)
// to skip/suppress known false positives to the appendix. Additive + fail-safe.
export type { FalsePositiveTuning, FalsePositiveSignal } from "./tuning.js";

// E8 extension — confirmed-exploit-shape priors (learned-facts mechanism).
// May only WIDEN investigation eligibility; never bypasses E2/E4's proof gates.
export type { PriorConfirmedShapes, ConfirmedShapeSignal } from "./prior-shapes.js";

// Static confirmation (3a) internals — reusable by the fix/report layers + tests.
export { confirmStatic, assembleConfirmed, toUnconfirmed } from "./static.js";

// ⛔ Guardrails (3b) — exported so integration + tests can assert they BLOCK.
export {
  ScopeGuard,
  assertLiveAuthorized,
  isAllowlisted,
  looksLikeProduction,
  hostOf,
  buildDefaultEgressGuard,
  type ScopeGuardOptions,
  type LiveAuthzInput,
} from "./guard.js";

// A16 — deterministic safety predicate gating model-COMPOSED live-DAST
// payloads (sql_injection/xss/ssrf/path_traversal/command_injection only —
// see payload-safety.ts's header for the full composable-vs-pre-written-only
// rationale). Exported so callers/tests can assert the predicate directly,
// independent of the adaptive loop that consumes it.
export {
  COMPOSABLE_LIVE_CATEGORIES,
  isComposableLiveCategory,
  evaluateComposedPayloadSafety,
  type PayloadSafetyVerdict,
  type EvaluateComposedPayloadOptions,
} from "./payload-safety.js";

// Live DAST (3b) recon/exploit surface + defaults.
export {
  confirmLive,
  isLiveEligible,
  LIVE_CONFIRMABLE_CATEGORIES,
  defaultBrowserDriver,
  defaultTransport,
} from "./live.js";

// ⛔ Red-team scenario library (Phase-4 / Wave 5, §16). A scenario PARAMETERIZES
// the gated live-DAST engine — no new egress path. Every run reuses
// assertLiveAuthorized + ScopeGuard (allowlist + production block + kill switch +
// rate/blast caps + egress guard).
export {
  validateScenario,
  isRelativePath,
  resolveScenarioTarget,
  assertScenarioAuthorized,
  runScenario,
  type ScenarioValidation,
  type ScenarioAuthzInput,
  type ScenarioRunDeps,
  type ScenarioRunResult,
  type ScenarioStepResult,
} from "./scenarios.js";

// Deterministic classification helpers.
export {
  deriveSeverity,
  deriveTitle,
  deriveImpact,
  extractParam,
  assessSink,
  isDataFlowConfirmable,
  DATAFLOW_SINK_KINDS,
  type SinkAssessment,
} from "./taxonomy.js";

// ⛔ Per-language confirmation heuristics (Layer 3a stack breadth — §7 Wave 4).
// A new stack adds a plugin under heuristics/<lang>/ and is appended to
// HEURISTICS — the static-confirmation engine stays stack-agnostic.
export { HEURISTICS, resolveHeuristics } from "./heuristics/registry.js";
export { EMPTY_HEURISTICS } from "./heuristics/types.js";
export type { ConfirmationHeuristics, ResolvedHeuristics } from "./heuristics/types.js";

// E1 — agentic investigation loop: READ-ONLY repo tools + the multi-turn
// tool-calling loop that drives them. OFF by default (ConfirmDeps.investigation).
export {
  INVESTIGATION_TOOL_DEFINITIONS,
  SUBMIT_CONCLUSION_TOOL,
  executeInvestigationTool,
  type InvestigationToolContext,
} from "./investigate-tools.js";
export {
  runInvestigation,
  type InvestigationVerdict,
  type InvestigationOutcome,
  type InvestigationTurn,
  type InvestigationToolCallRecord,
} from "./investigate.js";

// E2 — executable-evidence gate (a real, existing, repo test that FAILS
// against current code — never a synthesized replay, see evidence.ts's header).
export {
  gatherExecutableEvidence,
  createDefaultTestRunner,
  type TestRunner,
  type TestRunResult,
  type ExecutableEvidence,
  type GatherEvidenceOptions,
} from "./evidence.js";

// E4 — multi-agent adversarial confirmation (N independent verifier lenses,
// strict majority required). Exported so callers/tests can assert the
// disagreement-does-not-confirm invariant directly.
export {
  runAdversarialVerification,
  type VerifierLens,
  type VerifierVerdict,
  type AdversarialOutcome,
} from "./adversarial.js";

// E1 + E2 + E4 tied together — the one path allowed to confirm a finding
// neither the deterministic static proof nor live DAST could. See this
// module's header comment for the full three-gate invariant.
export {
  attemptInvestigationConfirmation,
  type InvestigationPathResult,
} from "./investigation-pipeline.js";

// B5 — purple-team verification loop. Runs a red-team scenario through the
// EXISTING gated engine above (runScenario — no new execution path) and
// structurally evaluates a B3-generated Sigma DetectionRule against the
// resulting transcript. Standalone: not wired into any pipeline layer or
// report-assembly path (B10's job in a later wave). See purple-loop.ts's
// header for the full safety-preservation and evaluator-scope rationale.
export {
  parseSigmaRule,
  evaluateSigmaRule,
  evaluateDetectionRuleAgainstScenario,
  runPurpleTeamScenario,
  findOrCreateDetectionCoverage,
  verifyScenarioDetection,
  summarizePurpleTeamRun,
  REDTEAM_CATEGORY_TO_FINDING_CATEGORIES,
  type ParsedSigmaRule,
  type EvaluableRequest,
  type SigmaEvalOutcome,
  type SigmaRuleEvaluation,
  type RunPurpleTeamScenarioInput,
  type RunPurpleTeamScenarioDeps,
  type PurpleTeamScenarioResult,
  type FindOrCreateCoverageOptions,
  type VerifyScenarioDetectionResult,
  type PurpleTeamScenarioSummaryEntry,
  type PurpleTeamRunSummary,
  type PurpleTeamRunEntry,
} from "./purple-loop.js";
