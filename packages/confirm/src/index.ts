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
} from "./types.js";

// §15 false-positive tuning hook — inject the regression corpus (from @montr/qa)
// to skip/suppress known false positives to the appendix. Additive + fail-safe.
export type { FalsePositiveTuning, FalsePositiveSignal } from "./tuning.js";

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

// Live DAST (3b) recon/exploit surface + defaults.
export {
  confirmLive,
  isLiveEligible,
  LIVE_CONFIRMABLE_CATEGORIES,
  defaultBrowserDriver,
} from "./live.js";

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
