/**
 * Shared types for Layer 3 (Exploit Confirmation). All finding/proof shapes come
 * from @montr/contracts (golden rule #10). The interfaces below are the injection
 * seams — deterministic, offline-testable defaults are wired in `confirm.ts`,
 * while the real worker closes over the live gateway/transport/browser.
 */
import type {
  AppMap,
  AuditEventInput,
  ConfirmedFinding,
  DataFlowHop,
  Effort,
  LLMGateway,
  ProbableFinding,
  Severity,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { SemanticMatch } from "@montr/semantic-index";
import type { FalsePositiveTuning } from "./tuning.js";
import type { TestRunner } from "./evidence.js";

/**
 * Layer 3 input. Mirrors the frozen `Layer3JobData` the orchestrator builds
 * (allowLive + stagingUrl) plus the correlation output and App Map it operates
 * on. `allowLive` is the orchestrator's approver-authorization gate; this layer
 * independently RE-ENFORCES every guardrail at the HTTP layer (defense in depth).
 */
export interface ConfirmInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  probable: ProbableFinding[];
  /** ⛔ Live DAST toggle — OFF unless staging is authorized by an approver (DECIDE-1). */
  allowLive: boolean;
  stagingUrl?: string;
  config: MontrConfig;
  /**
   * Local checkout root for this scan's repo (E1). Optional — when absent,
   * the investigation loop's `read_file`/`grep`/`find_definition` tools
   * degrade to a clear "no repo checkout available" message rather than
   * throwing, and the App-Map-only tools (`list_routes`, `get_orm_model`,
   * `query_call_graph`) keep working fully. Mirrors `LayerRunnerOptions`'s
   * `resolveRepoRoot` convention in `apps/worker/src/runners.ts` (that
   * file is outside this change's scope — wiring a real value through from
   * the worker is a natural, narrow follow-up, matching this codebase's
   * established "built, tested, and documented as not-yet-wired" pattern,
   * e.g. A31's Batch API).
   */
  repoRoot?: string;
}

/**
 * E1/E4 tuning knob for the agentic investigation loop and its adversarial
 * verifier panel (`investigate.ts`, `adversarial.ts`). EVERYTHING here is
 * optional and the loop is OFF unless `enabled: true` is explicitly set —
 * unlike the single-call static LLM veto, a multi-turn tool loop plus N
 * verifier calls is a materially larger cost/latency profile per
 * unconfirmed finding, so defaulting it on would silently multiply LLM
 * calls for every existing deployment and caller. Wiring a production
 * default (e.g. a `config.confirmation.investigation.enabled` schema field
 * read by `apps/worker/src/runners.ts`) is a natural follow-up outside this
 * change's file scope (packages/confirm/src/**, packages/appmap/src/** and
 * packages/llm-gateway/src/** read-only).
 *
 * A3 (2026-09-12) update: that production default now exists —
 * `@montr/config`'s `ConfirmationInvestigationConfigSchema`
 * (`packages/config/src/schema.ts`), populated by
 * `apps/worker/src/runners.ts`'s Layer 3 runner — and, per the owner's
 * explicit decision, defaults `enabled` to TRUE (a deliberate deviation from
 * every other agentic-loop toggle in this codebase, all of which default
 * OFF; see that schema's doc comment for the full rationale). This interface
 * itself is UNCHANGED in that regard: `enabled` here still defaults to
 * `undefined`/falsy when a caller builds `ConfirmDeps` directly (every
 * existing offline test is unaffected) — only the worker's production
 * wiring picks a different default.
 */
export interface InvestigationConfig {
  /** OFF by default — see the interface doc comment above. */
  enabled?: boolean;
  /**
   * Soft per-call turn cap (default 6). Always clamped to the hard
   * structural ceiling in `investigate.ts` (8) regardless of this value —
   * that ceiling cannot be raised via config, by design.
   */
  maxTurns?: number;
  /** Extended-thinking/reasoning depth for investigation + verifier calls. Default "high". */
  effort?: Effort;
  /** Number of E4 adversarial verifiers to run (default + hard cap: 4, one per defined lens). */
  verifierCount?: number;
  /**
   * A3 scoping (2026-09-12): when set, `confirm.ts` only offers a not-yet-
   * confirmed finding to this loop when its CATEGORY's base severity —
   * `baseSeverityForCategory(finding.category)` in `taxonomy.ts` — is one of
   * these values. Absent/undefined ⇒ no severity restriction (every existing
   * test that doesn't set this is unaffected). The worker's production
   * wiring defaults this to `["high", "critical"]` (owner decision) so the
   * loop's real cost only lands on the categories it exists to help — `idor`
   * and `broken_access_control` have zero static data-flow proof at all
   * (`taxonomy.ts`'s `DATAFLOW_SINK_KINDS`) and are only reachable this way
   * absent live DAST.
   *
   * Deliberately NOT `deriveSeverity(finding.category, finding.exposure)`
   * (the exposure-discounted function that assigns a *confirmed* finding's
   * final severity): idor/broken_access_control are both base "high", but
   * deriveSeverity downgrades a non-public-exposure instance one tier to
   * "medium" — and the overwhelmingly common real-world case for both
   * categories is authenticated-only, not anonymous-public. Gating
   * eligibility on the exposure-discounted value would silently exclude that
   * common case from the default scope, defeating the reason this loop
   * exists. Category base severity is a cost-gate signal ("is this class of
   * finding inherently worth the spend"), not a claim about this specific
   * finding's final severity — that's still computed correctly at
   * confirmation time via `deriveSeverity`, unaffected by this gate.
   */
  severities?: Severity[];
}

/** Structural audit sink. @montr/telemetry's AuditLogClient / state-store's AuditLog satisfy it. */
export interface AuditSink {
  append(input: AuditEventInput): Promise<unknown> | unknown;
}

/** Structural subset of @montr/security's `EgressGuard` (golden rule #1). */
export interface EgressGuardLike {
  assert(target: string): void;
  isAllowed(target: string): boolean;
}

/** Minimal structured logger (subset of @montr/telemetry's Logger). */
export interface ConfirmLogger {
  debug?(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

/* ------------------------------- live DAST I/O ------------------------------ */

export interface LiveHttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  /** ⛔ Kill switch — the transport MUST abort in-flight when this fires. */
  signal?: AbortSignal;
}

export interface LiveHttpResponse {
  status: number;
  headers?: Record<string, string>;
  body: string;
}

/** Outbound HTTP for live probing. Default: undici. Tests inject a fake. */
export interface LiveHttpTransport {
  send(req: LiveHttpRequest): Promise<LiveHttpResponse>;
}

/** A carried authenticated session captured by the browser driver. */
export interface AuthenticatedSession {
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

export interface BrowserLoginRequest {
  loginUrl: string;
  username?: string;
  password?: string;
  signal?: AbortSignal;
}

/**
 * Authenticated-flow driver for live DAST. Default: playwright-core (lazily
 * loaded, degrades gracefully when the browser is absent). Tests inject a fake.
 */
export interface BrowserDriver {
  login(req: BrowserLoginRequest): Promise<AuthenticatedSession>;
  close?(): Promise<void>;
}

/* -------------------------------- dependencies ------------------------------ */

/**
 * Injected collaborators. Everything is optional so `confirmFindings` runs fully
 * offline with pure static confirmation and no live target.
 */
export interface ConfirmDeps {
  /** Confirmation-tier gateway. Enriches the static argument + acts as a fail-safe VETO (can only demote). */
  llm?: LLMGateway;
  /** ⛔ Kill switch. Honored between findings and before/around every probe. */
  signal?: AbortSignal;
  audit?: AuditSink;
  logger?: ConfirmLogger;
  /**
   * E10 — optional intra-layer progress callback. Mirrors
   * `@montr/orchestrator`'s `LayerContext.emitProgress(phase, pct, message)`
   * exactly (same signature) and follows the identical wiring pattern as
   * `signal`/`logger` above: `apps/worker/src/runners.ts`'s layer3 runner
   * passes `ctx.emitProgress` straight through. Consumed today only by the
   * E1 investigation loop (`investigate.ts`), called once per tool-call
   * turn with a human-readable phase/message. Omitting it leaves the
   * investigation loop — and every other path in this package — byte-
   * identical to before; this is purely additive telemetry, never load-
   * bearing for a confirmation decision.
   */
  emitProgress?: (phase: string, pct: number, message?: string) => void;
  /** ⛔ Egress guard. Default built from @montr/security with { includeDastTargets: true }. */
  egressGuard?: EgressGuardLike;
  transport?: LiveHttpTransport;
  browser?: BrowserDriver;
  /** Deterministic clock for `createdAt`. Default `() => new Date().toISOString()`. */
  now?: () => string;
  /** Monotonic ms clock for rate limiting. Default `Date.now`. */
  clockMs?: () => number;
  /** Throttle primitive for the rate limiter. Default real setTimeout (abortable). */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Deterministic id for a confirmed finding. Default `cf_<proofType>_<probableId>`. */
  idFactory?: (probable: ProbableFinding, proofType: "static" | "live") => string;
  /**
   * Whether the LLM cross-check may demote a statically-reachable finding when it
   * judges it NOT exploitable (fail-safe, golden rule #4). Defaults to true when
   * an `llm` is supplied. The LLM can NEVER promote — only the deterministic
   * data-flow proof confirms.
   */
  useLlmCrossCheck?: boolean;
  /**
   * ⛔ §15 regression-corpus tuning (fail-safe). When supplied, a probable finding
   * whose (category, file, line) matches an operator-marked known false positive
   * is SKIPPED and routed straight to the Unconfirmed appendix (kept, never
   * deleted). Additive; can only make confirmation more conservative.
   */
  fpTuning?: FalsePositiveTuning;
  /**
   * E1/E4 — agentic investigation loop + adversarial verifier panel tuning.
   * OFF by default (`enabled` unset/false) — see {@link InvestigationConfig}.
   */
  investigation?: InvestigationConfig;
  /**
   * E2 — injectable executable-evidence test runner. Default: a real, lazy
   * `vitest` subprocess runner scoped to exactly the one existing test file
   * the investigation loop named (`evidence.ts`'s `createDefaultTestRunner`).
   * Tests inject a fake, mirroring `transport`/`browser`'s convention.
   */
  testRunner?: TestRunner;
  /**
   * A9 — optional semantic-code-search callback (`@montr/semantic-index`'s
   * `querySemanticIndex`), wired into the E1 investigation loop's new
   * `semantic_search` tool (`investigate-tools.ts`) so the investigator can
   * retrieve structurally/semantically similar code by MEANING alongside its
   * literal `grep`/`find_definition` tools — e.g. sweeping a confirmed
   * finding's vulnerable pattern into other locations across the repo.
   * Absent ⇒ `semantic_search` still appears in the loop's tool list (so the
   * model's behavior is stable across a deployment where the index sometimes
   * is and sometimes isn't available) but degrades to an honest "not
   * available" tool result — never a crash, and never silently indistinguishable
   * from "no matches found". Constructed in `apps/worker/src/runners.ts`,
   * gated on the same `config.semanticIndex.enabled` + embeddings-capable
   * provider + pgvector availability as the Layer 0 index build itself — see
   * docs/modules/semantic-index.md's Consumption Status.
   */
  semanticSearch?: (queryText: string, topK?: number) => Promise<SemanticMatch[]>;
}

/* --------------------------------- outcomes -------------------------------- */

export interface StaticConfirmOutcome {
  kind: "confirmed" | "unconfirmed";
  finding?: ConfirmedFinding;
  /** Populated when `kind === "unconfirmed"`. */
  reason?: string;
  /** The deterministic data-flow trace (present whether or not it confirmed). */
  dataFlow: DataFlowHop[];
}

export interface LiveConfirmOutcome {
  confirmed: boolean;
  finding?: ConfirmedFinding;
  reason?: string;
  /** The captured request/response transcript (proof, or partial evidence). */
  exchanges: import("@montr/contracts").HttpExchange[];
}
