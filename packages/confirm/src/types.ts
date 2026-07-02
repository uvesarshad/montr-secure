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
  LLMGateway,
  ProbableFinding,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

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
