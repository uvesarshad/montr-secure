/**
 * ⛔ Red-team scenario library (Phase-4 / Wave 5, PRD §16, build-plan §8).
 *
 * A red-team scenario is a reusable, versioned parameterization of the SAME
 * heavily-gated Layer-3 live-DAST engine — it adds NO new egress path. Running
 * one reuses, without exception:
 *   - {@link assertLiveAuthorized} — dast enabled + approver-authorized + target
 *     allowlisted + production blocked (§11), and
 *   - {@link ScopeGuard} — kill switch, allowlist, production block, rate +
 *     blast-radius caps, and @montr/security's egress guard, on EVERY probe.
 *
 * `runScenario` is transport-agnostic: with a `transport` it actually probes an
 * authorized allowlisted staging target (the DAST engine, mockable in tests);
 * WITHOUT one it performs the full authorization + per-step guardrail gate and
 * NEVER leaves the process (the API uses this "authorize + gate + audit" mode —
 * probing itself belongs to the worker). Either way, a non-allowlisted or
 * production target is refused BEFORE any request is crafted.
 */
import {
  KillSwitchActivatedError,
  type HttpExchange,
  type RedTeamScenario,
  type RedTeamStep,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { assertLiveAuthorized, ScopeGuard, buildDefaultEgressGuard, hostOf } from "./guard.js";
import type {
  ConfirmLogger,
  EgressGuardLike,
  LiveHttpResponse,
  LiveHttpTransport,
} from "./types.js";

/* ============================== validation ============================== */

export interface ScenarioValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** True when `path` is a target-relative path, not an absolute/scheme-relative URL. */
export function isRelativePath(path: string): boolean {
  const p = path.trim();
  if (p.startsWith("//")) return false; // scheme-relative → resolves to another host
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) return false; // absolute URL (http://, etc.)
  return true;
}

/**
 * ⛔ Structural validation of a scenario BEFORE it is stored/enabled. A scenario
 * step path must be RELATIVE to the allowlisted target — an absolute URL would let
 * a step smuggle an off-allowlist destination, so it is rejected (defense in depth
 * on top of the per-probe allowlist gate).
 */
export function validateScenario(
  scenario: Pick<RedTeamScenario, "name" | "steps" | "targetAllowlistRef">,
): ScenarioValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!scenario.targetAllowlistRef || scenario.targetAllowlistRef.trim().length === 0) {
    errors.push(
      "targetAllowlistRef is required — a scenario must be bound to an allowlisted target",
    );
  }
  if (!Array.isArray(scenario.steps) || scenario.steps.length === 0) {
    warnings.push("scenario has no steps — it will authorize but probe nothing");
  }
  const seenOrders = new Set<number>();
  for (const [i, step] of (scenario.steps ?? []).entries()) {
    if (seenOrders.has(step.order)) warnings.push(`steps[${i}] duplicates order ${step.order}`);
    seenOrders.add(step.order);
    if (step.path !== undefined && !isRelativePath(step.path)) {
      errors.push(
        `steps[${i}].path must be relative to the allowlisted target (no absolute/scheme-relative URL): ${step.path}`,
      );
    }
    if (step.method && MUTATING_METHODS.has(step.method.toUpperCase())) {
      warnings.push(
        `steps[${i}] is ${step.method.toUpperCase()} (mutating) — it is capped by dast.scope.maxMutatingRequests (0 by default)`,
      );
    }
  }
  return { valid: errors.length === 0, errors, warnings };
}

/* =============================== execution =============================== */

export interface ScenarioAuthzInput {
  scenario: RedTeamScenario;
  config: MontrConfig;
  /** ⛔ Approver authorization gate (true once the RBAC approver check passed). */
  allowLive: boolean;
  /** Optional target override — must ALSO be on the allowlist (validated). */
  targetOverride?: string;
}

/** The target a scenario runs against (override wins; else its bound ref). */
export function resolveScenarioTarget(
  scenario: Pick<RedTeamScenario, "targetAllowlistRef">,
  override?: string,
): string {
  const o = override?.trim();
  return o && o.length > 0 ? o : scenario.targetAllowlistRef;
}

/**
 * ⛔ Assert a scenario is authorized to run and return the validated target. Reuses
 * the Layer-3 live-DAST authorization gate verbatim: throws
 * {@link DastTargetNotAllowlistedError} / {@link HumanApprovalRequiredError} when
 * DAST is disabled, the caller is not an approver, or the target is off-allowlist
 * or looks like production. No probe is crafted before this passes.
 */
export function assertScenarioAuthorized(input: ScenarioAuthzInput): string {
  const target = resolveScenarioTarget(input.scenario, input.targetOverride);
  return assertLiveAuthorized({
    config: input.config,
    allowLive: input.allowLive,
    stagingUrl: target,
  });
}

export interface ScenarioStepResult {
  order: number;
  action: string;
  method: string;
  path: string;
  url: string;
  /** Whether a request was actually sent (false in gate-only/authorize mode). */
  probed: boolean;
  status?: number;
  /** Set when a guardrail (caps/allowlist/egress) stopped this step. */
  blocked?: boolean;
  reason?: string;
}

export interface ScenarioRunResult {
  scenarioId: string;
  target: string;
  /** Always true when returned — the authorization gate threw otherwise. */
  authorized: true;
  /** True iff at least one request was actually sent (a transport was supplied). */
  probed: boolean;
  /** True iff a guardrail stopped the run early (e.g. blast-radius cap). */
  blocked: boolean;
  requestsSent: number;
  mutatingSent: number;
  steps: ScenarioStepResult[];
  /** Captured request/response transcript (proof) when probing. */
  transcript: HttpExchange[];
}

export interface ScenarioRunDeps {
  /** ⛔ Egress guard. Default built from @montr/security (folds in DAST targets). */
  egressGuard?: EgressGuardLike;
  /**
   * The live DAST engine. When ABSENT, `runScenario` authorizes + gate-checks
   * every step but sends nothing (the API's mode — it never probes). When present
   * (worker / tests inject a fake), authorized allowlisted steps are probed.
   */
  transport?: LiveHttpTransport;
  /** ⛔ Kill switch — halts the run instantly, everywhere. */
  signal?: AbortSignal;
  clockMs?: () => number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  logger?: ConfirmLogger;
}

const MAX_SNIPPET = 512;
const REDACTED_HEADERS = new Set(["authorization", "cookie", "set-cookie", "x-api-key"]);

function truncate(s: string, n = MAX_SNIPPET): string {
  return s.length > n ? `${s.slice(0, n)}…[truncated ${s.length - n} chars]` : s;
}

function safeHeaders(headers?: Record<string, string>): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = REDACTED_HEADERS.has(k.toLowerCase()) ? "[redacted]" : v;
  }
  return out;
}

/** Substitute dynamic route segments (`[id]`, `:id`) with a benign concrete value. */
function concretePath(path: string): string {
  const p = path.startsWith("/") ? path : `/${path}`;
  return p.replace(/\[[^\]]+\]/g, "1").replace(/:([A-Za-z0-9_]+)/g, "1");
}

function joinUrl(target: string, path: string): string {
  return `${target.replace(/\/$/, "")}${concretePath(path)}`;
}

function isAbort(err: unknown): boolean {
  if (err instanceof KillSwitchActivatedError) return true;
  const e = err as { name?: string; code?: string } | null;
  return e?.name === "AbortError" || e?.code === "UND_ERR_ABORTED";
}

function asKill(err: unknown): KillSwitchActivatedError {
  return err instanceof KillSwitchActivatedError
    ? err
    : new KillSwitchActivatedError("red-team scenario aborted by kill switch");
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function toExchange(
  method: string,
  url: string,
  note: string,
  response: LiveHttpResponse,
  body?: string,
): HttpExchange {
  const resHeaders = safeHeaders(response.headers);
  return {
    request: {
      method,
      url,
      ...(body !== undefined ? { bodySnippet: truncate(body) } : {}),
    },
    response: {
      status: response.status,
      ...(resHeaders ? { headers: resHeaders } : {}),
      bodySnippet: truncate(response.body ?? ""),
    },
    note,
  };
}

/**
 * ⛔ Run a red-team scenario against its allowlisted target through the Layer-3
 * guardrails. Authorization is asserted FIRST (off-allowlist / production /
 * unauthorized → throws before any probe). Then every step passes the full
 * {@link ScopeGuard} pre-flight (kill switch → caps → allowlist → production →
 * egress) before a request is sent. Throws {@link KillSwitchActivatedError} if the
 * kill switch fires; any other guardrail refusal stops the run (fail-safe) and is
 * reported as a blocked step rather than a crafted probe.
 */
export async function runScenario(
  input: ScenarioAuthzInput,
  deps: ScenarioRunDeps = {},
): Promise<ScenarioRunResult> {
  // 1. ⛔ Hard gate — refuse before crafting anything. Non-allowlisted / production
  //    / unauthorized / DAST-disabled all throw here.
  const target = assertScenarioAuthorized(input);

  // 2. Egress guard + per-run scope guard (blast-radius caps, rate limit, kill).
  const egressGuard = deps.egressGuard ?? (await buildDefaultEgressGuard(input.config));
  const guard = new ScopeGuard({
    config: input.config,
    egressGuard,
    ...(deps.signal ? { signal: deps.signal } : {}),
    ...(deps.clockMs ? { clockMs: deps.clockMs } : {}),
    ...(deps.sleep ? { sleep: deps.sleep } : {}),
    ...(deps.logger ? { logger: deps.logger } : {}),
  });

  const steps = [...input.scenario.steps].sort((a, b) => a.order - b.order);
  const results: ScenarioStepResult[] = [];
  const transcript: HttpExchange[] = [];
  let blocked = false;
  let probedAny = false;

  for (const step of steps) {
    const method = (step.method ?? "GET").toUpperCase();
    const path = step.path ?? "/";
    const url = joinUrl(target, path);

    // ⛔ Full pre-flight guardrail gate BEFORE anything leaves the process.
    try {
      guard.assertProbeAllowed(url, method);
    } catch (err) {
      if (isAbort(err)) throw asKill(err); // kill switch → halt everything
      deps.logger?.warn?.("scenario: step blocked by guardrail; halting run", {
        scenarioId: input.scenario.id,
        order: step.order,
        error: msg(err),
      });
      results.push({
        order: step.order,
        action: step.action,
        method,
        path,
        url,
        probed: false,
        blocked: true,
        reason: msg(err),
      });
      blocked = true;
      break;
    }

    // Gate-only (authorize) mode: no transport ⇒ never send.
    if (!deps.transport) {
      results.push({ order: step.order, action: step.action, method, path, url, probed: false });
      continue;
    }

    let response: LiveHttpResponse;
    try {
      await guard.throttle();
      guard.assertNotKilled();
      response = await deps.transport.send({
        method,
        url,
        ...(step.body !== undefined ? { body: step.body } : {}),
        ...(deps.signal ? { signal: deps.signal } : {}),
      });
    } catch (err) {
      if (isAbort(err)) throw asKill(err);
      deps.logger?.warn?.("scenario: probe transport error; halting run", {
        scenarioId: input.scenario.id,
        order: step.order,
        error: msg(err),
      });
      results.push({
        order: step.order,
        action: step.action,
        method,
        path,
        url,
        probed: false,
        blocked: true,
        reason: msg(err),
      });
      blocked = true;
      break;
    }

    guard.record(method);
    probedAny = true;
    transcript.push(toExchange(method, url, step.action, response, step.body));
    results.push({
      order: step.order,
      action: step.action,
      method,
      path,
      url,
      probed: true,
      status: response.status,
    });
  }

  return {
    scenarioId: input.scenario.id,
    target,
    authorized: true,
    probed: probedAny,
    blocked,
    requestsSent: guard.requestsSent,
    mutatingSent: guard.mutatingSent,
    steps: results,
    transcript,
  };
}

export type { RedTeamStep };
export { hostOf };
