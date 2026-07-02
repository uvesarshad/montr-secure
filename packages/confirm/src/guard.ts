/**
 * ⛔ Live-DAST guardrails, enforced at the HTTP layer (build-plan §5.4, §11).
 *
 * Every one of these is NON-NEGOTIABLE and enforced HERE regardless of what the
 * orchestrator already checked (defense in depth):
 *   - target allowlist (strict host match — no suffix/substring bypass),
 *   - production blocked by policy,
 *   - approver authorization required before any live run,
 *   - kill switch halts probing instantly,
 *   - rate limit + blast-radius caps (per-scan + mutating-request caps),
 *   - all outbound routed through @montr/security's egress guard.
 * Failing any check throws a typed error; nothing is probed.
 */
import {
  DastTargetNotAllowlistedError,
  HumanApprovalRequiredError,
  KillSwitchActivatedError,
  RateLimitExceededError,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { ConfirmLogger, EgressGuardLike } from "./types.js";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Host markers that force a production classification (blocked by policy). */
const PRODUCTION_MARKERS = ["prod", "production", "www.", "live.", "release"];
/** Host markers that positively identify a non-production (staging/test) target. */
const STAGING_MARKERS = [
  "staging",
  "stage",
  "test",
  "dev",
  "qa",
  "uat",
  "sandbox",
  "preview",
  "canary",
  "localhost",
  "127.0.0.1",
  ".internal",
  ".local",
];

function toUrl(raw: string): URL {
  const s = raw.trim();
  if (!s) throw new DastTargetNotAllowlistedError("empty DAST target", { target: raw });
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return new URL(s);
    return new URL(`https://${s}`);
  } catch {
    throw new DastTargetNotAllowlistedError(`invalid DAST target URL: ${s}`, { target: s });
  }
}

/** Lowercased host (with non-default port) of a target, or the raw string if unparseable. */
export function hostOf(target: string): string {
  try {
    return toUrl(target).host.toLowerCase();
  } catch {
    return target;
  }
}

/**
 * Strict allowlist check: the target's HOST must exactly equal an allowlist
 * entry's host (defeating `staging.example.com.evil.net`-style suffix bypasses),
 * and its path must sit under the entry's path. Bare exact-string matches also pass.
 */
export function isAllowlisted(target: string, allowlist: readonly string[]): boolean {
  let u: URL;
  try {
    u = toUrl(target);
  } catch {
    return false;
  }
  const host = u.host.toLowerCase();
  const path = u.pathname || "/";
  for (const entry of allowlist) {
    if (target === entry) return true;
    let e: URL;
    try {
      e = toUrl(entry);
    } catch {
      continue;
    }
    if (e.host.toLowerCase() !== host) continue; // exact host — no suffix bypass
    const root = (e.pathname || "/").replace(/\/$/, ""); // strip trailing slash
    if (root === "" || path === root || path.startsWith(`${root}/`)) return true;
  }
  return false;
}

/**
 * Whether a target looks like production. Positive staging markers win; otherwise
 * an explicit production marker classifies it as production. Unparseable → block
 * (fail-safe). A neutral host is NOT flagged here — the allowlist is authoritative.
 */
export function looksLikeProduction(target: string): boolean {
  let host: string;
  try {
    host = toUrl(target).host.toLowerCase();
  } catch {
    return true;
  }
  if (STAGING_MARKERS.some((m) => host.includes(m))) return false;
  return PRODUCTION_MARKERS.some((m) => host.includes(m));
}

export interface LiveAuthzInput {
  config: MontrConfig;
  /** The orchestrator's approver-authorization gate (computeAllowLive). */
  allowLive: boolean;
  stagingUrl?: string;
}

/**
 * ⛔ Assert a live run is authorized. Throws a typed error unless EVERY condition
 * holds: DAST enabled, approver authorized, a staging target that is allowlisted
 * and not production. Returns the validated target URL.
 */
export function assertLiveAuthorized(inp: LiveAuthzInput): string {
  const { config, allowLive, stagingUrl } = inp;
  const dast = config.dast;
  if (!dast.enabled) {
    throw new DastTargetNotAllowlistedError("live DAST is disabled by policy (dast.enabled=false)");
  }
  if (!allowLive) {
    throw new HumanApprovalRequiredError(
      "live DAST requires approver authorization (RBAC) before any probe",
    );
  }
  if (!stagingUrl) {
    throw new DastTargetNotAllowlistedError("no staging target provided for live DAST");
  }
  if (dast.allowlist.length === 0) {
    throw new DastTargetNotAllowlistedError("DAST allowlist is empty — nothing may be probed");
  }
  if (!isAllowlisted(stagingUrl, dast.allowlist)) {
    throw new DastTargetNotAllowlistedError(
      `staging target is not on the allowlist: ${hostOf(stagingUrl)}`,
      { host: hostOf(stagingUrl), allowlistCount: dast.allowlist.length },
    );
  }
  if (dast.productionBlocked && looksLikeProduction(stagingUrl)) {
    throw new DastTargetNotAllowlistedError(
      `staging target looks like production — blocked by policy: ${hostOf(stagingUrl)}`,
      { host: hostOf(stagingUrl) },
    );
  }
  return stagingUrl;
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abortErr = (): Error =>
      signal?.reason instanceof Error ? signal.reason : new KillSwitchActivatedError("aborted");
    if (signal?.aborted) {
      reject(abortErr());
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(abortErr());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export interface ScopeGuardOptions {
  config: MontrConfig;
  egressGuard: EgressGuardLike;
  /** ⛔ Kill switch. */
  signal?: AbortSignal;
  clockMs?: () => number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  logger?: ConfirmLogger;
}

/**
 * Per-scan live-probe gate. One instance guards a whole live run: it counts
 * requests against the blast-radius caps, throttles to the rate limit, and
 * refuses any probe that is killed / off-allowlist / production / non-egressable.
 */
export class ScopeGuard {
  private readonly scope: MontrConfig["dast"]["scope"];
  private readonly allowlist: readonly string[];
  private readonly productionBlocked: boolean;
  private readonly egressGuard: EgressGuardLike;
  private readonly signal?: AbortSignal;
  private readonly clockMs: () => number;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;

  private total = 0;
  private mutating = 0;
  private sendTimes: number[] = [];

  constructor(opts: ScopeGuardOptions) {
    this.scope = opts.config.dast.scope;
    this.allowlist = opts.config.dast.allowlist;
    this.productionBlocked = opts.config.dast.productionBlocked;
    this.egressGuard = opts.egressGuard;
    if (opts.signal) this.signal = opts.signal;
    this.clockMs = opts.clockMs ?? Date.now;
    this.sleep = opts.sleep ?? defaultSleep;
  }

  get requestsSent(): number {
    return this.total;
  }
  get mutatingSent(): number {
    return this.mutating;
  }
  get maxConcurrent(): number {
    return this.scope.maxConcurrentRequests;
  }

  /** ⛔ Throw immediately if the kill switch has fired. */
  assertNotKilled(): void {
    if (this.signal?.aborted) {
      const reason = this.signal.reason;
      if (reason instanceof KillSwitchActivatedError) throw reason;
      throw new KillSwitchActivatedError("kill switch activated — halting DAST probing");
    }
  }

  /**
   * ⛔ Full pre-flight gate for one probe. Order matters: kill switch first, then
   * blast-radius caps, then allowlist, then production, then the egress guard.
   */
  assertProbeAllowed(url: string, method: string): void {
    this.assertNotKilled();

    if (this.total >= this.scope.maxRequestsPerScan) {
      throw new RateLimitExceededError("DAST per-scan request cap reached (blast-radius)", {
        cap: this.scope.maxRequestsPerScan,
        sent: this.total,
      });
    }
    const isMutating = MUTATING_METHODS.has(method.toUpperCase());
    if (isMutating && this.mutating >= this.scope.maxMutatingRequests) {
      throw new RateLimitExceededError("DAST mutating-request cap reached (blast-radius)", {
        cap: this.scope.maxMutatingRequests,
        sent: this.mutating,
        method: method.toUpperCase(),
      });
    }
    if (!isAllowlisted(url, this.allowlist)) {
      throw new DastTargetNotAllowlistedError(
        `target not on the staging allowlist: ${hostOf(url)}`,
        {
          host: hostOf(url),
          allowlistCount: this.allowlist.length,
        },
      );
    }
    if (this.productionBlocked && looksLikeProduction(url)) {
      throw new DastTargetNotAllowlistedError(
        `production target blocked by policy: ${hostOf(url)}`,
        {
          host: hostOf(url),
        },
      );
    }
    // Outermost net: only client-authorized allowlisted staging is egressable.
    this.egressGuard.assert(url);
  }

  /** Throttle so we never exceed maxRequestsPerSecond (abortable via the kill switch). */
  async throttle(): Promise<void> {
    const rps = this.scope.maxRequestsPerSecond;
    if (!(rps > 0)) return;
    const windowMs = 1000;
    const now = this.clockMs();
    this.sendTimes = this.sendTimes.filter((t) => now - t < windowMs);
    if (this.sendTimes.length >= rps) {
      const oldest = this.sendTimes[0] ?? now;
      const wait = windowMs - (now - oldest);
      if (wait > 0) {
        this.assertNotKilled();
        await this.sleep(wait, this.signal);
        this.assertNotKilled();
      }
    }
  }

  /** Record a completed send (call AFTER the response returns). */
  record(method: string): void {
    this.total += 1;
    if (MUTATING_METHODS.has(method.toUpperCase())) this.mutating += 1;
    this.sendTimes.push(this.clockMs());
  }
}

/** Build the default egress guard from @montr/security (folds in DAST staging targets). */
export async function buildDefaultEgressGuard(config: MontrConfig): Promise<EgressGuardLike> {
  const { createEgressGuard } = await import("@montr/security");
  return createEgressGuard(config, { includeDastTargets: true });
}
