/**
 * Retry + backoff, driven by the per-layer `RETRY_POLICIES` from
 * @montr/contracts. Retry lives in ONE place so inline and BullMQ execution
 * behave identically; process-crash recovery is handled separately by resume().
 *
 * The loop is kill-switch aware: an aborted signal stops retrying immediately
 * (no thundering herd against a DAST target after a kill).
 */
import { isMontrError, KillSwitchActivatedError, type RetryPolicy } from "@montr/contracts";

/** Injectable sleep so tests run retries without real wall-clock delay. */
export type SleepFn = (ms: number, signal?: AbortSignal) => Promise<void>;

export const realSleep: SleepFn = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortReason(signal));
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = () => {
      cleanup();
      reject(abortReason(signal));
    };
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });

function abortReason(signal?: AbortSignal): unknown {
  return signal?.reason ?? new KillSwitchActivatedError("aborted");
}

function backoffDelayMs(policy: RetryPolicy, retryIndex: number): number {
  return policy.backoff.type === "exponential"
    ? policy.backoff.delay * 2 ** retryIndex
    : policy.backoff.delay;
}

/**
 * A typed error is retried only when it explicitly marks itself retriable
 * (e.g. RateLimitExceeded). Definitive typed errors (BudgetExceeded,
 * GateNotPassed, KillSwitchActivated, …) are never retried. Untyped errors are
 * treated as transient and retried.
 */
function isRetriable(err: unknown): boolean {
  if (isMontrError(err)) return err.retriable;
  return true;
}

export interface RunWithRetryOptions {
  readonly sleep?: SleepFn;
  readonly onRetry?: (attempt: number, err: unknown) => void;
}

/**
 * Run `fn` up to `policy.attempts` times. `fn` receives the 0-based attempt
 * index. Honors the kill switch (abort → stop) and the typed-error retriability.
 */
export async function runWithRetry<T>(
  policy: RetryPolicy,
  signal: AbortSignal,
  fn: (attempt: number) => Promise<T>,
  opts: RunWithRetryOptions = {},
): Promise<T> {
  const sleep = opts.sleep ?? realSleep;
  const attempts = Math.max(1, policy.attempts);
  let lastErr: unknown;

  for (let i = 0; i < attempts; i++) {
    if (signal.aborted) throw abortReason(signal);
    try {
      return await fn(i);
    } catch (err) {
      lastErr = err;
      // Kill switch or definitively non-retriable → surface immediately.
      if (signal.aborted || !isRetriable(err)) throw err;
      if (i === attempts - 1) break;
      opts.onRetry?.(i + 1, err);
      await sleep(backoffDelayMs(policy, i), signal);
    }
  }
  throw lastErr;
}
