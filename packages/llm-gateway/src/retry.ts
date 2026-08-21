import type { Provider } from "@montr/contracts";
import { isRetriableProviderError, timeoutError } from "./errors.js";

/**
 * Uniform retry + backoff + per-attempt timeout for every adapter. Clocks and
 * sleeps are injectable so tests are fast and deterministic (no real timers).
 */

export type SleepFn = (ms: number) => Promise<void>;

export const defaultSleep: SleepFn = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export interface RetryPolicy {
  /** Number of retries AFTER the first attempt (total attempts = maxRetries + 1). */
  maxRetries: number;
  /** Base backoff in ms; delay for retry n is `baseDelayMs * 2^n`. */
  baseDelayMs: number;
  /** Cap on any single backoff delay. */
  maxDelayMs: number;
  sleep: SleepFn;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxRetries: 2,
  baseDelayMs: 500,
  maxDelayMs: 8000,
  sleep: defaultSleep,
};

/**
 * Run `fn` with an AbortSignal that fires after `timeoutMs`. The returned
 * promise rejects with a retriable timeout error if the deadline passes first.
 */
export function runWithTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  provider: Provider,
): Promise<T> {
  if (timeoutMs <= 0) return fn(new AbortController().signal);
  const controller = new AbortController();
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      controller.abort();
      reject(timeoutError(provider, timeoutMs));
    }, timeoutMs);
    fn(controller.signal).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err as Error);
      },
    );
  });
}

/**
 * Bound the gap between stream events: if the next event does not arrive within
 * `timeoutMs`, reject with a retriable timeout error. Guards providers whose SDK
 * does not honor an AbortSignal, so a wedged stream can never hang the pipeline.
 */
export async function* withIteratorTimeout<T>(
  iterable: AsyncIterable<T>,
  timeoutMs: number,
  provider: Provider,
): AsyncGenerator<T, void, unknown> {
  if (timeoutMs <= 0) {
    yield* iterable;
    return;
  }
  const iterator = iterable[Symbol.asyncIterator]();
  try {
    for (;;) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(timeoutError(provider, timeoutMs)), timeoutMs);
      });
      let result: IteratorResult<T>;
      try {
        result = await Promise.race([iterator.next(), timeout]);
      } finally {
        if (timer) clearTimeout(timer);
      }
      if (result.done) return;
      yield result.value;
    }
  } finally {
    await iterator.return?.();
  }
}

/** Retry a fallible async operation with exponential backoff on transient errors. */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  policy: RetryPolicy,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= policy.maxRetries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastError = err;
      const hasBudget = attempt < policy.maxRetries;
      if (!hasBudget || !isRetriableProviderError(err)) throw err;
      const delay = Math.min(policy.baseDelayMs * 2 ** attempt, policy.maxDelayMs);
      await policy.sleep(delay);
    }
  }
  throw lastError;
}

/**
 * Model-fallback cascade (A11). Previously a failing model was retried on
 * ITSELF (via {@link withRetry}) and then the call failed outright — no
 * cascade to an alternate model existed. `withRetryAndFallback` keeps that
 * exact behavior for the primary model (full `policy` — every retry, every
 * backoff), and only reaches for `fallbackModels` once the primary's retry
 * budget is exhausted (or it fails immediately on a non-retriable error).
 */
export interface ModelFallbackOptions {
  /**
   * Fallback model ids to try, in order, after the primary exhausts its
   * retry budget. Each gets exactly ONE attempt — no backoff, no retries —
   * so the cascade is bounded (never infinite) regardless of chain length.
   * A model id equal to the one already attempted is skipped (no self-fallback).
   */
  fallbackModels: readonly string[];
  /** Invoked once per fallback attempt, before it runs (for logging/metrics). */
  onFallback?: (fromModelId: string, toModelId: string) => void;
}

/**
 * Run `fn` against `primaryModelId` with the full retry policy (identical to
 * `withRetry`). If that ultimately fails, cascade through
 * `fallback.fallbackModels` in order — one bare attempt each, in the order
 * given — before surfacing an error. On total failure, throws the LAST error
 * encountered (from the final fallback attempt if any ran, otherwise the
 * primary's error) so callers see the failure closest to "why did this
 * ultimately not work."
 */
export async function withRetryAndFallback<T>(
  primaryModelId: string,
  fn: (modelId: string, attempt: number) => Promise<T>,
  policy: RetryPolicy,
  fallback: ModelFallbackOptions = { fallbackModels: [] },
): Promise<T> {
  try {
    return await withRetry((attempt) => fn(primaryModelId, attempt), policy);
  } catch (primaryErr) {
    let lastError: unknown = primaryErr;
    const attemptedModels = new Set([primaryModelId]);
    for (const fallbackModelId of fallback.fallbackModels) {
      if (attemptedModels.has(fallbackModelId)) continue;
      attemptedModels.add(fallbackModelId);
      fallback.onFallback?.(primaryModelId, fallbackModelId);
      try {
        return await fn(fallbackModelId, 0);
      } catch (fallbackErr) {
        lastError = fallbackErr;
      }
    }
    throw lastError;
  }
}
