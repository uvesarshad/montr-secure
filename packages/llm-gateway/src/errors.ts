import { MontrError, RateLimitExceededError, type Provider } from "@montr/contracts";

/**
 * Provider-error classification + mapping into the typed @montr/contracts error
 * taxonomy. No provider SDK is imported here — we classify structurally
 * (`.status`, error name) so the same logic covers all four adapters.
 */

/** HTTP statuses that are safe to retry with backoff. */
const RETRIABLE_STATUS = new Set([408, 409, 425, 429, 500, 502, 503, 504, 529]);

function statusOf(err: unknown): number | undefined {
  if (typeof err !== "object" || err === null) return undefined;
  const rec = err as Record<string, unknown>;
  for (const key of ["status", "statusCode", "$metadata"] as const) {
    const v = rec[key];
    if (typeof v === "number") return v;
    if (key === "$metadata" && typeof v === "object" && v !== null) {
      const code = (v as Record<string, unknown>).httpStatusCode;
      if (typeof code === "number") return code;
    }
  }
  return undefined;
}

function nameOf(err: unknown): string {
  if (err instanceof Error) return err.name;
  if (typeof err === "object" && err !== null) {
    const n = (err as Record<string, unknown>).name;
    if (typeof n === "string") return n;
  }
  return "";
}

/** True when the failure is transient and a retry could succeed. */
export function isRetriableProviderError(err: unknown): boolean {
  if (err instanceof MontrError) return err.retriable;
  const status = statusOf(err);
  if (status !== undefined) return RETRIABLE_STATUS.has(status);
  const name = nameOf(err);
  // Timeouts, aborts, and low-level connection failures are transient.
  if (/Abort|Timeout|Connection|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket/i.test(name)) {
    return true;
  }
  const message = err instanceof Error ? err.message : String(err ?? "");
  return /timed out|timeout|ECONNRESET|ETIMEDOUT|socket hang up|network|fetch failed/i.test(
    message,
  );
}

/**
 * Wrap a raw provider error in a typed MontrError. 429 → RateLimitExceededError
 * (retriable); everything else → INTERNAL with a retriable flag. Details are
 * metadata-only (provider + status) — never request/response bodies.
 */
export function toGatewayError(err: unknown, provider: Provider): MontrError {
  if (err instanceof MontrError) return err;
  const status = statusOf(err);
  const retriable = isRetriableProviderError(err);
  const message = err instanceof Error ? err.message : String(err ?? "unknown provider error");
  const details: Record<string, unknown> = { provider };
  if (status !== undefined) details.status = status;

  if (status === 429) {
    return new RateLimitExceededError(`LLM provider rate limit (${provider})`, details);
  }
  return new MontrError("INTERNAL", `LLM provider call failed (${provider}): ${message}`, {
    retriable,
    details,
    cause: err,
  });
}

/** A gateway-level timeout, surfaced as a retriable INTERNAL error. */
export function timeoutError(provider: Provider, timeoutMs: number): MontrError {
  return new MontrError("INTERNAL", `LLM provider call timed out after ${timeoutMs}ms`, {
    retriable: true,
    details: { provider, timeoutMs },
  });
}
