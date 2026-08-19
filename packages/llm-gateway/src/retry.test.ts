import { describe, it, expect, vi } from "vitest";
import { RateLimitExceededError, MontrError } from "@montr/contracts";
import { withRetry, DEFAULT_RETRY_POLICY, type RetryPolicy } from "./retry.js";

/**
 * Uniform retry + backoff for every adapter (§8.2). Retryable failures (rate
 * limits, transient 5xx, timeouts) get exponential backoff up to `maxRetries`;
 * non-retryable failures (e.g. auth errors) must fail immediately with no
 * wasted attempt. Sleeps are injected so these tests run with zero real delay.
 */

function fakePolicy(overrides: Partial<RetryPolicy> = {}): RetryPolicy {
  const sleepCalls: number[] = [];
  const sleep = vi.fn(async (ms: number) => {
    sleepCalls.push(ms);
  });
  return { ...DEFAULT_RETRY_POLICY, sleep, ...overrides };
}

describe("withRetry", () => {
  it("returns the result immediately on first-attempt success (no retries, no sleep)", async () => {
    const policy = fakePolicy();
    const fn = vi.fn(async () => "ok");
    const result = await withRetry(fn, policy);
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(policy.sleep).not.toHaveBeenCalled();
  });

  it("retries a retryable failure and succeeds on a later attempt", async () => {
    const policy = fakePolicy({ maxRetries: 3 });
    let calls = 0;
    const fn = vi.fn(async () => {
      calls++;
      if (calls < 3) throw new RateLimitExceededError("rate limited");
      return "recovered";
    });
    const result = await withRetry(fn, policy);
    expect(result).toBe("recovered");
    expect(fn).toHaveBeenCalledTimes(3);
    // Two failed attempts before success -> two backoff sleeps.
    expect(policy.sleep).toHaveBeenCalledTimes(2);
  });

  it("applies exponential backoff: delay doubles each retry, capped at maxDelayMs", async () => {
    const sleepCalls: number[] = [];
    const policy: RetryPolicy = {
      maxRetries: 4,
      baseDelayMs: 100,
      maxDelayMs: 350,
      sleep: async (ms) => {
        sleepCalls.push(ms);
      },
    };
    let calls = 0;
    const fn = vi.fn(async () => {
      calls++;
      if (calls <= 4) throw new RateLimitExceededError("rate limited");
      return "ok";
    });
    await withRetry(fn, policy);
    // attempt 0 -> 100, attempt 1 -> 200, attempt 2 -> 400 capped to 350, attempt 3 -> 800 capped to 350
    expect(sleepCalls).toEqual([100, 200, 350, 350]);
  });

  it("does NOT retry a non-retryable failure — fails on the very first attempt", async () => {
    const policy = fakePolicy({ maxRetries: 5 });
    const nonRetryable = new MontrError("CONFIG_VALIDATION", "bad config", { retriable: false });
    const fn = vi.fn(async () => {
      throw nonRetryable;
    });
    await expect(withRetry(fn, policy)).rejects.toBe(nonRetryable);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(policy.sleep).not.toHaveBeenCalled();
  });

  it("does NOT retry a structurally-classified non-retryable error (e.g. 401 auth failure)", async () => {
    const policy = fakePolicy({ maxRetries: 5 });
    const authError = Object.assign(new Error("unauthorized"), { status: 401 });
    const fn = vi.fn(async () => {
      throw authError;
    });
    await expect(withRetry(fn, policy)).rejects.toBe(authError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("exceeds max retries and surfaces the final error (not the first)", async () => {
    const policy = fakePolicy({ maxRetries: 2 });
    let calls = 0;
    const fn = vi.fn(async () => {
      calls++;
      throw new RateLimitExceededError(`attempt ${calls} failed`);
    });
    await expect(withRetry(fn, policy)).rejects.toThrow("attempt 3 failed");
    // maxRetries=2 -> 3 total attempts (1 initial + 2 retries).
    expect(fn).toHaveBeenCalledTimes(3);
    expect(policy.sleep).toHaveBeenCalledTimes(2);
  });

  it("retries a structurally-classified retryable error (e.g. 429/503 status)", async () => {
    const policy = fakePolicy({ maxRetries: 1 });
    let calls = 0;
    const fn = vi.fn(async () => {
      calls++;
      if (calls === 1) throw Object.assign(new Error("service unavailable"), { status: 503 });
      return "ok";
    });
    const result = await withRetry(fn, policy);
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });
});
