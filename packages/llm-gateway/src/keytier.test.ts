import { describe, it, expect, vi } from "vitest";
import { KeyTierRejectedError } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";
import { detectKeyTier, applyKeyTierGuard } from "./keytier.js";

/**
 * ⛔ Key-tier guard (§11): warn or block on suspected data-retaining key
 * tiers. Cloud providers running in the client's own tenancy are classified
 * `enterprise` (not suspect); a direct Anthropic key can't be confirmed from
 * the key string alone and fails safe to `unknown` (suspect) — golden rule
 * #4: uncertainty resolves toward less autonomy.
 */

function spyLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn(() => logger),
  };
  return logger;
}

describe("detectKeyTier", () => {
  it("an operator-declared tier always wins, even over a cloud provider", () => {
    expect(detectKeyTier({ provider: "bedrock", declaredTier: "data_retaining" })).toBe(
      "data_retaining",
    );
  });

  it("classifies bedrock/vertex/azure as 'enterprise' (own-tenancy BAA/DPA)", () => {
    expect(detectKeyTier({ provider: "bedrock" })).toBe("enterprise");
    expect(detectKeyTier({ provider: "vertex" })).toBe("enterprise");
    expect(detectKeyTier({ provider: "azure" })).toBe("enterprise");
  });

  it("classifies a direct Anthropic key as 'unknown' (cannot be confirmed) — fail-safe", () => {
    expect(detectKeyTier({ provider: "anthropic" })).toBe("unknown");
  });

  it("an explicit declaredTier of 'enterprise' overrides an otherwise-unknown Anthropic key", () => {
    expect(detectKeyTier({ provider: "anthropic", declaredTier: "enterprise" })).toBe("enterprise");
  });
});

describe("applyKeyTierGuard", () => {
  it("'enterprise' tier is always allowed, regardless of guard mode (including 'block')", () => {
    const logger = spyLogger();
    const result = applyKeyTierGuard("enterprise", "block", "bedrock", logger);
    expect(result).toEqual({ tier: "enterprise", suspect: false, action: "allowed" });
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("mode 'off' allows a suspect tier without warning", () => {
    const logger = spyLogger();
    const result = applyKeyTierGuard("unknown", "off", "anthropic", logger);
    expect(result).toEqual({ tier: "unknown", suspect: true, action: "allowed" });
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("mode 'warn' logs 'llm.key_tier_suspect' with provider+tier metadata and allows the call", () => {
    const logger = spyLogger();
    const result = applyKeyTierGuard("unknown", "warn", "anthropic", logger);
    expect(result).toEqual({ tier: "unknown", suspect: true, action: "warned" });
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.key_tier_suspect",
      expect.objectContaining({ provider: "anthropic", keyTier: "unknown" }),
    );
  });

  it("mode 'warn' also fires for the explicit 'data_retaining' suspect tier", () => {
    const logger = spyLogger();
    const result = applyKeyTierGuard("data_retaining", "warn", "anthropic", logger);
    expect(result.action).toBe("warned");
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.key_tier_suspect",
      expect.objectContaining({ keyTier: "data_retaining" }),
    );
  });

  it("mode 'block' THROWS KeyTierRejectedError for a suspect 'unknown' tier", () => {
    expect(() => applyKeyTierGuard("unknown", "block", "anthropic")).toThrow(KeyTierRejectedError);
  });

  it("mode 'block' throw includes provider + tier in the error details", () => {
    try {
      applyKeyTierGuard("data_retaining", "block", "anthropic");
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(KeyTierRejectedError);
      const rejected = err as KeyTierRejectedError;
      expect(rejected.details).toEqual({ provider: "anthropic", keyTier: "data_retaining" });
      expect(rejected.code).toBe("KEY_TIER_REJECTED");
    }
  });

  it("mode 'block' does not require a logger (works when none is passed)", () => {
    expect(() => applyKeyTierGuard("unknown", "block", "anthropic", undefined)).toThrow(
      KeyTierRejectedError,
    );
  });

  it("guard works without a logger in 'warn' mode too (logger is optional)", () => {
    expect(() => applyKeyTierGuard("unknown", "warn", "anthropic", undefined)).not.toThrow();
  });
});
