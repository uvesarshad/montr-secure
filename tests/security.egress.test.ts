import { describe, it, expect } from "vitest";
import { getHardenedDefaults } from "@montr/config";
import { EgressBlockedError, isMontrError } from "@montr/contracts";
import {
  deriveEgressPolicy,
  isEgressAllowed,
  assertEgressAllowed,
  assertStartupEgress,
  createEgressGuard,
  normalizeHost,
  type EgressConfig,
} from "../packages/security/src/egress-guard";

/**
 * WS-N egress-guard tests (build-plan §4.8, §11, golden rule #1). Proves the only
 * permitted outbound destination is the configured client LLM endpoint; all else
 * is denied with a typed EgressBlockedError.
 */

const baseSecurity = { egressPolicy: "default-deny" as const, allowedEgressHosts: [] as string[] };

describe("normalizeHost", () => {
  it("extracts the lowercased hostname from URLs and bare hosts", () => {
    expect(normalizeHost("https://API.Anthropic.com/v1/messages")).toBe("api.anthropic.com");
    expect(normalizeHost("api.anthropic.com:443")).toBe("api.anthropic.com");
    expect(normalizeHost("api.anthropic.com")).toBe("api.anthropic.com");
  });
  it("throws EgressBlockedError on empty input", () => {
    expect(() => normalizeHost("   ")).toThrow(EgressBlockedError);
  });
});

describe("deriveEgressPolicy — real MontrConfig satisfies EgressConfig", () => {
  it("hardened defaults resolve to default-deny with only api.anthropic.com allowed", () => {
    const cfg = getHardenedDefaults(); // real @montr/config value
    const policy = deriveEgressPolicy(cfg);
    expect(policy.policy).toBe("default-deny");
    expect(isEgressAllowed(policy, "https://api.anthropic.com/v1/messages")).toBe(true);
    expect(isEgressAllowed(policy, "https://evil.example.com/exfil")).toBe(false);
    expect(isEgressAllowed(policy, "http://169.254.169.254/latest/meta-data")).toBe(false);
  });
});

describe("deriveEgressPolicy — explicit endpoint narrows egress to one host", () => {
  it("allows only the configured endpoint host, not the whole provider domain", () => {
    const cfg: EgressConfig = {
      llm: { provider: "bedrock", endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com" },
      security: { ...baseSecurity, allowedEgressHosts: ["osv-mirror.internal"] },
    };
    const policy = deriveEgressPolicy(cfg);
    expect(policy.llmHost).toBe("bedrock-runtime.us-east-1.amazonaws.com");
    expect(isEgressAllowed(policy, "bedrock-runtime.us-east-1.amazonaws.com")).toBe(true);
    expect(isEgressAllowed(policy, "osv-mirror.internal")).toBe(true); // operator-approved infra
    expect(isEgressAllowed(policy, "s3.amazonaws.com")).toBe(false); // NOT a broad *.amazonaws.com allow
  });
});

describe("deriveEgressPolicy — provider default without endpoint warns (broad suffix)", () => {
  it("azure without an endpoint allows the suffix but records a warning", () => {
    const cfg: EgressConfig = { llm: { provider: "azure" }, security: baseSecurity };
    const policy = deriveEgressPolicy(cfg);
    expect(policy.allowedSuffixes).toContain(".openai.azure.com");
    expect(isEgressAllowed(policy, "myresource.openai.azure.com")).toBe(true);
    expect(isEgressAllowed(policy, "evil.com")).toBe(false);
    expect(policy.warnings.some((w) => w.includes("llm.endpoint"))).toBe(true);
  });
});

describe("telemetry + DAST destinations", () => {
  it("allows the telemetry endpoint only when telemetry is opt-in enabled", () => {
    const enabled: EgressConfig = {
      llm: { provider: "anthropic" },
      security: baseSecurity,
      telemetry: { enabled: true, endpoint: "https://metrics.internal:4318" },
    };
    expect(isEgressAllowed(deriveEgressPolicy(enabled), "metrics.internal")).toBe(true);

    const disabled: EgressConfig = {
      llm: { provider: "anthropic" },
      security: baseSecurity,
      telemetry: { enabled: false, endpoint: "https://metrics.internal:4318" },
    };
    expect(isEgressAllowed(deriveEgressPolicy(disabled), "metrics.internal")).toBe(false);
  });

  it("only folds in DAST staging targets when explicitly requested", () => {
    const cfg: EgressConfig = {
      llm: { provider: "anthropic" },
      security: baseSecurity,
      dast: { allowlist: ["https://staging.client.test"] },
    };
    expect(isEgressAllowed(deriveEgressPolicy(cfg), "staging.client.test")).toBe(false);
    expect(
      isEgressAllowed(deriveEgressPolicy(cfg, { includeDastTargets: true }), "staging.client.test"),
    ).toBe(true);
  });
});

describe("assertEgressAllowed / createEgressGuard", () => {
  const policy = deriveEgressPolicy({ llm: { provider: "anthropic" }, security: baseSecurity });

  it("throws a typed EgressBlockedError for a denied destination", () => {
    try {
      assertEgressAllowed(policy, "https://attacker.example/exfil");
      throw new Error("should have thrown");
    } catch (e) {
      expect(isMontrError(e)).toBe(true);
      expect((e as EgressBlockedError).code).toBe("EGRESS_BLOCKED");
    }
    expect(() =>
      assertEgressAllowed(policy, "https://api.anthropic.com/v1/messages"),
    ).not.toThrow();
  });

  it("createEgressGuard bundles a working per-request assert()", () => {
    const guard = createEgressGuard({ llm: { provider: "anthropic" }, security: baseSecurity });
    expect(guard.isAllowed("api.anthropic.com")).toBe(true);
    expect(() => guard.assert("evil.com")).toThrow(EgressBlockedError);
  });
});

describe("assertStartupEgress", () => {
  it("rejects a non-default-deny policy (golden rule #1)", () => {
    const cfg = {
      llm: { provider: "anthropic" as const },
      security: { egressPolicy: "allow-all", allowedEgressHosts: [] },
    };
    expect(() => assertStartupEgress(cfg)).toThrow(EgressBlockedError);
  });

  it("returns a compiled policy and forwards warnings for hardened defaults", () => {
    const warnings: string[] = [];
    const policy = assertStartupEgress(getHardenedDefaults(), {
      onWarning: (w) => warnings.push(w),
    });
    expect(policy.allowedHosts.has("api.anthropic.com")).toBe(true);
    // anthropic default host is exact (no broad suffix) → no warning expected
    expect(policy.warnings.length).toBe(0);
    expect(warnings.length).toBe(0);
  });
});
