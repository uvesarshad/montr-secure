import { describe, it, expect } from "vitest";
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  CATEGORY_TAXONOMY,
  complianceForCategory,
  BudgetExceededError,
  isMontrError,
  buildIdempotencyKey,
  RECOMMENDED_MODEL_MATRIX,
  MODEL_FLOOR,
  RETRY_POLICIES,
} from "@montr/contracts";

describe("@montr/contracts", () => {
  it("every Category has a taxonomy entry with CWE + OWASP", () => {
    for (const category of Object.keys(CATEGORY_TAXONOMY)) {
      const mapping = complianceForCategory(category as keyof typeof CATEGORY_TAXONOMY);
      expect(mapping.owasp).toMatch(/^A\d{2}:2021$/);
      expect(mapping.owaspTitle.length).toBeGreaterThan(0);
    }
  });

  it("rejects a malformed AppMap", () => {
    const result = AppMapSchema.safeParse({ id: "x" });
    expect(result.success).toBe(false);
  });

  it("enforces proofType === proofArtifact.kind on a confirmed finding", () => {
    const bad = ConfirmedFindingSchema.safeParse({
      id: "c1",
      scanId: "s1",
      clientId: "cl1",
      title: "mismatch",
      category: "xss",
      severity: "high",
      exposure: "public",
      location: { file: "a.ts", line: 1 },
      impact: "x",
      proofType: "static",
      proofArtifact: { kind: "live", target: "https://x", transcript: [] },
      createdAt: "2026-01-15T10:00:00.000Z",
    });
    expect(bad.success).toBe(false);
  });

  it("typed errors serialize to an envelope and are detectable", () => {
    const err = new BudgetExceededError("over budget", { spentUsd: 10 });
    expect(isMontrError(err)).toBe(true);
    expect(err.toEnvelope()).toMatchObject({ code: "BUDGET_EXCEEDED", retriable: false });
  });

  it("idempotency keys are deterministic", () => {
    expect(buildIdempotencyKey("scan_1", "layer2", "h")).toBe("scan_1:layer2:h");
    expect(buildIdempotencyKey("scan_1", "layer2", "h")).toBe(
      buildIdempotencyKey("scan_1", "layer2", "h"),
    );
  });

  it("pins the recommended model matrix + floor (DECIDE-3)", () => {
    expect(RECOMMENDED_MODEL_MATRIX.confirmation.modelId).toBe("claude-opus-5");
    expect(RECOMMENDED_MODEL_MATRIX.default.modelId).toBe("claude-sonnet-5");
    expect(RECOMMENDED_MODEL_MATRIX.triage.modelId).toBe("claude-haiku-4-5");
    expect(MODEL_FLOOR.confirmationTier.minModelId).toBe("claude-sonnet-5");
    // Live DAST layer retries conservatively.
    expect(RETRY_POLICIES.layer3.attempts).toBeLessThanOrEqual(RETRY_POLICIES.layer2.attempts);
  });
});
