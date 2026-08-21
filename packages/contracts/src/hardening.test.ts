import { describe, it, expect } from "vitest";
import { HardeningCategorySchema, HardeningRecommendationSchema } from "./hardening.js";

const NOW = "2026-08-22T00:00:00.000Z";

describe("HardeningCategorySchema", () => {
  it("accepts every documented category", () => {
    for (const c of [
      "security_headers",
      "csp",
      "cookie_policy",
      "rate_limits",
      "waf_rules",
      "network_policy",
      "framework_configuration",
    ]) {
      expect(HardeningCategorySchema.parse(c)).toBe(c);
    }
  });

  it("rejects an unknown category", () => {
    expect(() => HardeningCategorySchema.parse("code_fix")).toThrow();
  });
});

describe("HardeningRecommendationSchema", () => {
  const base = {
    id: "hr_1",
    category: "security_headers" as const,
    severity: "medium" as const,
    title: "Wire helmet() into the Express app",
    gap: "No helmet dependency detected in package.json/lockfile.",
    recommendation: "app.use(helmet());",
    rationale: "Missing security headers expose the app to clickjacking/MIME-sniffing.",
    evidence: [
      "package.json: no `helmet` dependency",
      "src/app.ts: express() with no header middleware",
    ],
    createdAt: NOW,
  };

  it("accepts a well-formed recommendation", () => {
    const parsed = HardeningRecommendationSchema.parse(base);
    expect(parsed.category).toBe("security_headers");
    expect(parsed.evidence.length).toBeGreaterThan(0);
    expect(parsed.relatedFindingIds).toEqual([]);
  });

  it("accepts an optional framework and relatedFindingIds", () => {
    const parsed = HardeningRecommendationSchema.parse({
      ...base,
      framework: "express",
      relatedFindingIds: ["finding_1", "finding_2"],
    });
    expect(parsed.framework).toBe("express");
    expect(parsed.relatedFindingIds).toEqual(["finding_1", "finding_2"]);
  });

  it("rejects an empty evidence array — a recommendation must cite a real signal", () => {
    expect(() => HardeningRecommendationSchema.parse({ ...base, evidence: [] })).toThrow();
  });

  it("rejects an empty title/gap/recommendation/rationale", () => {
    expect(() => HardeningRecommendationSchema.parse({ ...base, title: "" })).toThrow();
    expect(() => HardeningRecommendationSchema.parse({ ...base, gap: "" })).toThrow();
    expect(() => HardeningRecommendationSchema.parse({ ...base, recommendation: "" })).toThrow();
    expect(() => HardeningRecommendationSchema.parse({ ...base, rationale: "" })).toThrow();
  });

  it("has no risk-classification or diff/patch field — advisory-only by construction", () => {
    const parsed = HardeningRecommendationSchema.parse(base);
    expect(parsed).not.toHaveProperty("riskClass");
    expect(parsed).not.toHaveProperty("patch");
    expect(parsed).not.toHaveProperty("diff");
  });
});
