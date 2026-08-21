import { describe, it, expect } from "vitest";
import type { HardeningRecommendation } from "@montr/contracts";
import { renderHardeningRecommendationsMarkdown } from "./render.js";
import { NOW } from "./test-helpers.js";

function rec(overrides: Partial<HardeningRecommendation> = {}): HardeningRecommendation {
  return {
    id: "hard_1",
    category: "security_headers",
    severity: "medium",
    title: "Wire helmet() into the Express app",
    gap: "No helmet dependency detected.",
    recommendation: "app.use(helmet());",
    rationale: "Missing baseline headers.",
    evidence: ["No helmet in package.json"],
    relatedFindingIds: [],
    createdAt: NOW,
    ...overrides,
  };
}

describe("renderHardeningRecommendationsMarkdown", () => {
  it("renders an explicit no-gaps note for an empty list", () => {
    const md = renderHardeningRecommendationsMarkdown([]);
    expect(md).toContain("No hardening gaps were detected");
  });

  it("groups recommendations by category and renders every field", () => {
    const md = renderHardeningRecommendationsMarkdown([
      rec({ id: "hard_1", category: "security_headers", severity: "high" }),
      rec({
        id: "hard_2",
        category: "waf_rules",
        title: "Add SQLi WAF coverage",
        relatedFindingIds: ["finding_1"],
      }),
    ]);
    expect(md).toContain("### Security Headers");
    expect(md).toContain("### WAF Rules");
    expect(md).toContain("Wire helmet() into the Express app");
    expect(md).toContain("Add SQLi WAF coverage");
    expect(md).toContain("Related findings:** finding_1");
    expect(md).toContain("Advisory-only");
  });

  it("sorts within a category by severity (highest first)", () => {
    const md = renderHardeningRecommendationsMarkdown([
      rec({ id: "hard_1", title: "Low one", severity: "low" }),
      rec({ id: "hard_2", title: "Critical one", severity: "critical" }),
    ]);
    expect(md.indexOf("Critical one")).toBeLessThan(md.indexOf("Low one"));
  });
});
