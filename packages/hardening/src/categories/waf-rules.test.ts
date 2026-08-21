import { describe, it, expect } from "vitest";
import { detectWafRuleRecommendations } from "./waf-rules.js";
import { confirmedFinding } from "../test-helpers.js";

describe("detectWafRuleRecommendations", () => {
  it("recommends AWSManagedRulesSQLiRuleSet for a confirmed SQL injection", () => {
    const finding = confirmedFinding({ id: "f1", category: "sql_injection" });
    const drafts = detectWafRuleRecommendations([finding]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.recommendation).toContain("AWSManagedRulesSQLiRuleSet");
    expect(drafts[0]?.relatedFindingIds).toEqual(["f1"]);
  });

  it("groups multiple findings of the same category into one recommendation", () => {
    const findings = [
      confirmedFinding({ id: "f1", category: "xss" }),
      confirmedFinding({ id: "f2", category: "xss" }),
    ];
    const drafts = detectWafRuleRecommendations(findings);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.relatedFindingIds).toEqual(["f1", "f2"]);
    expect(drafts[0]?.evidence).toHaveLength(2);
  });

  it("produces separate recommendations for different categories", () => {
    const findings = [
      confirmedFinding({ id: "f1", category: "ssrf" }),
      confirmedFinding({ id: "f2", category: "command_injection" }),
    ];
    const drafts = detectWafRuleRecommendations(findings);
    expect(drafts.map((d) => d.category)).toEqual(["waf_rules", "waf_rules"]);
    expect(drafts.map((d) => d.relatedFindingIds)).toEqual([["f1"], ["f2"]]);
  });

  it("produces nothing for a category with no WAF-layer analog", () => {
    const finding = confirmedFinding({ id: "f1", category: "broken_access_control" });
    const drafts = detectWafRuleRecommendations([finding]);
    expect(drafts).toHaveLength(0);
  });

  it("produces nothing for an empty findings list", () => {
    expect(detectWafRuleRecommendations([])).toHaveLength(0);
  });
});
