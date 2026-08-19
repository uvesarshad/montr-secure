import { describe, it, expect } from "vitest";
import { classifyFixRisk, AUTO_ELIGIBLE_CATEGORIES, FIX_STRATEGIES } from "@montr/fix";

describe("@montr/fix risk classifier (§11 safety control)", () => {
  it("auth/access-control/crypto categories are ALWAYS human-required", () => {
    expect(classifyFixRisk({ category: "broken_access_control" })).toBe("human-required");
    expect(classifyFixRisk({ category: "broken_authentication" })).toBe("human-required");
    expect(classifyFixRisk({ category: "weak_crypto" })).toBe("human-required");
    expect(classifyFixRisk({ category: "idor" })).toBe("human-required");
    expect(classifyFixRisk({ category: "csrf" })).toBe("human-required");
  });

  it("touching auth/crypto forces human-required even for a normally auto-eligible category", () => {
    expect(classifyFixRisk({ category: "xss", touchesAuthOrCrypto: true })).toBe("human-required");
  });

  it("wide blast radius forces human-required", () => {
    expect(classifyFixRisk({ category: "sql_injection", wideBlastRadius: true })).toBe(
      "human-required",
    );
  });

  it("uncertainty resolves to human-required (golden rule #4)", () => {
    expect(classifyFixRisk({ category: "xss", uncertain: true })).toBe("human-required");
    expect(classifyFixRisk({ category: "other" })).toBe("human-required");
  });

  it("mechanical, low-blast-radius categories are auto-eligible", () => {
    expect(classifyFixRisk({ category: "sql_injection" })).toBe("auto-eligible");
    expect(classifyFixRisk({ category: "xss" })).toBe("auto-eligible");
    expect(classifyFixRisk({ category: "permissive_cors" })).toBe("auto-eligible");
    expect(classifyFixRisk({ category: "nosql_injection" })).toBe("auto-eligible");
    expect(classifyFixRisk({ category: "insecure_cookie" })).toBe("auto-eligible");
    expect(classifyFixRisk({ category: "missing_security_headers" })).toBe("auto-eligible");
    expect(classifyFixRisk({ category: "open_redirect" })).toBe("auto-eligible");
  });

  it("vulnerable_dependency is NOT auto-eligible (no safe target-version data, no egress to look it up)", () => {
    expect(classifyFixRisk({ category: "vulnerable_dependency" })).toBe("human-required");
  });

  it("every auto-eligible category has a real, implemented FixStrategy (A14)", () => {
    // The advertised auto-eligible surface must never outstrip what's actually
    // implemented. (`hardcoded_secret` is the deliberate inverse case: it HAS a
    // strategy — for a validated patch + proof test — but is intentionally left
    // off AUTO_ELIGIBLE_CATEGORIES because the leaked key still needs human
    // rotation, so the extra strategy without a matching category is expected.)
    const strategyCategories = new Set(FIX_STRATEGIES.map((s) => s.category));
    for (const category of AUTO_ELIGIBLE_CATEGORIES) {
      expect(strategyCategories.has(category), category).toBe(true);
    }
  });
});
