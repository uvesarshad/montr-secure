import { describe, it, expect } from "vitest";
import { classifyFixRisk } from "@montr/fix";

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
    expect(classifyFixRisk({ category: "vulnerable_dependency" })).toBe("auto-eligible");
  });
});
