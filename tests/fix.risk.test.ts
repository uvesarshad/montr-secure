import { describe, it, expect } from "vitest";
import {
  classifyConfirmedFindingRisk,
  deriveRiskSignals,
  MAX_AUTO_CHANGED_LINES,
} from "@montr/fix";
import { mockConfirmedFindings } from "@montr/fixtures";
import type { Category, ConfirmedFinding } from "@montr/contracts";

/**
 * ⛔ Layer 4 risk classifier is a SAFETY control (§11, golden rules #3/#4).
 * These tests pin the HARD rules: auth/session/crypto/access-control and wide
 * blast radius and uncertainty ALWAYS resolve to `human-required`.
 */

const baseConfirmed = mockConfirmedFindings[0] as ConfirmedFinding; // SQLi, public

function confirmedWith(category: Category, file = baseConfirmed.location.file): ConfirmedFinding {
  return { ...baseConfirmed, category, location: { ...baseConfirmed.location, file } };
}

/** A benign patch that trips none of the auth/crypto heuristics. */
const cleanPatch = [
  "--- a/app/api/users/route.ts",
  "+++ b/app/api/users/route.ts",
  "@@ -8,3 +8,1 @@",
  "-  const rows = await prisma.$queryRawUnsafe(`... ${q} ...`);",
  "+  const rows = await prisma.$queryRaw`... ${q} ...`;",
].join("\n");

const AUTH_CRYPTO_ACCESS_CATEGORIES: Category[] = [
  "broken_access_control",
  "broken_authentication",
  "weak_crypto",
  "idor",
  "csrf",
  "sensitive_data_exposure",
  "insecure_deserialization",
];

describe("@montr/fix — classifyConfirmedFindingRisk (deterministic safety control)", () => {
  it("auth/session/crypto/access-control categories are ALWAYS human-required (hard rule §11)", () => {
    for (const category of AUTH_CRYPTO_ACCESS_CATEGORIES) {
      const decision = classifyConfirmedFindingRisk(confirmedWith(category), {
        patch: cleanPatch,
        changedFiles: ["app/api/users/route.ts"],
        changedLines: 2,
        uncertain: false, // even with a clean, validated-looking patch
      });
      expect(decision.riskClass, category).toBe("human-required");
      expect(decision.rationale.length).toBeGreaterThan(0);
    }
  });

  it("an auth/crypto FILE PATH escalates an otherwise auto-eligible category", () => {
    const decision = classifyConfirmedFindingRisk(confirmedWith("xss", "lib/auth/session.ts"), {
      patch: cleanPatch,
      changedFiles: ["lib/auth/session.ts"],
      changedLines: 2,
      uncertain: false,
    });
    expect(decision.riskClass).toBe("human-required");
    expect(decision.signals.touchesAuthOrCrypto).toBe(true);
  });

  it("an auth/crypto API in the PATCH BODY escalates an auto-eligible category", () => {
    const patch = cleanPatch + '\n+  const h = crypto.createHash("sha256");';
    const decision = classifyConfirmedFindingRisk(confirmedWith("xss", "app/search/page.tsx"), {
      patch,
      changedFiles: ["app/search/page.tsx"],
      changedLines: 3,
      uncertain: false,
    });
    expect(decision.riskClass).toBe("human-required");
    expect(decision.signals.touchesAuthOrCrypto).toBe(true);
  });

  it("wide blast radius (line count) → human-required; within budget → auto-eligible", () => {
    const wide = classifyConfirmedFindingRisk(confirmedWith("sql_injection"), {
      patch: cleanPatch,
      changedFiles: ["app/api/users/route.ts"],
      changedLines: MAX_AUTO_CHANGED_LINES + 1,
      uncertain: false,
    });
    expect(wide.riskClass).toBe("human-required");
    expect(wide.signals.wideBlastRadius).toBe(true);

    const narrow = classifyConfirmedFindingRisk(confirmedWith("sql_injection"), {
      patch: cleanPatch,
      changedFiles: ["app/api/users/route.ts"],
      changedLines: 4,
      uncertain: false,
    });
    expect(narrow.riskClass).toBe("auto-eligible");
  });

  it("wide blast radius (multiple files or shared module) → human-required", () => {
    const multi = classifyConfirmedFindingRisk(confirmedWith("sql_injection"), {
      patch: cleanPatch,
      changedFiles: ["app/api/users/route.ts", "app/api/orders/route.ts"],
      changedLines: 4,
      uncertain: false,
    });
    expect(multi.riskClass).toBe("human-required");

    const shared = classifyConfirmedFindingRisk(confirmedWith("xss", "src/shared/render.ts"), {
      patch: cleanPatch,
      changedFiles: ["src/shared/render.ts"],
      changedLines: 4,
      uncertain: false,
    });
    expect(shared.riskClass).toBe("human-required");
    expect(shared.signals.wideBlastRadius).toBe(true);
  });

  it("uncertainty ALWAYS resolves to human-required (golden rule #4)", () => {
    const decision = classifyConfirmedFindingRisk(confirmedWith("sql_injection"), {
      patch: "",
      changedFiles: ["app/api/users/route.ts"],
      changedLines: 0,
      uncertain: true,
    });
    expect(decision.riskClass).toBe("human-required");
    expect(decision.rationale.toLowerCase()).toContain("uncertain");
  });

  it("mechanical, low-blast-radius, validated categories are auto-eligible", () => {
    for (const category of ["sql_injection", "xss", "permissive_cors"] as Category[]) {
      const decision = classifyConfirmedFindingRisk(confirmedWith(category), {
        patch: cleanPatch,
        changedFiles: ["app/api/users/route.ts"],
        changedLines: 4,
        uncertain: false,
      });
      expect(decision.riskClass, category).toBe("auto-eligible");
    }
  });

  it("deployment policy can force any category to human-required", () => {
    const decision = classifyConfirmedFindingRisk(
      confirmedWith("sql_injection"),
      {
        patch: cleanPatch,
        changedFiles: ["app/api/users/route.ts"],
        changedLines: 4,
        uncertain: false,
      },
      { alwaysHumanCategories: ["sql_injection"] },
    );
    expect(decision.riskClass).toBe("human-required");
    expect(decision.rationale.toLowerCase()).toContain("policy");
  });

  it("deriveRiskSignals falls back to the finding file when changedFiles is empty", () => {
    const signals = deriveRiskSignals(confirmedWith("xss", "app/auth/login.ts"), {
      patch: "",
      changedFiles: [],
      changedLines: 0,
      uncertain: false,
    });
    expect(signals.touchesAuthOrCrypto).toBe(true);
  });
});
