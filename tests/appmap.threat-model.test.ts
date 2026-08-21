/**
 * E6 — threat-model derivation (`packages/appmap/src/threat-model.ts`), the
 * Layer 0.5 SUB-STEP of Layer 0 (not a new pipeline layer — see that module's
 * doc comment). Covers:
 *   1. The deterministic baseline is grounded in the FIXTURE's actual routes/
 *      model (not generic OWASP boilerplate) — asserted by checking the output
 *      references real route paths and the real `User` model name.
 *   2. The zero-surface case the audit's own E6 example names (no XXE/
 *      deserialization surface when no deserialize sink exists).
 *   3. LLM enrichment is additive-only and grounds/validates every suggestion
 *      against the real App Map (rejects a hallucinated route, a malformed
 *      response degrades safely to the baseline).
 */
import { describe, it, expect } from "vitest";
import {
  mockAppMap,
  mockCleanAppMap,
  createFakeLlmGateway,
  CLIENT_ID,
  SCAN_ID,
} from "@montr/fixtures";
import {
  deriveThreatModel,
  buildDeterministicThreatModel,
  buildAttackSurfaceBaseline,
  buildTrustBoundaries,
} from "@montr/appmap";
import { AppMapSchema, type AppMap } from "@montr/contracts";

describe("appmap threat-model — deterministic baseline (E6)", () => {
  it("grounds trust boundaries in the fixture's actual route paths", () => {
    const boundaries = buildTrustBoundaries(mockAppMap);
    expect(boundaries.length).toBeGreaterThan(0);
    const allPaths = boundaries.flatMap((b) => b.routePaths);
    expect(allPaths).toContain("/api/users");
    expect(allPaths).toContain("/search");
    // Both fixture routes are public — one boundary, not a generic list.
    const publicBoundary = boundaries.find((b) => b.name.toLowerCase().includes("public"));
    expect(publicBoundary?.routePaths).toEqual(expect.arrayContaining(["/api/users", "/search"]));
  });

  it("flags sql_injection and xss as high plausibility, grounded in the real taint sinks", () => {
    const surface = buildAttackSurfaceBaseline(mockAppMap);
    const sqli = surface.find((e) => e.category === "sql_injection");
    expect(sqli?.plausibility).toBe("high");
    expect(sqli?.rationale).toMatch(/app\/api\/users\/route\.ts/);

    const xss = surface.find((e) => e.category === "xss");
    expect(xss?.plausibility).toBe("high");
    expect(xss?.rationale).toMatch(/app\/search\/page\.tsx/);
  });

  it("marks xxe/insecure_deserialization/nosql_injection as zero-surface (the audit's own worked example)", () => {
    const surface = buildAttackSurfaceBaseline(mockAppMap);
    for (const category of ["xxe", "insecure_deserialization", "nosql_injection"] as const) {
      const entry = surface.find((e) => e.category === category);
      expect(entry?.plausibility, `${category} should be zero-surface`).toBe("none");
    }
  });

  it("flags idor/broken_access_control referencing the real 'User' model and public routes", () => {
    const surface = buildAttackSurfaceBaseline(mockAppMap);
    const idor = surface.find((e) => e.category === "idor");
    const bac = surface.find((e) => e.category === "broken_access_control");
    expect(idor).toBeDefined();
    expect(bac).toBeDefined();
    expect(idor?.rationale).toMatch(/User/);
    expect(idor?.rationale).toMatch(/\/api\/users|\/search/);
  });

  it("produces App-Map-grounded abuse cases, not generic boilerplate", () => {
    const tm = buildDeterministicThreatModel(mockAppMap);
    expect(tm.abuseCases.length).toBeGreaterThan(0);
    const titles = tm.abuseCases.map((c) => c.description).join(" ");
    // Grounded: mentions the actual vulnerable file/route, not a generic OWASP phrase.
    expect(titles).toMatch(/app\/api\/users\/route\.ts|app\/search\/page\.tsx/);
    expect(tm.generatedByLlm).toBe(false);
  });

  it("scopeHints.priorityCategories orders high-plausibility categories first, never empty on a vulnerable fixture", () => {
    const tm = buildDeterministicThreatModel(mockAppMap);
    expect(tm.scopeHints.priorityCategories.length).toBeGreaterThan(0);
    const categories = tm.scopeHints.priorityCategories.map((h) => h.category);
    expect(categories).toContain("sql_injection");
    expect(categories).toContain("xss");
    expect(tm.scopeHints.zeroSurfaceCategories).toEqual(
      expect.arrayContaining(["xxe", "insecure_deserialization", "nosql_injection"]),
    );
  });

  it("is defined and sane on the clean fixture too (no crash on a minimal App Map)", () => {
    const tm = buildDeterministicThreatModel(mockCleanAppMap);
    expect(tm.trustBoundaries.length).toBeGreaterThan(0);
    expect(() => AppMapSchema.parse({ ...mockCleanAppMap, threatModel: tm })).not.toThrow();
  });
});

describe("appmap threat-model — deriveThreatModel fail-safe behavior", () => {
  it("returns the deterministic baseline unchanged when no gateway is wired", async () => {
    const result = await deriveThreatModel(mockAppMap, undefined, {
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
    });
    expect(result.called).toBe(false);
    expect(result.threatModel.generatedByLlm).toBe(false);
    expect(result.threatModel).toEqual(buildDeterministicThreatModel(mockAppMap));
  });

  it("never calls the gateway when the kill switch is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const gateway = createFakeLlmGateway();
    const result = await deriveThreatModel(mockAppMap, gateway, {
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      signal: controller.signal,
    });
    expect(result.called).toBe(false);
    expect(result.threatModel.generatedByLlm).toBe(false);
  });

  it("degrades to the baseline when the model returns malformed JSON", async () => {
    const gateway = createFakeLlmGateway({ cannedByPurpose: { threat_model: "not json at all" } });
    const result = await deriveThreatModel(mockAppMap, gateway, {
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
    });
    expect(result.called).toBe(true);
    expect(result.threatModel.generatedByLlm).toBe(false);
    expect(result.threatModel.abuseCases).toEqual(
      buildDeterministicThreatModel(mockAppMap).abuseCases,
    );
  });

  it("appends a valid LLM-proposed abuse case and rejects a hallucinated route path", async () => {
    const suggestion = JSON.stringify({
      abuseCases: [
        {
          title: "Bulk user enumeration",
          description: "An attacker paginates /api/users to scrape every user's email.",
          routePaths: ["/api/users", "/api/does-not-exist"],
          categories: ["idor"],
        },
      ],
      additionalPriorityCategories: [
        { category: "sensitive_data_exposure", rationale: "User emails are returned unfiltered." },
      ],
    });
    const gateway = createFakeLlmGateway({ cannedByPurpose: { threat_model: suggestion } });
    const result = await deriveThreatModel(mockAppMap, gateway, {
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
    });
    expect(result.called).toBe(true);
    expect(result.threatModel.generatedByLlm).toBe(true);

    const added = result.threatModel.abuseCases.find((c) => c.title === "Bulk user enumeration");
    expect(added).toBeDefined();
    // The real route path survives; the hallucinated one is stripped.
    expect(added?.routePaths).toEqual(["/api/users"]);
    expect(added?.routePaths).not.toContain("/api/does-not-exist");

    const priorities = result.threatModel.scopeHints.priorityCategories.map((h) => h.category);
    expect(priorities).toContain("sensitive_data_exposure");

    // ⛔ Additive-only: every deterministic entry survives unchanged underneath.
    const baseline = buildDeterministicThreatModel(mockAppMap);
    for (const entry of baseline.attackSurface) {
      expect(result.threatModel.attackSurface).toContainEqual(entry);
    }
    for (const c of baseline.abuseCases) {
      expect(result.threatModel.abuseCases).toContainEqual(c);
    }
  });

  it("rejects an invalid/unknown category from the model rather than accepting it verbatim", async () => {
    const suggestion = JSON.stringify({
      additionalPriorityCategories: [
        { category: "not_a_real_category", rationale: "should be dropped" },
        { category: "csrf", rationale: "real category, should be kept" },
      ],
    });
    const gateway = createFakeLlmGateway({ cannedByPurpose: { threat_model: suggestion } });
    const result = await deriveThreatModel(mockAppMap, gateway, {
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
    });
    const categories = result.threatModel.scopeHints.priorityCategories.map((h) => h.category);
    expect(categories).not.toContain("not_a_real_category");
    expect(categories).toContain("csrf");
  });

  it("never spends a token on an App Map with zero routes", async () => {
    const emptyRoutesMap: AppMap = AppMapSchema.parse({ ...mockAppMap, routes: [] });
    const gateway = createFakeLlmGateway();
    const result = await deriveThreatModel(emptyRoutesMap, gateway, {
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
    });
    expect(result.called).toBe(false);
  });
});
