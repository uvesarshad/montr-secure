/**
 * Threat-model report renderer tests (B7). Verifies the artifact is
 * finding-specific (not a boilerplate template with fields swapped in): the
 * summary/markdown/JSON output must reference the REAL route paths, ORM
 * models, and rationale text carried by the input `ThreatModel`, and must
 * stay quiet (no STRIDE rows, no attack-surface rows) when the input has no
 * grounded evidence.
 */
import { describe, expect, it } from "vitest";
import { ThreatModelSchema, type ThreatModel } from "@montr/contracts";
import {
  buildThreatModelReport,
  renderThreatModelReportJson,
  renderThreatModelReportMarkdown,
} from "./threat-model.js";

function threatModel(overrides: Partial<ThreatModel>): ThreatModel {
  return ThreatModelSchema.parse({
    trustBoundaries: [],
    attackSurface: [],
    abuseCases: [],
    scopeHints: { priorityCategories: [], priorityRoutePaths: [], zeroSurfaceCategories: [] },
    generatedByLlm: false,
    ...overrides,
  });
}

const GROUNDED: ThreatModel = threatModel({
  trustBoundaries: [
    {
      name: "Public unauthenticated routes",
      description: '1 route(s) classified "public": /api/orders.',
      routePaths: ["/api/orders"],
      stride: [
        {
          category: "spoofing",
          rationale:
            '1 route(s) in this boundary accept requests with no verified caller identity (authState "public": /api/orders).',
        },
        {
          category: "tampering",
          rationale: "Route(s) /api/orders write/delete ORM model(s) Order behind public auth.",
        },
        {
          category: "elevation_of_privilege",
          rationale:
            "The same write/delete access on Order from route(s) /api/orders is reachable without proving any role.",
        },
      ],
    },
    {
      name: "Authenticated user-scoped routes",
      description: '1 route(s) classified "authenticated": /api/profile.',
      routePaths: ["/api/profile"],
      stride: [],
    },
  ],
  attackSurface: [
    {
      category: "sql_injection",
      plausibility: "high",
      rationale: "1 raw/SQL query sink(s) detected: app/api/orders/route.ts:9.",
      stride: ["tampering", "information_disclosure"],
    },
    {
      category: "insecure_deserialization",
      plausibility: "none",
      rationale: "No deserialize-kind taint sink detected anywhere in the App Map.",
      stride: [],
    },
    {
      category: "csrf",
      plausibility: "medium",
      rationale:
        "1 cookie-derived taint source(s) detected; confirm state-changing routes carry CSRF protection.",
      stride: ["spoofing", "tampering"],
    },
  ],
  abuseCases: [
    {
      title: "Raw-query SQL injection via /api/orders",
      description:
        "An attacker submits crafted input that reaches the raw/SQL sink at app/api/orders/route.ts:9, exposed by route /api/orders.",
      routePaths: ["/api/orders"],
      categories: ["sql_injection"],
    },
  ],
  generatedByLlm: false,
});

const EMPTY: ThreatModel = threatModel({});

describe("buildThreatModelReport", () => {
  it("is finding-specific: the summary references real counts, not a boilerplate template", () => {
    const report = buildThreatModelReport(GROUNDED, { scanId: "scan_1", repo: "acme/orders-api" });
    expect(report.scanId).toBe("scan_1");
    expect(report.repo).toBe("acme/orders-api");
    expect(report.summary).toContain("2 identified trust boundar");
    expect(report.summary).toContain("1 of which accepts");
    expect(report.summary).toContain("Spoofing");
    expect(report.summary).toContain("Tampering");
    // insecure_deserialization is plausibility "none" — must never appear as attack surface.
    expect(report.attackSurface.some((e) => e.category === "insecure_deserialization")).toBe(false);
    expect(report.attackSurface.map((e) => e.category)).toEqual(["sql_injection", "csrf"]);
  });

  it("sorts attack surface high-plausibility first", () => {
    const report = buildThreatModelReport(GROUNDED);
    expect(report.attackSurface[0]?.plausibility).toBe("high");
    expect(report.attackSurface[1]?.plausibility).toBe("medium");
  });

  it("rolls up STRIDE counts across both boundaries and attack-surface categories", () => {
    const report = buildThreatModelReport(GROUNDED);
    const tampering = report.strideRollup.find((r) => r.category === "tampering");
    expect(tampering?.boundaryCount).toBe(1); // only the public boundary
    expect(tampering?.attackSurfaceCount).toBe(2); // sql_injection + csrf
    const dos = report.strideRollup.find((r) => r.category === "denial_of_service");
    expect(dos?.boundaryCount).toBe(0);
    expect(dos?.attackSurfaceCount).toBe(0);
  });

  it("stays quiet on an empty/no-evidence threat model — no spurious rows", () => {
    const report = buildThreatModelReport(EMPTY);
    expect(report.trustBoundaries).toEqual([]);
    expect(report.attackSurface).toEqual([]);
    expect(
      report.strideRollup.every((r) => r.boundaryCount === 0 && r.attackSurfaceCount === 0),
    ).toBe(true);
    expect(report.summary).toContain("0 identified trust boundar");
    expect(report.summary).toContain("No finding category has real structural attack surface");
  });
});

describe("renderThreatModelReportJson", () => {
  it("round-trips the build model as valid JSON", () => {
    const json = renderThreatModelReportJson(GROUNDED, {
      scanId: "scan_1",
      now: "2026-08-22T00:00:00.000Z",
    });
    const parsed = JSON.parse(json) as {
      scanId: string;
      generatedAt: string;
      trustBoundaries: unknown[];
    };
    expect(parsed.scanId).toBe("scan_1");
    expect(parsed.generatedAt).toBe("2026-08-22T00:00:00.000Z");
    expect(parsed.trustBoundaries).toHaveLength(2);
  });
});

describe("renderThreatModelReportMarkdown", () => {
  it("renders finding-specific markdown referencing real route/model/rationale text", () => {
    const md = renderThreatModelReportMarkdown(GROUNDED, {
      scanId: "scan_1",
      repo: "acme/orders-api",
    });
    expect(md).toContain("# Threat Model");
    expect(md).toContain("acme/orders-api");
    expect(md).toContain("scan_1");
    expect(md).toContain("Public unauthenticated routes");
    expect(md).toContain("/api/orders");
    expect(md).toContain("**Tampering**");
    expect(md).toContain("Order behind public auth");
    expect(md).toContain("Raw-query SQL injection via /api/orders");
    // Boundary with no grounded STRIDE evidence says so explicitly, not silently omitted.
    expect(md).toContain("_No STRIDE category has grounded evidence against this boundary._");
    // insecure_deserialization (plausibility none) must not leak into the rendered attack surface table.
    expect(md).not.toContain("insecure_deserialization");
  });

  it("renders a readable empty-state, not a broken/empty document", () => {
    const md = renderThreatModelReportMarkdown(EMPTY);
    expect(md).toContain("No trust boundaries were identified");
    expect(md).toContain("No finding category has real structural attack surface");
    expect(md).toContain("No concrete abuse-case scenarios were derived");
  });

  it("neutralizes markdown table metacharacters in interpolated text", () => {
    const withPipe = threatModel({
      trustBoundaries: [
        {
          name: "Public",
          description: "desc",
          routePaths: ["/a|b"],
          stride: [{ category: "spoofing", rationale: "route /a|b has no auth | dangerous" }],
        },
      ],
    });
    const md = renderThreatModelReportMarkdown(withPipe);
    expect(md).toContain("/a\\|b");
    expect(md).toContain("no auth \\| dangerous");
  });
});
