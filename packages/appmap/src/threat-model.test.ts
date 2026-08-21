/**
 * STRIDE + threat-model derivation tests (B7). Verifies the deterministic
 * baseline's STRIDE classification is grounded in real App Map evidence —
 * both the precision case (a properly-authenticated boundary with no
 * write/delete fan-out gets NO spurious STRIDE tags) and the positive case (a
 * public boundary with a real route->model write link gets Tampering +
 * Elevation of Privilege + Repudiation, grounded in that exact route/model).
 */
import { describe, expect, it } from "vitest";
import { AppMapSchema, type AppMap } from "@montr/contracts";
import {
  buildAttackSurfaceBaseline,
  buildDeterministicThreatModel,
  buildTrustBoundaries,
} from "./threat-model.js";

function baseAppMap(overrides: Partial<AppMap>): AppMap {
  return AppMapSchema.parse({
    id: "am_test",
    clientId: "client_test",
    repo: "https://example.internal/test/repo",
    branch: "main",
    commitSha: "a".repeat(40),
    createdAt: "2026-08-22T00:00:00.000Z",
    languages: ["typescript"],
    frameworks: ["nextjs", "prisma"],
    entrypoints: [],
    routes: [],
    dataStores: [],
    ormModels: [],
    thirdPartyCalls: [],
    envSecretSurfaces: [],
    taintSources: [],
    taintSinks: [],
    stale: false,
    rebuildPolicy: "rebuild_on_stale_commit",
    ...overrides,
  });
}

describe("buildTrustBoundaries — STRIDE precision", () => {
  it("does NOT flag a properly-authenticated, no-fan-out boundary (no spurious STRIDE)", () => {
    const appMap = baseAppMap({
      routes: [
        {
          path: "/api/profile",
          method: "GET",
          authState: "authenticated",
          isApiRoute: true,
          authGate: "requireSession",
          handler: { file: "app/api/profile/route.ts", line: 1 },
          referencedModels: [{ modelName: "User", operations: ["read"] }],
        },
      ],
      ormModels: [
        {
          name: "User",
          dataStore: "app_db",
          file: "prisma/schema.prisma",
          fields: [{ name: "id", type: "Int", isId: true }],
        },
      ],
      dataStores: [{ kind: "postgres", name: "app_db", accessedVia: "prisma" }],
    });

    const boundaries = buildTrustBoundaries(appMap);
    const authenticated = boundaries.find((b) => b.name.startsWith("Authenticated"));
    expect(authenticated).toBeDefined();
    // Authenticated boundary: not weak, so it never gets Spoofing/Tampering/EoP/
    // Repudiation/InfoDisclosure regardless of read/write shape.
    expect(authenticated?.stride).toEqual([]);
  });

  it("flags Spoofing on a public boundary even with no write/delete fan-out", () => {
    const appMap = baseAppMap({
      routes: [
        {
          path: "/health",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/health/route.ts", line: 1 },
        },
      ],
    });

    const boundaries = buildTrustBoundaries(appMap);
    const pub = boundaries.find((b) => b.name.startsWith("Public"));
    expect(pub?.stride.map((s) => s.category)).toEqual(["spoofing"]);
    expect(pub?.stride[0]?.rationale).toContain("/health");
  });

  it("flags Tampering + Elevation of Privilege + Repudiation on a public write-capable boundary, grounded in the real route/model", () => {
    const appMap = baseAppMap({
      routes: [
        {
          path: "/api/users/:id",
          method: "DELETE",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/users/[id]/route.ts", line: 1 },
          referencedModels: [{ modelName: "User", operations: ["delete"] }],
        },
      ],
      ormModels: [
        {
          name: "User",
          dataStore: "app_db",
          file: "prisma/schema.prisma",
          fields: [{ name: "id", type: "Int", isId: true }],
        },
      ],
      dataStores: [{ kind: "postgres", name: "app_db", accessedVia: "prisma" }],
    });

    const boundaries = buildTrustBoundaries(appMap);
    const pub = boundaries.find((b) => b.name.startsWith("Public"));
    const categories = pub?.stride.map((s) => s.category) ?? [];
    expect(categories).toContain("spoofing");
    expect(categories).toContain("tampering");
    expect(categories).toContain("elevation_of_privilege");
    expect(categories).toContain("repudiation");
    // Never DoS: no rate-limit/throughput signal exists in the App Map (documented judgment call).
    expect(categories).not.toContain("denial_of_service");
    const tampering = pub?.stride.find((s) => s.category === "tampering");
    expect(tampering?.rationale).toContain("/api/users/:id");
    expect(tampering?.rationale).toContain("User");
  });

  it("flags Information Disclosure on external third-party integrations", () => {
    const appMap = baseAppMap({
      thirdPartyCalls: [
        { kind: "http", name: "stripe", location: { file: "lib/billing.ts", line: 4 } },
      ],
    });
    const boundaries = buildTrustBoundaries(appMap);
    const external = boundaries.find((b) => b.name === "External API integrations");
    expect(external?.stride.map((s) => s.category)).toEqual(["information_disclosure"]);
    expect(external?.stride[0]?.rationale).toContain("stripe");
  });
});

describe("buildAttackSurfaceBaseline — per-category STRIDE", () => {
  it("suppresses STRIDE to [] when plausibility is none", () => {
    const appMap = baseAppMap({});
    const entries = buildAttackSurfaceBaseline(appMap);
    const insecureDeser = entries.find((e) => e.category === "insecure_deserialization");
    expect(insecureDeser?.plausibility).toBe("none");
    expect(insecureDeser?.stride).toEqual([]);
  });

  it("assigns Tampering + Information Disclosure to a plausible sql_injection entry", () => {
    const appMap = baseAppMap({
      taintSinks: [
        {
          kind: "sql_query",
          location: { file: "app/api/x/route.ts", line: 9 },
          description: "raw",
        },
      ],
    });
    const entries = buildAttackSurfaceBaseline(appMap);
    const sqli = entries.find((e) => e.category === "sql_injection");
    expect(sqli?.plausibility).toBe("high");
    expect(sqli?.stride).toEqual(["tampering", "information_disclosure"]);
  });
});

describe("buildDeterministicThreatModel — end-to-end", () => {
  it("produces a schema-valid ThreatModel with STRIDE attached at both granularities", () => {
    const appMap = baseAppMap({
      routes: [
        {
          path: "/api/orders",
          method: "POST",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/orders/route.ts", line: 1 },
          referencedModels: [{ modelName: "Order", operations: ["write"] }],
        },
      ],
      ormModels: [
        {
          name: "Order",
          dataStore: "app_db",
          file: "prisma/schema.prisma",
          fields: [{ name: "id", type: "Int", isId: true }],
        },
      ],
      dataStores: [{ kind: "postgres", name: "app_db", accessedVia: "prisma" }],
      taintSinks: [
        {
          kind: "sql_query",
          location: { file: "app/api/orders/route.ts", line: 5 },
          description: "raw",
        },
      ],
    });

    const threatModel = buildDeterministicThreatModel(appMap);
    expect(threatModel.generatedByLlm).toBe(false);
    const pub = threatModel.trustBoundaries.find((b) => b.name.startsWith("Public"));
    expect(pub?.stride.some((s) => s.category === "tampering")).toBe(true);
    const sqli = threatModel.attackSurface.find((e) => e.category === "sql_injection");
    expect(sqli?.stride).toContain("tampering");
  });
});
