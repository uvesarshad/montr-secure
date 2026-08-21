/**
 * B8 — chain-condition precision. Direct unit coverage of
 * `evaluateChainCondition`'s three structural conditions, independent of the
 * graph-enumeration machinery in `./graph.test.ts`.
 */
import { describe, it, expect } from "vitest";
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  type AppMap,
  type ConfirmedFinding,
  type Route,
} from "@montr/contracts";
import { evaluateChainCondition, RCE_CATEGORIES } from "./conditions.js";

const NOW = "2026-08-22T00:00:00.000Z";

function mkAppMap(overrides: Partial<AppMap> = {}): AppMap {
  return AppMapSchema.parse({
    id: "appmap_1",
    clientId: "client_1",
    repo: "https://example.internal/x",
    branch: "main",
    commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334",
    createdAt: NOW,
    routes: [],
    ormModels: [],
    taintSinks: [],
    ...overrides,
  });
}

function mkFinding(
  overrides: Partial<ConfirmedFinding> & Pick<ConfirmedFinding, "id" | "title" | "category">,
): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    scanId: "scan_1",
    clientId: "client_1",
    severity: "high",
    exposure: "public",
    location: { file: "a.ts", line: 1 },
    impact: "impact",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "arg", dataFlow: [], sanitizersBypassed: [] },
    createdAt: NOW,
    ...overrides,
  });
}

const publicRoute: Route = {
  path: "/api/public",
  method: "GET",
  authState: "public",
  isApiRoute: true,
};
const gatedRoute: Route = {
  path: "/api/gated",
  method: "GET",
  authState: "role_gated",
  isApiRoute: true,
};

describe("evaluateChainCondition — RCE-class fans out to any other finding", () => {
  it("every RCE_CATEGORIES member chains to an unrelated finding", () => {
    const appMap = mkAppMap();
    const f2 = mkFinding({ id: "f2", title: "unrelated", category: "missing_security_headers" });
    for (const category of RCE_CATEGORIES) {
      const f1 = mkFinding({ id: "f1", title: "rce", category });
      const cond = evaluateChainCondition(appMap, f1, f2, undefined, undefined);
      expect(cond?.kind).toBe("rce-post-exploitation");
    }
  });

  it("a non-RCE category does not get the rce-post-exploitation condition", () => {
    const appMap = mkAppMap();
    const f1 = mkFinding({ id: "f1", title: "xss", category: "xss" });
    const f2 = mkFinding({ id: "f2", title: "unrelated", category: "missing_security_headers" });
    expect(evaluateChainCondition(appMap, f1, f2, undefined, undefined)).toBeUndefined();
  });
});

describe("evaluateChainCondition — ssrf-internal-pivot precision", () => {
  it("requires the target route to be non-public", () => {
    const appMap = mkAppMap();
    const f1 = mkFinding({
      id: "f1",
      title: "ssrf",
      category: "ssrf",
      location: { file: "a.ts", line: 1 },
    });
    const f2public = mkFinding({
      id: "f2",
      title: "other",
      category: "sensitive_data_exposure",
      location: { file: "b.ts", line: 1 },
    });
    expect(evaluateChainCondition(appMap, f1, f2public, publicRoute, publicRoute)).toBeUndefined();
    expect(evaluateChainCondition(appMap, f1, f2public, publicRoute, gatedRoute)?.kind).toBe(
      "ssrf-internal-pivot",
    );
  });

  it("does not chain to itself's own route", () => {
    const appMap = mkAppMap();
    const f1 = mkFinding({
      id: "f1",
      title: "ssrf",
      category: "ssrf",
      location: { file: "a.ts", line: 1 },
    });
    const f2 = mkFinding({
      id: "f2",
      title: "other",
      category: "sensitive_data_exposure",
      location: { file: "a.ts", line: 1 },
    });
    expect(evaluateChainCondition(appMap, f1, f2, gatedRoute, gatedRoute)).toBeUndefined();
  });

  it("strength is boosted when a real http_client taint sink corroborates F1's location", () => {
    const f1 = mkFinding({
      id: "f1",
      title: "ssrf",
      category: "ssrf",
      location: { file: "a.ts", line: 5 },
    });
    const f2 = mkFinding({
      id: "f2",
      title: "other",
      category: "sensitive_data_exposure",
      location: { file: "b.ts", line: 1 },
    });
    const bare = evaluateChainCondition(mkAppMap(), f1, f2, publicRoute, gatedRoute);
    const corroborated = evaluateChainCondition(
      mkAppMap({ taintSinks: [{ kind: "http_client", location: { file: "a.ts", line: 5 } }] }),
      f1,
      f2,
      publicRoute,
      gatedRoute,
    );
    expect(corroborated!.strength).toBeGreaterThan(bare!.strength);
  });
});

describe("evaluateChainCondition — idor-credential-leak precision", () => {
  const appMapWithCreds = mkAppMap({
    ormModels: [
      {
        name: "User",
        fields: [
          { name: "id", type: "Int", isId: true },
          { name: "password", type: "String", isId: false },
        ],
      },
    ],
  });
  const routeReadsUser: Route = {
    ...publicRoute,
    referencedModels: [{ modelName: "User", operations: ["read"] }],
  };

  it("requires an access-control category on F1", () => {
    const f1 = mkFinding({ id: "f1", title: "xss", category: "xss" });
    const f2 = mkFinding({ id: "f2", title: "gated", category: "broken_authentication" });
    expect(
      evaluateChainCondition(appMapWithCreds, f1, f2, routeReadsUser, gatedRoute),
    ).toBeUndefined();
  });

  it("requires the exposed model to actually have a credential-shaped field", () => {
    const appMapNoCreds = mkAppMap({
      ormModels: [
        {
          name: "User",
          fields: [
            { name: "id", type: "Int", isId: true },
            { name: "displayName", type: "String", isId: false },
          ],
        },
      ],
    });
    const f1 = mkFinding({ id: "f1", title: "idor", category: "idor" });
    const f2 = mkFinding({ id: "f2", title: "gated", category: "broken_authentication" });
    expect(
      evaluateChainCondition(appMapNoCreds, f1, f2, routeReadsUser, gatedRoute),
    ).toBeUndefined();
  });

  it("chains an idor finding leaking credentials to a non-public route", () => {
    const f1 = mkFinding({ id: "f1", title: "idor", category: "idor" });
    const f2 = mkFinding({ id: "f2", title: "gated", category: "broken_authentication" });
    expect(evaluateChainCondition(appMapWithCreds, f1, f2, routeReadsUser, gatedRoute)?.kind).toBe(
      "idor-credential-leak",
    );
  });
});
