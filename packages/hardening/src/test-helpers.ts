/** Minimal, hand-built AppMap/ConfirmedFinding builders for this package's tests. */
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  type AppMap,
  type Category,
  type ConfirmedFinding,
  type Framework,
  type Route,
} from "@montr/contracts";

export const NOW = "2026-08-22T00:00:00.000Z";

export function baseAppMap(overrides: Partial<AppMap> = {}): AppMap {
  return AppMapSchema.parse({
    id: "appmap_1",
    clientId: "client_1",
    scanId: "scan_1",
    repo: "example/repo",
    branch: "main",
    commitSha: "abc1234",
    createdAt: NOW,
    languages: ["typescript"],
    frameworks: [] as Framework[],
    routes: [] as Route[],
    ...overrides,
  });
}

export function route(overrides: Partial<Route> = {}): Route {
  return {
    path: "/api/public",
    method: "GET",
    authState: "public",
    isApiRoute: true,
    ...overrides,
  };
}

export function confirmedFinding(overrides: Partial<ConfirmedFinding> = {}): ConfirmedFinding {
  const category: Category = overrides.category ?? "sql_injection";
  return ConfirmedFindingSchema.parse({
    id: "finding_1",
    scanId: "scan_1",
    clientId: "client_1",
    title: `Confirmed ${category}`,
    category,
    cwe: [],
    severity: "high",
    exposure: "public",
    location: { file: "src/routes/orders.ts", line: 42 },
    impact: "Confirmed exploitable.",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: "tainted input reaches the sink",
      dataFlow: [],
      sanitizersBypassed: [],
    },
    createdAt: NOW,
    ...overrides,
  });
}
