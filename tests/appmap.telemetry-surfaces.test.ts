/**
 * B6 — detection-coverage gap analysis:
 *   1. `telemetrySurfaces` population (`packages/appmap/src/telemetry-surfaces.ts`)
 *      against a real fixture repo with real logging-library imports.
 *   2. The tri-state `DetectionCoverage` verdict
 *      (`packages/appmap/src/coverage-analysis.ts`), earned from real signals
 *      — never a coin flip or a hardcoded fallback.
 */
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  buildAppMap,
  buildTelemetrySurfaces,
  detectRepoTelemetry,
  detectRouteTelemetry,
  collectFiles,
  createProject,
  evaluateCoverageForFinding,
  routeForFinding,
  buildDetectionCoverage,
  persistDetectionCoverageForScan,
} from "@montr/appmap";
import type { BuildAppMapInput } from "@montr/appmap";
import { getHardenedDefaults } from "@montr/config";
import {
  mockAppMap,
  mockConfirmedFindings,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  COMMIT_SHA,
  CONFIRMED_SQLI_ID,
  CONFIRMED_XSS_ID,
} from "@montr/fixtures";
import {
  ScanScopeSchema,
  DetectionRuleSchema,
  DetectionCoverageSchema,
  type AppMap,
  type DetectionRule,
  type TelemetrySurfaces,
} from "@montr/contracts";
import type { DetectionCoverageRepository, DetectionRuleRepository } from "@montr/state-store";

const MIXED_LOGGING_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/telemetry-samples/mixed-logging", import.meta.url),
);
const EXPRESS_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/express-sample", import.meta.url),
);

const fixedNow = (): Date => new Date(FIXED_NOW);

function baseInput(dir: string, overrides: Partial<BuildAppMapInput> = {}): BuildAppMapInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: dir,
    branch: "main",
    mode: "full",
    scope: ScanScopeSchema.parse({ mode: "full" }),
    config: getHardenedDefaults(),
    commitSha: COMMIT_SHA,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. telemetry-surfaces population against a real fixture repo.
// ---------------------------------------------------------------------------

describe("appmap telemetry-surfaces — repo-level detection (real fixture, real imports)", () => {
  it("detects the real winston dependency + a real APM (@sentry/node) dependency", async () => {
    const inv = await collectFiles(MIXED_LOGGING_DIR);
    const { loggingLibraries, observabilityTools } = await detectRepoTelemetry(
      MIXED_LOGGING_DIR,
      inv,
    );
    expect(loggingLibraries).toContain("winston");
    expect(observabilityTools).toEqual(
      expect.arrayContaining([{ kind: "sentry", packageName: "@sentry/node" }]),
    );
  });

  it("detects zero logging libraries/APM tools on the plain express-sample fixture", async () => {
    const inv = await collectFiles(EXPRESS_DIR);
    const { loggingLibraries, observabilityTools } = await detectRepoTelemetry(EXPRESS_DIR, inv);
    expect(loggingLibraries).toEqual([]);
    expect(observabilityTools).toEqual([]);
  });
});

describe("appmap telemetry-surfaces — per-route logging detection (real ts-morph AST scan)", () => {
  it("distinguishes structured / console / silent routes in the same file, with a real matched sample", async () => {
    const inv = await collectFiles(MIXED_LOGGING_DIR);
    const project = createProject(MIXED_LOGGING_DIR, inv.sourceFiles);
    const appMapResult = await buildAppMap(baseInput(MIXED_LOGGING_DIR), { now: fixedNow });
    const routes = appMapResult.appMap.routes;
    expect(routes.length).toBeGreaterThanOrEqual(3);

    const telemetry = detectRouteTelemetry(project, MIXED_LOGGING_DIR, routes, true);
    const byPath = new Map(telemetry.map((t) => [t.path, t]));

    const orders = byPath.get("/orders");
    expect(orders?.hasLoggingCall).toBe(true);
    expect(orders?.loggerKind).toBe("structured");
    expect(orders?.sample).toMatch(/logger\.info/);

    const health = byPath.get("/health");
    expect(health?.hasLoggingCall).toBe(true);
    expect(health?.loggerKind).toBe("console");
    expect(health?.sample).toMatch(/console\.log/);

    const secret = byPath.get("/secret");
    expect(secret?.hasLoggingCall).toBe(false);
    expect(secret?.loggerKind).toBeUndefined();
  });

  it("buildTelemetrySurfaces combines both signals end-to-end on the real fixture", async () => {
    const inv = await collectFiles(MIXED_LOGGING_DIR);
    const appMapResult = await buildAppMap(baseInput(MIXED_LOGGING_DIR), { now: fixedNow });
    const surfaces = await buildTelemetrySurfaces(appMapResult.appMap, {
      dir: MIXED_LOGGING_DIR,
      inventory: inv,
    });
    expect(surfaces.hasStructuredLogging).toBe(true);
    expect(surfaces.loggingLibraries).toContain("winston");
    expect(surfaces.routes.some((r) => r.path === "/orders" && r.loggerKind === "structured")).toBe(
      true,
    );
    expect(surfaces.routes.some((r) => r.path === "/secret" && r.hasLoggingCall === false)).toBe(
      true,
    );
  });

  it("is wired into buildAppMap's real Layer 0 output (AppMap.telemetrySurfaces)", async () => {
    const result = await buildAppMap(baseInput(MIXED_LOGGING_DIR), { now: fixedNow });
    expect(result.appMap.telemetrySurfaces).toBeDefined();
    expect(result.appMap.telemetrySurfaces?.hasStructuredLogging).toBe(true);
  });

  it("degrades to a defined-but-empty telemetrySurfaces on a repo with zero logging (never crashes)", async () => {
    const result = await buildAppMap(baseInput(EXPRESS_DIR), { now: fixedNow });
    expect(result.appMap.telemetrySurfaces).toBeDefined();
    expect(result.appMap.telemetrySurfaces?.hasStructuredLogging).toBe(false);
    expect(result.appMap.telemetrySurfaces?.loggingLibraries).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. Detection-coverage gap analysis — tri-state verdict, real signals only.
// ---------------------------------------------------------------------------

function rule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return DetectionRuleSchema.parse({
    id: "rule_0001",
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    findingId: CONFIRMED_SQLI_ID,
    format: "sigma",
    content: "title: SQLi via raw query\nlogsource: {product: node}\ndetection: {...}",
    mitreTechniques: ["T1190"],
    provenance: "static",
    createdAt: FIXED_NOW,
    ...overrides,
  });
}

/** `mockAppMap` augmented with a hand-built `telemetrySurfaces` for the two fixture routes. */
function appMapWithTelemetry(telemetrySurfaces: TelemetrySurfaces): AppMap {
  return { ...mockAppMap, telemetrySurfaces };
}

describe("appmap coverage-analysis — 'detected' (structured logging + a real rule)", () => {
  it("scores detected:true with a specific, non-boilerplate reasoning naming the route and rule", () => {
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: true,
      loggingLibraries: ["winston"],
      observabilityTools: [],
      routes: [
        {
          path: "/api/users",
          method: "GET",
          hasLoggingCall: true,
          loggerKind: "structured",
          sample: 'logger.info("users fetched", { q })',
        },
      ],
    });
    const finding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_SQLI_ID)!;
    const verdict = evaluateCoverageForFinding(appMap, finding, [rule()]);

    expect(verdict.detected).toBe(true);
    expect(verdict.detectionRuleId).toBe("rule_0001");
    expect(verdict.reasoning).toMatch(/\/api\/users/);
    expect(verdict.reasoning).toMatch(/rule_0001/);
    expect(verdict.reasoning).toMatch(/structured logging call/);
  });
});

describe("appmap coverage-analysis — 'not_detected' (a real, named blind spot)", () => {
  it("scores detected:false and names the exact gap: zero logging calls on the route's handler", () => {
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: true,
      loggingLibraries: ["winston"],
      observabilityTools: [],
      routes: [
        {
          path: "/search",
          method: "GET",
          hasLoggingCall: false,
        },
      ],
    });
    const finding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_XSS_ID)!;
    const verdict = evaluateCoverageForFinding(appMap, finding, [
      rule({ id: "rule_0002", findingId: CONFIRMED_XSS_ID }),
    ]);

    expect(verdict.detected).toBe(false);
    // The reasoning must name the CONCRETE gap (no logging call at all on this
    // specific route's handler), not generic boilerplate.
    expect(verdict.reasoning).toMatch(/\/search/);
    expect(verdict.reasoning).toMatch(/NO logging call/);
    expect(verdict.reasoning).toMatch(/app\/search\/page\.tsx/);
  });

  it("scores detected:false when structured/console logging exists but no rule has been generated yet", () => {
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: true,
      loggingLibraries: ["winston"],
      observabilityTools: [],
      routes: [
        { path: "/api/users", method: "GET", hasLoggingCall: true, loggerKind: "structured" },
      ],
    });
    const finding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_SQLI_ID)!;
    const verdict = evaluateCoverageForFinding(appMap, finding, []); // no rules exist yet

    expect(verdict.detected).toBe(false);
    expect(verdict.detectionRuleId).toBeUndefined();
    expect(verdict.reasoning).toMatch(/no detection rule exists yet/);
  });
});

describe("appmap coverage-analysis — 'unknown' (a genuinely ambiguous case, not a default)", () => {
  it("scores unknown when logging is console-only (real logging, but too coarse to tell)", () => {
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: true,
      loggingLibraries: ["winston"],
      observabilityTools: [],
      routes: [
        {
          path: "/api/users",
          method: "GET",
          hasLoggingCall: true,
          loggerKind: "console",
          sample: 'console.log("hit users")',
        },
      ],
    });
    const finding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_SQLI_ID)!;
    const verdict = evaluateCoverageForFinding(appMap, finding, [rule()]);

    expect(verdict.detected).toBe("unknown");
    expect(verdict.reasoning).toMatch(/console/);
    expect(verdict.reasoning).toMatch(/structured fields/);
  });

  it("scores unknown (not false) when a rule exists but the route was never analyzed for telemetry", () => {
    // telemetrySurfaces present, but with no entry at all for this route path —
    // i.e. genuinely never analyzed, distinct from "analyzed and found silent".
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: false,
      loggingLibraries: [],
      observabilityTools: [],
      routes: [],
    });
    const finding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_SQLI_ID)!;
    const verdict = evaluateCoverageForFinding(appMap, finding, [rule()]);

    expect(verdict.detected).toBe("unknown");
    expect(verdict.reasoning).toMatch(/never analyzed/);
    expect(verdict.detectionRuleId).toBe("rule_0001");
  });

  it("does NOT default to unknown for every case — a resolvable route with zero logging is a firm false", () => {
    // Regression guard: "unknown" must be earned, not the fallback shape.
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: false,
      loggingLibraries: [],
      observabilityTools: [],
      routes: [{ path: "/api/users", method: "GET", hasLoggingCall: false }],
    });
    const finding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_SQLI_ID)!;
    const verdict = evaluateCoverageForFinding(appMap, finding, [rule()]);
    expect(verdict.detected).toBe(false);
  });
});

describe("appmap coverage-analysis — routeForFinding proximity resolution", () => {
  it("picks the closest-preceding route handler when multiple routes share one file", () => {
    const appMap: AppMap = {
      ...mockAppMap,
      routes: [
        {
          path: "/a",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "x.ts", line: 5 },
        },
        {
          path: "/b",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "x.ts", line: 20 },
        },
      ],
    };
    const finding = { ...mockConfirmedFindings[0]!, location: { file: "x.ts", line: 22 } };
    const route = routeForFinding(appMap, finding);
    expect(route?.path).toBe("/b");
  });
});

describe("appmap coverage-analysis — buildDetectionCoverage / persistDetectionCoverageForScan", () => {
  it("builds one real, schema-valid DetectionCoverage row per confirmed finding", () => {
    const appMap = appMapWithTelemetry({
      hasStructuredLogging: true,
      loggingLibraries: ["winston"],
      observabilityTools: [],
      routes: [
        { path: "/api/users", method: "GET", hasLoggingCall: true, loggerKind: "structured" },
        { path: "/search", method: "GET", hasLoggingCall: false },
      ],
    });
    const rows = buildDetectionCoverage(appMap, mockConfirmedFindings, [rule()], {
      now: fixedNow,
    });
    expect(rows).toHaveLength(mockConfirmedFindings.length);
    for (const row of rows) {
      expect(() => DetectionCoverageSchema.parse(row)).not.toThrow();
    }
    const sqli = rows.find((r) => r.findingId === CONFIRMED_SQLI_ID);
    expect(sqli?.detected).toBe(true);
    const xss = rows.find((r) => r.findingId === CONFIRMED_XSS_ID);
    expect(xss?.detected).toBe(false);
  });

  it("persists real rows through the actual DetectionCoverageRepository/DetectionRuleRepository contract", async () => {
    const createdCoverage: unknown[] = [];
    const fakeRules: DetectionRuleRepository = {
      create: async (_clientId, r) => r,
      get: async () => null,
      list: async () => [],
      listByFinding: async (_clientId, findingId) =>
        findingId === CONFIRMED_SQLI_ID ? [rule()] : [],
    };
    const fakeCoverage: DetectionCoverageRepository = {
      create: async (_clientId, c) => {
        createdCoverage.push(c);
        return c;
      },
      get: async () => null,
      list: async () => [],
      listByFinding: async () => [],
      updateVerification: async (): Promise<never> => {
        throw new Error("not needed for this test");
      },
    };

    const appMap = appMapWithTelemetry({
      hasStructuredLogging: true,
      loggingLibraries: ["winston"],
      observabilityTools: [],
      routes: [
        { path: "/api/users", method: "GET", hasLoggingCall: true, loggerKind: "structured" },
        { path: "/search", method: "GET", hasLoggingCall: false },
      ],
    });

    const result = await persistDetectionCoverageForScan(
      appMap,
      mockConfirmedFindings,
      { detectionCoverage: fakeCoverage, detectionRules: fakeRules },
      { now: fixedNow },
    );

    expect(result).toHaveLength(mockConfirmedFindings.length);
    expect(createdCoverage).toHaveLength(mockConfirmedFindings.length);
    const sqliRow = result.find((r) => r.findingId === CONFIRMED_SQLI_ID);
    expect(sqliRow?.detected).toBe(true);
    expect(sqliRow?.detectionRuleId).toBe("rule_0001");
  });

  it("returns an empty array without calling the repository when there are no confirmed findings", async () => {
    let called = false;
    const fakeRules: DetectionRuleRepository = {
      create: async (_c, r) => r,
      get: async () => null,
      list: async () => [],
      listByFinding: async () => [],
    };
    const fakeCoverage: DetectionCoverageRepository = {
      create: async (_c, c) => {
        called = true;
        return c;
      },
      get: async () => null,
      list: async () => [],
      listByFinding: async () => [],
      updateVerification: async (): Promise<never> => {
        throw new Error("unused");
      },
    };
    const result = await persistDetectionCoverageForScan(mockAppMap, [], {
      detectionCoverage: fakeCoverage,
      detectionRules: fakeRules,
    });
    expect(result).toEqual([]);
    expect(called).toBe(false);
  });
});
