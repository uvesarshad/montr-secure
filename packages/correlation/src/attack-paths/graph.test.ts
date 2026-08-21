/**
 * B8 — attack-path graph. Verifies: (1) two findings that genuinely satisfy a
 * chain condition produce a real `AttackPath` with a specific, grounded
 * narrative; (2) two UNRELATED findings never chain (precision — this must
 * not be a combinatorial "any two findings" noise generator); (3) the
 * RCE-enables-everything case is flagged distinctly (its own condition kind,
 * and the path severity is force-bumped to "critical"); (4) only MAXIMAL
 * chains survive — a real 3-hop chain's own 2-hop prefix is never also
 * emitted as a separate, redundant path; (5) ranking sorts a live-DAST-proven
 * chain above an otherwise-identical static-proof-only chain.
 */
import { describe, it, expect } from "vitest";
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  type AppMap,
  type ConfirmedFinding,
} from "@montr/contracts";
import { buildAttackPathCandidates, buildAttackPaths } from "./graph.js";

const CLIENT_ID = "client_1";
const SCAN_ID = "scan_1";
const NOW = "2026-08-22T00:00:00.000Z";

function mkFinding(
  overrides: Partial<ConfirmedFinding> &
    Pick<ConfirmedFinding, "id" | "title" | "category" | "location">,
): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    severity: "high",
    exposure: "public",
    impact: "test finding",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "test-arg", dataFlow: [], sanitizersBypassed: [] },
    createdAt: NOW,
    ...overrides,
  });
}

/** A single-route, no-model App Map — extended per-test with additional routes/ormModels/taintSinks. */
function baseAppMap(extra: Partial<AppMap>): AppMap {
  return AppMapSchema.parse({
    id: "appmap_1",
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: "https://example.internal/montr/attack-path-fixture",
    branch: "main",
    commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334",
    createdAt: NOW,
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
    ...extra,
  });
}

describe("@montr/correlation attack-paths — SSRF -> internal-only pivot", () => {
  const appMap = baseAppMap({
    routes: [
      {
        id: "route_webhook",
        path: "/api/webhooks/register",
        method: "POST",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/webhooks/register/route.ts", line: 10 },
      },
      {
        id: "route_exports",
        path: "/api/exports/:id",
        method: "GET",
        authState: "role_gated",
        isApiRoute: true,
        handler: { file: "app/api/exports/[id]/route.ts", line: 8 },
      },
    ],
    taintSinks: [
      {
        kind: "http_client",
        location: { file: "app/api/webhooks/register/route.ts", line: 12 },
        description: "fetch(targetUrl)",
      },
    ],
  });

  const ssrf = mkFinding({
    id: "f_ssrf",
    title: "SSRF via unvalidated webhook target URL",
    category: "ssrf",
    location: { file: "app/api/webhooks/register/route.ts", line: 12 },
    exposure: "public",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "targetUrl", dataFlow: [], sanitizersBypassed: [] },
  });

  const exportsLeak = mkFinding({
    id: "f_exports",
    title: "S3 export bucket read via internal metadata credentials",
    category: "sensitive_data_exposure",
    location: { file: "app/api/exports/[id]/route.ts", line: 8 },
    exposure: "authed",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "exportId", dataFlow: [], sanitizersBypassed: [] },
  });

  it("chains the SSRF into the role-gated route with a grounded, specific narrative", () => {
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap,
      findings: [ssrf, exportsLeak],
      now: NOW,
    });

    expect(candidates).toHaveLength(1);
    const [chain] = candidates;
    expect(chain!.attackPath.steps.map((s) => s.findingId)).toEqual(["f_ssrf", "f_exports"]);
    expect(chain!.conditions[0]?.kind).toBe("ssrf-internal-pivot");
    // The http_client taint sink at the SSRF's own location corroborates the category tag.
    expect(chain!.conditions[0]?.strength).toBeCloseTo(0.55, 5);

    const narrative = chain!.attackPath.narrative;
    expect(narrative).toContain("POST /api/webhooks/register");
    expect(narrative).toContain("SSRF via unvalidated webhook target URL");
    expect(narrative).toContain("GET /api/exports/:id");
    expect(narrative).toContain("S3 export bucket read via internal metadata credentials");

    expect(() =>
      buildAttackPaths({
        clientId: CLIENT_ID,
        scanId: SCAN_ID,
        appMap,
        findings: [ssrf, exportsLeak],
        now: NOW,
      }),
    ).not.toThrow();
  });

  it("does NOT chain when the second finding is on an equally-public route (no internal-pivot signal)", () => {
    const publicAppMap = baseAppMap({
      routes: [{ ...appMap.routes[0]! }, { ...appMap.routes[1]!, authState: "public" }],
      taintSinks: appMap.taintSinks,
    });
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: publicAppMap,
      findings: [ssrf, exportsLeak],
      now: NOW,
    });
    expect(candidates).toHaveLength(0);
  });
});

describe("@montr/correlation attack-paths — IDOR credential leak", () => {
  const appMap = baseAppMap({
    routes: [
      {
        id: "route_profile",
        path: "/api/profile/:id",
        method: "GET",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/profile/[id]/route.ts", line: 6 },
        referencedModels: [{ modelName: "User", operations: ["read"] }],
      },
      {
        id: "route_admin",
        path: "/api/admin/dashboard",
        method: "GET",
        authState: "authenticated",
        isApiRoute: true,
        handler: { file: "app/api/admin/dashboard/route.ts", line: 4 },
      },
    ],
    ormModels: [
      {
        name: "User",
        dataStore: "app_db",
        file: "prisma/schema.prisma",
        fields: [
          { name: "id", type: "Int", isId: true },
          { name: "email", type: "String", isId: false },
          { name: "apiKey", type: "String", isId: false },
        ],
      },
    ],
  });

  const idor = mkFinding({
    id: "f_idor",
    title: "IDOR on /api/profile/:id exposes any user's record",
    category: "idor",
    location: { file: "app/api/profile/[id]/route.ts", line: 6 },
    exposure: "public",
  });

  const admin = mkFinding({
    id: "f_admin",
    title: "Admin dashboard trusts client-supplied role header",
    category: "broken_authentication",
    location: { file: "app/api/admin/dashboard/route.ts", line: 4 },
    exposure: "authed",
  });

  it("chains an IDOR that leaks a credential-shaped field into a different authed route", () => {
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap,
      findings: [idor, admin],
      now: NOW,
    });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.conditions[0]?.kind).toBe("idor-credential-leak");
    expect(candidates[0]!.attackPath.narrative).toContain("leaking credentials");
  });

  it("does NOT chain an IDOR whose exposed model has no credential-shaped field", () => {
    const noCredAppMap = baseAppMap({
      routes: appMap.routes,
      ormModels: [
        {
          name: "User",
          dataStore: "app_db",
          file: "prisma/schema.prisma",
          fields: [
            { name: "id", type: "Int", isId: true },
            { name: "email", type: "String", isId: false },
            { name: "displayName", type: "String", isId: false },
          ],
        },
      ],
    });
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: noCredAppMap,
      findings: [idor, admin],
      now: NOW,
    });
    expect(candidates).toHaveLength(0);
  });
});

describe("@montr/correlation attack-paths — RCE-class enables everything (flagged distinctly)", () => {
  const appMap = baseAppMap({
    routes: [
      {
        id: "route_convert",
        path: "/api/convert",
        method: "POST",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/convert/route.ts", line: 20 },
      },
      {
        id: "route_reports",
        path: "/api/reports",
        method: "GET",
        authState: "authenticated",
        isApiRoute: true,
        handler: { file: "app/api/reports/route.ts", line: 5 },
      },
    ],
  });

  const rce = mkFinding({
    id: "f_rce",
    title: "OS command injection in file-conversion pipeline",
    category: "command_injection",
    location: { file: "app/api/convert/route.ts", line: 20 },
    severity: "critical",
  });

  const unrelated = mkFinding({
    id: "f_reports",
    title: "Missing rate limit on report generation",
    category: "rate_limit_missing",
    location: { file: "app/api/reports/route.ts", line: 5 },
    severity: "low",
  });

  it("chains an RCE-class finding to an otherwise-unrelated finding via the distinct rce-post-exploitation kind", () => {
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap,
      findings: [rce, unrelated],
      now: NOW,
    });
    expect(candidates).toHaveLength(1);
    const [chain] = candidates;
    expect(chain!.conditions[0]?.kind).toBe("rce-post-exploitation");
    expect(chain!.conditions[0]?.strength).toBeGreaterThan(0.9);
    // The chain's own severity is force-bumped to critical even though the
    // second hop's raw severity is "low" — post-RCE, it's game over regardless.
    expect(chain!.attackPath.severity).toBe("critical");
    expect(chain!.attackPath.narrative).toContain("arbitrary code execution");
  });
});

describe("@montr/correlation attack-paths — precision: unrelated findings never chain", () => {
  it("two config-class findings on different public routes, sharing no model, produce zero chains", () => {
    const appMap = baseAppMap({
      routes: [
        {
          id: "route_a",
          path: "/api/a",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/a/route.ts", line: 3 },
        },
        {
          id: "route_b",
          path: "/api/b",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/b/route.ts", line: 3 },
        },
      ],
    });
    const a = mkFinding({
      id: "f_a",
      title: "Missing security headers on /api/a",
      category: "missing_security_headers",
      location: { file: "app/api/a/route.ts", line: 3 },
    });
    const b = mkFinding({
      id: "f_b",
      title: "Missing security headers on /api/b",
      category: "missing_security_headers",
      location: { file: "app/api/b/route.ts", line: 3 },
    });
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap,
      findings: [a, b],
      now: NOW,
    });
    expect(candidates).toHaveLength(0);
    expect(
      buildAttackPaths({
        clientId: CLIENT_ID,
        scanId: SCAN_ID,
        appMap,
        findings: [a, b],
        now: NOW,
      }),
    ).toHaveLength(0);
  });

  it("fewer than 2 confirmed findings never produces a chain (contract's own .min(2) on steps)", () => {
    const appMap = baseAppMap({});
    const solo = mkFinding({
      id: "f_solo",
      title: "Solo finding",
      category: "ssrf",
      location: { file: "app/api/x/route.ts", line: 1 },
    });
    expect(
      buildAttackPathCandidates({
        clientId: CLIENT_ID,
        scanId: SCAN_ID,
        appMap,
        findings: [solo],
        now: NOW,
      }),
    ).toHaveLength(0);
    expect(
      buildAttackPathCandidates({
        clientId: CLIENT_ID,
        scanId: SCAN_ID,
        appMap,
        findings: [],
        now: NOW,
      }),
    ).toHaveLength(0);
  });
});

describe("@montr/correlation attack-paths — only MAXIMAL chains survive", () => {
  const appMap = baseAppMap({
    routes: [
      {
        id: "route_rce",
        path: "/api/convert",
        method: "POST",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/convert/route.ts", line: 20 },
      },
      {
        id: "route_profile",
        path: "/api/profile/:id",
        method: "GET",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/profile/[id]/route.ts", line: 6 },
        referencedModels: [{ modelName: "User", operations: ["read"] }],
      },
      {
        id: "route_admin",
        path: "/api/admin/dashboard",
        method: "GET",
        authState: "authenticated",
        isApiRoute: true,
        handler: { file: "app/api/admin/dashboard/route.ts", line: 4 },
      },
    ],
    ormModels: [
      {
        name: "User",
        dataStore: "app_db",
        file: "prisma/schema.prisma",
        fields: [
          { name: "id", type: "Int", isId: true },
          { name: "sessionId", type: "String", isId: false },
        ],
      },
    ],
  });

  // f1 (RCE) -> f2 (IDOR, credential leak) -> f3 (admin route requiring auth).
  // f1 also has a direct RCE edge straight to f3 (RCE reaches EVERY other
  // finding), so [f1, f3] is legitimately its own maximal 2-hop path too —
  // what must NOT appear is [f1, f2] alone, since that's a strict prefix of
  // the real 3-hop chain [f1, f2, f3].
  const f1 = mkFinding({
    id: "f1_rce",
    title: "OS command injection in file-conversion pipeline",
    category: "command_injection",
    location: { file: "app/api/convert/route.ts", line: 20 },
  });
  const f2 = mkFinding({
    id: "f2_idor",
    title: "IDOR on /api/profile/:id exposes any user's session id",
    category: "idor",
    location: { file: "app/api/profile/[id]/route.ts", line: 6 },
  });
  const f3 = mkFinding({
    id: "f3_admin",
    title: "Admin dashboard trusts client-supplied role header",
    category: "broken_authentication",
    location: { file: "app/api/admin/dashboard/route.ts", line: 4 },
    exposure: "authed",
  });

  it("emits the full 3-hop chain but never its own redundant 2-hop [f1, f2] prefix", () => {
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap,
      findings: [f1, f2, f3],
      now: NOW,
    });
    const keyOf = (ids: string[]) => ids.join(">");
    const keys = candidates.map((c) => keyOf(c.attackPath.steps.map((s) => s.findingId)));

    expect(keys).toContain(keyOf(["f1_rce", "f2_idor", "f3_admin"]));
    expect(keys).not.toContain(keyOf(["f1_rce", "f2_idor"]));
  });
});

describe("@montr/correlation attack-paths — feasibility ranks live-DAST-proven above static-proof-only", () => {
  const appMap = baseAppMap({
    routes: [
      {
        id: "route_webhook_live",
        path: "/api/webhooks/live",
        method: "POST",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/webhooks/live/route.ts", line: 10 },
      },
      {
        id: "route_internal_live",
        path: "/api/internal/live",
        method: "GET",
        authState: "role_gated",
        isApiRoute: true,
        handler: { file: "app/api/internal/live/route.ts", line: 8 },
      },
      {
        id: "route_webhook_static",
        path: "/api/webhooks/static",
        method: "POST",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/webhooks/static/route.ts", line: 10 },
      },
      {
        id: "route_internal_static",
        path: "/api/internal/static",
        method: "GET",
        authState: "role_gated",
        isApiRoute: true,
        handler: { file: "app/api/internal/static/route.ts", line: 8 },
      },
    ],
  });

  const liveTranscript = {
    kind: "live" as const,
    target: "https://staging.internal",
    transcript: [
      {
        request: { method: "POST", url: "/api/webhooks/live" },
        response: { status: 200 },
      },
    ],
  };

  const ssrfLive = mkFinding({
    id: "f_ssrf_live",
    title: "SSRF (live-proven) via webhook target URL",
    category: "ssrf",
    location: { file: "app/api/webhooks/live/route.ts", line: 10 },
    proofType: "live",
    proofArtifact: liveTranscript,
  });
  const internalLive = mkFinding({
    id: "f_internal_live",
    title: "Internal metadata read (live-proven)",
    category: "sensitive_data_exposure",
    location: { file: "app/api/internal/live/route.ts", line: 8 },
    exposure: "authed",
    proofType: "live",
    proofArtifact: { ...liveTranscript, target: "https://staging.internal/2" },
  });

  const ssrfStatic = mkFinding({
    id: "f_ssrf_static",
    title: "SSRF (static-only) via webhook target URL",
    category: "ssrf",
    location: { file: "app/api/webhooks/static/route.ts", line: 10 },
    proofType: "static",
    proofArtifact: { kind: "static", argument: "targetUrl", dataFlow: [], sanitizersBypassed: [] },
  });
  const internalStatic = mkFinding({
    id: "f_internal_static",
    title: "Internal metadata read (static-only)",
    category: "sensitive_data_exposure",
    location: { file: "app/api/internal/static/route.ts", line: 8 },
    exposure: "authed",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "exportId", dataFlow: [], sanitizersBypassed: [] },
  });

  it("ranks the live chain strictly above the structurally-identical static chain", () => {
    const candidates = buildAttackPathCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap,
      findings: [ssrfStatic, internalStatic, ssrfLive, internalLive],
      now: NOW,
    });

    // The SSRF condition doesn't require file/route adjacency (it's a genuinely
    // speculative "reaches SOME internal-only route" signal — see ./conditions.ts),
    // so all 4 cross-pairs of {live,static} x {live,static} legitimately chain;
    // what this test pins down is the RANKING, not the raw count.
    const keyed = (findingId: string, otherId: string) =>
      candidates.find(
        (c) =>
          c.attackPath.steps[0]?.findingId === findingId &&
          c.attackPath.steps[1]?.findingId === otherId,
      )!;
    const liveChain = keyed("f_ssrf_live", "f_internal_live");
    const staticChain = keyed("f_ssrf_static", "f_internal_static");
    expect(liveChain.attackPath.feasibilityScore).toBeGreaterThan(
      staticChain.attackPath.feasibilityScore,
    );
    // Ranked output: the all-live chain (highest confirmation confidence on both
    // hops) sorts strictly first among all four cross-pairs.
    expect(candidates[0]!.attackPath.steps[0]?.findingId).toBe("f_ssrf_live");
    expect(candidates[0]!.attackPath.steps[1]?.findingId).toBe("f_internal_live");
  });
});
