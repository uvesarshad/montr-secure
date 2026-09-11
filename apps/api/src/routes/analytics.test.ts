/**
 * GET /analytics/blue-team (A5, red/blue agentic-posture audit) — the
 * org-wide blue-team aggregate: ATT&CK coverage rolled up from each scan's
 * already-built `Report.blueTeam.mitreAttack` (B2/B10), a cross-scan
 * detection-rule inventory deduped by (format, content), and the real,
 * persisted (A7) `DetectionCoverage` trend across scans. Every other
 * `/analytics/*` route already ships without a dedicated test file; this one
 * gets one because the aggregation logic (merge, dedup, chronological
 * ordering) is genuinely non-trivial and worth locking down.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  ReportSchema,
  type DetectionCoverage,
  type DetectionRule,
  type MitreTechniqueCoverageShape,
  type Report,
  type Scan,
} from "@montr/contracts";
import { buildServer, createInMemoryDeps } from "../server.js";

const PASSWORD = "correct-horse-battery-staple";
const NOW = new Date("2026-09-12T12:00:00.000Z");
const CLIENT_ID = "default";

interface Session {
  token: string;
  id: string;
}

async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver" | "viewer",
): Promise<Session> {
  await app.inject({
    method: "POST",
    url: "/api/v1/auth/register",
    payload: { email, password: PASSWORD, ...(role ? { role } : {}) },
  });
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email, password: PASSWORD },
  });
  const body = res.json() as { token: string; user: { id: string } };
  return { token: body.token, id: body.user.id };
}

function scanFixture(overrides: Partial<Scan> & { id: string; createdAt: string }): Scan {
  return {
    clientId: CLIENT_ID,
    repo: "acme/blue-team-repo",
    branch: "main",
    mode: "full",
    scope: {
      mode: "full",
      includePaths: [],
      excludePaths: [],
      changedFiles: [],
      reachableFromChanges: false,
    },
    status: "completed",
    gateState: "not_started",
    operator: "blue-team-operator",
    ...overrides,
  };
}

function technique(
  id: string,
  name: string,
  tactic: string,
): MitreTechniqueCoverageShape["technique"] {
  return {
    id,
    name,
    tactic,
    framework: "attack-enterprise",
    url: `https://attack.mitre.org/techniques/${id}/`,
  };
}

function reportFixture(
  scanId: string,
  createdAt: string,
  coverage: MitreTechniqueCoverageShape[],
): Report {
  return ReportSchema.parse({
    id: `report_${scanId}`,
    scanId,
    clientId: CLIENT_ID,
    generatedAt: createdAt,
    executiveSummary: { totalConfirmed: 0, confirmedBySeverity: {} },
    fixStatus: {},
    costAndScope: {
      scope: { mode: "full" },
      cost: {
        scanId,
        estimate: {
          mode: "full",
          projectedInputTokens: 0,
          projectedOutputTokens: 0,
          projectedTotalTokens: 0,
          projectedUsd: 0,
          projectedWallClockSeconds: 0,
          basis: "test fixture",
          createdAt,
        },
      },
    },
    blueTeam: {
      mitreAttack: { findings: [], coverage },
    },
  });
}

function ruleFixture(
  overrides: Partial<DetectionRule> & { id: string; scanId: string; findingId: string },
): DetectionRule {
  return {
    clientId: CLIENT_ID,
    format: "sigma",
    content: "title: default rule\ndetection: {}",
    mitreTechniques: [],
    provenance: "static",
    createdAt: "2026-07-01T00:00:00.000Z",
    ...overrides,
  };
}

function coverageFixture(
  overrides: Partial<DetectionCoverage> & { id: string; scanId: string; findingId: string },
): DetectionCoverage {
  return {
    clientId: CLIENT_ID,
    detected: "unknown",
    reasoning: "no relevant rule exists yet",
    createdAt: "2026-07-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("GET /analytics/blue-team", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let viewer: Session;
  let operator: Session;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    viewer = await registerAndLogin(app, "bt-viewer@example.internal", "viewer");
    operator = await registerAndLogin(app, "bt-operator@example.internal", "operator");

    // Two scans of the same repo, chronological: scan_a then scan_b.
    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({
        id: "scan_a",
        createdAt: "2026-07-01T00:00:00.000Z",
        finishedAt: "2026-07-01T01:00:00.000Z",
      }),
    );
    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({
        id: "scan_b",
        createdAt: "2026-08-01T00:00:00.000Z",
        finishedAt: "2026-08-01T01:00:00.000Z",
      }),
    );
    // A third scan with no generated report — must be skipped, not crash.
    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({ id: "scan_no_report", createdAt: "2026-08-15T00:00:00.000Z" }),
    );

    // scan_a covers T1190 (1 finding); scan_b covers T1190 again (1 more
    // finding, same technique) plus a new technique T1059.
    await deps.store.reports.save(
      reportFixture("scan_a", "2026-07-01T01:00:00.000Z", [
        {
          technique: technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
          findingCount: 1,
          findingIds: ["f_a1"],
        },
      ]),
    );
    await deps.store.reports.save(
      reportFixture("scan_b", "2026-08-01T01:00:00.000Z", [
        {
          technique: technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
          findingCount: 1,
          findingIds: ["f_b1"],
        },
        {
          technique: technique("T1059", "Command and Scripting Interpreter", "Execution"),
          findingCount: 1,
          findingIds: ["f_b2"],
        },
      ]),
    );

    // Detection rules: scan_a and scan_b each generate the SAME sigma rule
    // content for the same recurring finding pattern (must dedup to one
    // inventory entry, occurrences: 2), plus one distinct otel rule.
    await deps.store.detectionRules.create(
      CLIENT_ID,
      ruleFixture({
        id: "rule_a1",
        scanId: "scan_a",
        findingId: "f_a1",
        format: "sigma",
        content: "title: SQLi via raw query\ndetection: recurring",
        mitreTechniques: ["T1190"],
        createdAt: "2026-07-01T01:00:00.000Z",
      }),
    );
    await deps.store.detectionRules.create(
      CLIENT_ID,
      ruleFixture({
        id: "rule_b1",
        scanId: "scan_b",
        findingId: "f_b1",
        format: "sigma",
        content: "title: SQLi via raw query\ndetection: recurring",
        mitreTechniques: ["T1190"],
        createdAt: "2026-08-01T01:00:00.000Z",
      }),
    );
    await deps.store.detectionRules.create(
      CLIENT_ID,
      ruleFixture({
        id: "rule_b2",
        scanId: "scan_b",
        findingId: "f_b2",
        format: "otel",
        content: "filter: cmd.exec",
        mitreTechniques: ["T1059"],
        createdAt: "2026-08-01T01:00:00.000Z",
      }),
    );

    // Detection coverage: scan_a has 1 detected + 1 unknown; scan_b has 1
    // not-detected. Real tri-state verdicts (A7), never mock data.
    await deps.store.detectionCoverage.create(
      CLIENT_ID,
      coverageFixture({
        id: "cov_a1",
        scanId: "scan_a",
        findingId: "f_a1",
        detected: true,
        reasoning: "covered by an existing WAF rule",
        createdAt: "2026-07-01T01:00:00.000Z",
      }),
    );
    await deps.store.detectionCoverage.create(
      CLIENT_ID,
      coverageFixture({
        id: "cov_b1",
        scanId: "scan_b",
        findingId: "f_b1",
        detected: false,
        reasoning: "no rule covers this route",
        createdAt: "2026-08-01T01:00:00.000Z",
      }),
    );
    await deps.store.detectionCoverage.create(
      CLIENT_ID,
      coverageFixture({
        id: "cov_b2",
        scanId: "scan_b",
        findingId: "f_b2",
        detected: "unknown",
        createdAt: "2026-08-01T01:00:00.000Z",
      }),
    );
  });

  afterAll(async () => app.close());

  it("requires authentication", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/analytics/blue-team" });
    expect(res.statusCode).toBe(401);
  });

  it("is viewer-visible (read-only, view_reports_and_audit)", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/analytics/blue-team",
      headers: { authorization: `Bearer ${viewer.token}` },
    });
    expect(res.statusCode).toBe(200);
  });

  it("aggregates ATT&CK coverage across scans, merging repeated techniques", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/analytics/blue-team",
      headers: { authorization: `Bearer ${operator.token}` },
    });
    const body = res.json() as {
      summary: {
        scansConsidered: number;
        attackCoverage: { coverage: MitreTechniqueCoverageShape[]; overTime: unknown[] };
      };
    };
    expect(body.summary.scansConsidered).toBe(2); // scan_no_report is excluded

    const byId = new Map(body.summary.attackCoverage.coverage.map((c) => [c.technique.id, c]));
    const t1190 = byId.get("T1190");
    expect(t1190?.findingCount).toBe(2); // 1 (scan_a) + 1 (scan_b), same technique
    expect(t1190?.findingIds.sort()).toEqual(["f_a1", "f_b1"]);
    const t1059 = byId.get("T1059");
    expect(t1059?.findingCount).toBe(1);

    expect(body.summary.attackCoverage.overTime).toEqual([
      expect.objectContaining({ scanId: "scan_a", techniqueCount: 1, cumulativeTechniqueCount: 1 }),
      expect.objectContaining({ scanId: "scan_b", techniqueCount: 2, cumulativeTechniqueCount: 2 }),
    ]);
  });

  it("dedupes the detection-rule inventory by (format, content) across scans", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/analytics/blue-team",
      headers: { authorization: `Bearer ${operator.token}` },
    });
    const body = res.json() as {
      summary: {
        detectionRules: {
          totalGenerated: number;
          rules: Array<{
            rule: { id: string; content: string };
            occurrences: number;
            scanIds: string[];
          }>;
        };
      };
    };
    expect(body.summary.detectionRules.totalGenerated).toBe(3);
    expect(body.summary.detectionRules.rules).toHaveLength(2); // recurring sigma rule collapses to 1

    const recurring = body.summary.detectionRules.rules.find((r) =>
      r.rule.content.includes("recurring"),
    );
    expect(recurring?.occurrences).toBe(2);
    expect(recurring?.scanIds.sort()).toEqual(["scan_a", "scan_b"]);
    // The bundle-export representative is the most-recently-generated occurrence.
    expect(recurring?.rule.id).toBe("rule_b1");
  });

  it("builds a chronological detection-coverage trend from real (A7) verdicts", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/analytics/blue-team",
      headers: { authorization: `Bearer ${operator.token}` },
    });
    const body = res.json() as {
      summary: {
        detectionCoverageTrend: {
          points: Array<{ scanId: string; detected: number; undetected: number; unknown: number }>;
          totals: { detected: number; undetected: number; unknown: number };
        };
      };
    };
    expect(body.summary.detectionCoverageTrend.points).toEqual([
      {
        scanId: "scan_a",
        repo: "acme/blue-team-repo",
        at: "2026-07-01T01:00:00.000Z",
        detected: 1,
        undetected: 0,
        unknown: 0,
      },
      {
        scanId: "scan_b",
        repo: "acme/blue-team-repo",
        at: "2026-08-01T01:00:00.000Z",
        detected: 0,
        undetected: 1,
        unknown: 1,
      },
    ]);
    expect(body.summary.detectionCoverageTrend.totals).toEqual({
      detected: 1,
      undetected: 1,
      unknown: 1,
    });
  });

  it("client isolation: a different client sees none of this client's blue-team data", async () => {
    const otherDeps = createInMemoryDeps({ clock: { now: () => NOW } });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherOperator = await registerAndLogin(
        otherApp,
        "other-bt-op@example.internal",
        "operator",
      );
      const res = await otherApp.inject({
        method: "GET",
        url: "/api/v1/analytics/blue-team",
        headers: { authorization: `Bearer ${otherOperator.token}` },
      });
      const body = res.json() as {
        summary: {
          scansConsidered: number;
          attackCoverage: { coverage: unknown[] };
          detectionRules: { totalGenerated: number };
        };
      };
      expect(body.summary.scansConsidered).toBe(0);
      expect(body.summary.attackCoverage.coverage).toHaveLength(0);
      expect(body.summary.detectionRules.totalGenerated).toBe(0);
    } finally {
      await otherApp.close();
    }
  });
});
