/**
 * B10 — full-report blue-team integration test. Verifies `buildReport`
 * genuinely wires B2 (MITRE ATT&CK), B3/B4 (detection-rule generation), B6
 * (detection-coverage gap analysis), B7 (threat-model report), B8
 * (attack-path graph), B9 (hardening recommendations), and B5 (purple-team
 * verification, landed this same wave) into `Report.blueTeam` — real,
 * finding-specific content, never empty arrays / placeholder text — from a
 * realistic fixture (confirmed findings + App Map with a threat model and
 * telemetry surfaces + precomputed hardening recommendations + purple-team
 * entries). Also verifies `./compliance.exports` (evidence.ts/controls.ts):
 * a finding with VERIFIED detection coverage earns the SOC2/ISO27001
 * detection-monitoring controls as real evidence; one without does not.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  HardeningRecommendationSchema,
  ScanSchema,
  type AppMap,
  type ConfirmedFinding,
  type HardeningRecommendation,
  type PurpleTeamScenarioSummaryEntryShape,
  type Report,
  type Scan,
} from "@montr/contracts";
import {
  buildReport,
  buildEvidencePackage,
  detectionMonitoringControls,
  DETECTION_MONITORING_CONTROL_IDS,
} from "@montr/report";
import {
  mockCostRollup,
  CLIENT_ID,
  REPO_URL,
  BRANCH,
  OPERATOR_ID,
  FIXED_NOW,
} from "@montr/fixtures";

const SCAN_ID = "scan_blueteam_0001";
const NOW = "2026-08-22T00:00:00.000Z";

const scan: Scan = ScanSchema.parse({
  id: SCAN_ID,
  clientId: CLIENT_ID,
  repo: REPO_URL,
  branch: BRANCH,
  mode: "full",
  scope: { mode: "full", includePaths: ["app/"], routeCount: 3, fileCount: 3 },
  status: "completed",
  gateState: "approved",
  operator: OPERATOR_ID,
  createdAt: FIXED_NOW,
});

const appMap: AppMap = AppMapSchema.parse({
  id: "appmap_blueteam_0001",
  clientId: CLIENT_ID,
  scanId: SCAN_ID,
  repo: REPO_URL,
  branch: BRANCH,
  commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334",
  createdAt: FIXED_NOW,
  languages: ["typescript"],
  frameworks: ["nextjs"],
  entrypoints: [],
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
    {
      id: "route_users",
      path: "/api/users",
      method: "GET",
      authState: "public",
      isApiRoute: true,
      handler: { file: "app/api/users/route.ts", line: 5 },
    },
  ],
  dataStores: [],
  ormModels: [],
  thirdPartyCalls: [],
  envSecretSurfaces: [],
  taintSources: [],
  taintSinks: [
    {
      kind: "http_client",
      location: { file: "app/api/webhooks/register/route.ts", line: 12 },
      description: "fetch(targetUrl)",
    },
    {
      kind: "orm_raw_query",
      location: { file: "app/api/users/route.ts", line: 9 },
      description: "prisma.$queryRawUnsafe(`... ${q} ...`)",
    },
  ],
  // B6 — one route with real structured logging (-> verified coverage), one
  // with no logging call at all (-> a real blind-spot "false" verdict), and
  // one never analyzed (-> "unknown", never a guess).
  telemetrySurfaces: {
    hasStructuredLogging: true,
    loggingLibraries: ["pino"],
    observabilityTools: [],
    routes: [
      {
        path: "/api/users",
        method: "GET",
        hasLoggingCall: true,
        loggerKind: "structured",
        sample: "logger.info({ event: 'user_query', q })",
      },
      {
        path: "/api/webhooks/register",
        method: "POST",
        hasLoggingCall: false,
      },
    ],
  },
  // B7 — a real threat model to render into the report's threat-model section.
  threatModel: {
    trustBoundaries: [
      {
        name: "Public unauthenticated routes",
        description: '2 route(s) classified "public": /api/webhooks/register, /api/users.',
        routePaths: ["/api/webhooks/register", "/api/users"],
        stride: [
          {
            category: "spoofing",
            rationale:
              "2 route(s) in this boundary accept requests with no verified caller identity.",
          },
        ],
      },
    ],
    attackSurface: [
      {
        category: "ssrf",
        plausibility: "high",
        rationale: "1 http_client sink(s) detected: app/api/webhooks/register/route.ts:12.",
        stride: ["information_disclosure", "elevation_of_privilege"],
      },
      {
        category: "sql_injection",
        plausibility: "high",
        rationale: "1 raw/SQL query sink(s) detected: app/api/users/route.ts:9.",
        stride: ["tampering", "information_disclosure"],
      },
    ],
    abuseCases: [
      {
        title: "SSRF via webhook target pivots into the internal exports route",
        description:
          "An attacker submits a crafted webhook target URL reaching the fetch() sink at " +
          "app/api/webhooks/register/route.ts:12, then uses the leaked response to reach the " +
          "role-gated exports route.",
        routePaths: ["/api/webhooks/register", "/api/exports/:id"],
        categories: ["ssrf", "sensitive_data_exposure"],
      },
    ],
    scopeHints: { priorityCategories: [], priorityRoutePaths: [], zeroSurfaceCategories: [] },
    generatedByLlm: false,
  },
  stale: false,
  rebuildPolicy: "rebuild_on_stale_commit",
});

function mkFinding(
  overrides: Partial<ConfirmedFinding> &
    Pick<
      ConfirmedFinding,
      "id" | "title" | "category" | "location" | "proofType" | "proofArtifact"
    >,
): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    severity: "high",
    exposure: "public",
    impact: "test finding",
    createdAt: NOW,
    ...overrides,
  });
}

const ssrfFinding = mkFinding({
  id: "cf_ssrf",
  title: "SSRF via unvalidated webhook target URL",
  category: "ssrf",
  location: { file: "app/api/webhooks/register/route.ts", line: 12 },
  exposure: "public",
  severity: "high",
  proofType: "static",
  proofArtifact: { kind: "static", argument: "targetUrl", dataFlow: [], sanitizersBypassed: [] },
});

const exportsFinding = mkFinding({
  id: "cf_exports",
  title: "Internal export bucket read reachable via SSRF pivot",
  category: "sensitive_data_exposure",
  location: { file: "app/api/exports/[id]/route.ts", line: 8 },
  exposure: "authed",
  severity: "critical",
  proofType: "static",
  proofArtifact: { kind: "static", argument: "exportId", dataFlow: [], sanitizersBypassed: [] },
});

const sqliFinding = mkFinding({
  id: "cf_sqli",
  title: "SQL Injection in the users search handler",
  category: "sql_injection",
  location: { file: "app/api/users/route.ts", line: 9 },
  exposure: "public",
  severity: "critical",
  proofType: "live",
  proofArtifact: {
    kind: "live",
    target: "https://staging.example.com",
    transcript: [
      {
        request: { method: "GET", url: "https://staging.example.com/api/users?q=alice" },
        response: { status: 200, bodySnippet: "" },
        note: "baseline",
      },
      {
        request: {
          method: "GET",
          url: "https://staging.example.com/api/users?q=alice%27%20OR%20%271%27%3D%271",
        },
        response: { status: 500, bodySnippet: "syntax error near OR" },
        note: "boolean-based SQLi payload",
      },
    ],
  },
});

const confirmed: ConfirmedFinding[] = [ssrfFinding, exportsFinding, sqliFinding];

const hardeningRecommendations: HardeningRecommendation[] = [
  HardeningRecommendationSchema.parse({
    id: "hard_waf_ssrf_0001",
    category: "waf_rules",
    severity: "high",
    title: "Add a WAF rule blocking outbound-fetch SSRF payloads on /api/webhooks/register",
    gap: "No WAF rule restricts the webhook target URL to an allowlisted egress range.",
    recommendation:
      "Add a WAF/edge rule denying requests where the `targetUrl` parameter resolves to a " +
      "private/link-local IP range (RFC1918, 169.254.0.0/16) before the request reaches the handler.",
    rationale:
      "Confirmed SSRF (cf_ssrf) shows the handler fetches an attacker-controlled URL with no " +
      "egress restriction — a config-level control closes the gap without a code change.",
    evidence: ["app/api/webhooks/register/route.ts:12: fetch(targetUrl)"],
    framework: "nextjs",
    relatedFindingIds: [ssrfFinding.id],
    createdAt: NOW,
  }),
];

const purpleTeamEntries: PurpleTeamScenarioSummaryEntryShape[] = [
  {
    scenarioId: "scn_ssrf_webhook",
    scenarioName: "SSRF via webhook target — internal metadata probe",
    findingId: ssrfFinding.id,
    findingCategory: "ssrf",
    detected: false,
    reason:
      "The generated Sigma rule's condition depends on cs-body|contains, but the scenario runner " +
      "sends no request body — structurally cannot fire against this transcript shape.",
  },
  {
    scenarioId: "scn_sqli_users",
    scenarioName: "SQL injection boolean-based probe against /api/users",
    findingId: sqliFinding.id,
    findingCategory: "sql_injection",
    detectionRuleId: "detr_sigma_placeholder",
    detected: true,
    reason: "The route-scoped Sigma selection matched the scenario's query-string payload.",
  },
];

let report: Report;

beforeAll(async () => {
  const out = await buildReport({
    scan,
    confirmed,
    unconfirmed: [],
    fixes: [],
    costRollup: { ...mockCostRollup, scanId: SCAN_ID },
    autoApply: false,
    appMap,
    hardeningRecommendations,
    purpleTeamEntries,
    generatedAt: NOW,
  });
  report = out.report;
});

describe("@montr/report buildReport — blue-team sections (B10)", () => {
  it("MITRE ATT&CK (B2): maps every confirmed finding to real technique ids", () => {
    expect(report.blueTeam.mitreAttack.findings).toHaveLength(3);
    const sqli = report.blueTeam.mitreAttack.findings.find((f) => f.category === "sql_injection");
    expect(sqli?.techniques.map((t) => t.id)).toEqual(["T1190", "T1213"]);
    const ssrf = report.blueTeam.mitreAttack.findings.find((f) => f.category === "ssrf");
    expect(ssrf?.techniques.map((t) => t.id)).toEqual(["T1190", "T1552.005"]);
    expect(report.blueTeam.mitreAttack.coverage.length).toBeGreaterThan(0);
  });

  it("Detection Engineering (B3/B4): generates real sigma/otel/siem rules + log-signature narrative per finding", () => {
    const rules = report.blueTeam.detectionEngineering.rules;
    // 3 formats x 3 findings.
    expect(rules).toHaveLength(9);
    const sqliSigma = rules.find((r) => r.findingId === sqliFinding.id && r.format === "sigma");
    expect(sqliSigma?.content).toContain("detection:");
    expect(sqliSigma?.content).toContain("logsource:");
    // Live-proof finding: the rule reflects the ACTUAL captured payload, not a
    // generic template.
    expect(sqliSigma?.content).toContain("/api/users");
    expect(sqliSigma?.content).toContain("alice' OR '1'='1");
    expect(sqliSigma?.logSignature?.pattern.length).toBeGreaterThan(0);
    expect(sqliSigma?.logSignature?.falseAlarmSources.length).toBeGreaterThan(0);
    expect(sqliSigma?.mitreTechniques).toEqual(["T1190", "T1213"]);

    const ssrfOtel = rules.find((r) => r.findingId === ssrfFinding.id && r.format === "otel");
    expect(ssrfOtel?.content.length).toBeGreaterThan(0);
    const exportsSiem = rules.find(
      (r) => r.findingId === exportsFinding.id && r.format === "siem_query",
    );
    expect(exportsSiem?.content.length).toBeGreaterThan(0);
  });

  it("Detection Coverage (B6): surfaces a real tri-state verdict per finding, grounded in telemetry", () => {
    const coverage = report.blueTeam.detectionEngineering.coverage;
    expect(coverage).toHaveLength(3);

    const sqliCoverage = coverage.find((c) => c.findingId === sqliFinding.id)!;
    expect(sqliCoverage.detected).toBe(true); // structured logging + a rule exists
    expect(sqliCoverage.reasoning).toContain("structured logging");
    expect(sqliCoverage.detectionRuleId).toBeDefined();

    const ssrfCoverage = coverage.find((c) => c.findingId === ssrfFinding.id)!;
    expect(ssrfCoverage.detected).toBe(false); // handler makes NO logging call — real blind spot
    expect(ssrfCoverage.reasoning).toContain("NO logging call");

    const exportsCoverage = coverage.find((c) => c.findingId === exportsFinding.id)!;
    expect(exportsCoverage.detected).toBe("unknown"); // route never analyzed for telemetry
  });

  it("Threat Model (B7): renders the App Map's real threat model, not a placeholder", () => {
    const tm = report.blueTeam.threatModel;
    expect(tm.present).toBe(true);
    expect(tm.summary).toContain("1 identified trust boundar");
    expect(tm.markdown).toContain("# Threat Model");
    expect(tm.markdown).toContain("SSRF via webhook target pivots into the internal exports route");
    expect(tm.raw?.attackSurface.map((a) => a.category)).toEqual(
      expect.arrayContaining(["ssrf", "sql_injection"]),
    );
  });

  it("Attack Paths (B8): chains the SSRF into the role-gated exports route with a grounded narrative", () => {
    const paths = report.blueTeam.attackPaths;
    expect(paths.length).toBeGreaterThan(0);
    const chain = paths[0]!;
    expect(chain.steps.map((s) => s.findingId)).toContain(ssrfFinding.id);
    expect(chain.steps.map((s) => s.findingId)).toContain(exportsFinding.id);
    expect(chain.narrative.length).toBeGreaterThan(0);
    expect(chain.feasibilityScore).toBeGreaterThan(0);
    // Ranked by feasibility (then severity) — descending.
    for (let i = 1; i < paths.length; i++) {
      expect(paths[i - 1]!.feasibilityScore).toBeGreaterThanOrEqual(paths[i]!.feasibilityScore);
    }
  });

  it("Hardening Recommendations (B9): advisory-only, carries the real precomputed recommendation", () => {
    const hardening = report.blueTeam.hardening;
    expect(hardening.advisoryOnly).toBe(true);
    expect(hardening.recommendations).toHaveLength(1);
    expect(hardening.recommendations[0]!.relatedFindingIds).toContain(ssrfFinding.id);
    expect(hardening.recommendations[0]!.recommendation).toContain("private/link-local IP range");
  });

  it("Purple Team (B5): detected-vs-undetected summary reflects the real precomputed entries", () => {
    const pt = report.blueTeam.purpleTeam;
    expect(pt.totalScenarios).toBe(2);
    expect(pt.detectedCount).toBe(1);
    expect(pt.undetectedCount).toBe(1);
    expect(pt.entries.map((e) => e.scenarioId).sort()).toEqual(
      ["scn_sqli_users", "scn_ssrf_webhook"].sort(),
    );
    const undetected = pt.entries.find((e) => !e.detected)!;
    expect(undetected.reason).toContain("cs-body|contains");
  });

  it("defaults every blue-team section to an honest empty state when appMap/extra inputs are omitted", async () => {
    const out = await buildReport({
      scan,
      confirmed,
      unconfirmed: [],
      fixes: [],
      costRollup: { ...mockCostRollup, scanId: SCAN_ID },
      autoApply: false,
      generatedAt: NOW,
    });
    expect(out.report.blueTeam.detectionEngineering.coverage).toEqual([]);
    expect(out.report.blueTeam.attackPaths).toEqual([]);
    expect(out.report.blueTeam.threatModel.present).toBe(false);
    expect(out.report.blueTeam.hardening.recommendations).toEqual([]);
    expect(out.report.blueTeam.purpleTeam.totalScenarios).toBe(0);
    // MITRE + rule generation are pure/appMap-independent — still real.
    expect(out.report.blueTeam.mitreAttack.findings).toHaveLength(3);
    expect(out.report.blueTeam.detectionEngineering.rules).toHaveLength(9);
  });
});

describe("@montr/report compliance exports — detection coverage as evidence (B10)", () => {
  it("SOC2: a finding with VERIFIED coverage earns CC7.2/CC7.3 as real evidence", async () => {
    const pkg = await buildEvidencePackage(report, "soc2");
    const sqliRecord = pkg.evidence.find((e) => e.findingId === sqliFinding.id)!;
    expect(sqliRecord.detectionCoverageVerified).toBe(true);
    expect(sqliRecord.detectionRuleIds?.length).toBeGreaterThan(0);
    const controlIds = sqliRecord.controls.map((c) => c.id);
    expect(controlIds).toEqual(expect.arrayContaining(DETECTION_MONITORING_CONTROL_IDS.soc2));

    // An unverified finding (blind spot) does NOT get the monitoring controls
    // as evidence — only the red-side category mapping.
    const ssrfRecord = pkg.evidence.find((e) => e.findingId === ssrfFinding.id)!;
    expect(ssrfRecord.detectionCoverageVerified).toBe(false);
    expect(ssrfRecord.controls.map((c) => c.id)).not.toEqual(
      expect.arrayContaining(DETECTION_MONITORING_CONTROL_IDS.soc2),
    );
  });

  it("ISO27001: a finding with VERIFIED coverage earns A.8.15/A.8.16 as real evidence", async () => {
    const pkg = await buildEvidencePackage(report, "iso27001");
    const sqliRecord = pkg.evidence.find((e) => e.findingId === sqliFinding.id)!;
    const controlIds = sqliRecord.controls.map((c) => c.id);
    expect(controlIds).toEqual(expect.arrayContaining(DETECTION_MONITORING_CONTROL_IDS.iso27001));
  });

  it("detectionMonitoringControls resolves real, catalog-backed descriptors", () => {
    const controls = detectionMonitoringControls("soc2");
    expect(controls.map((c) => c.id)).toEqual(["CC7.2", "CC7.3"]);
    expect(controls.every((c) => c.title.length > 0)).toBe(true);
  });
});
