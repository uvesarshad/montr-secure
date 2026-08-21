/**
 * B3/B4 tests. Covers: a live-DAST-backed finding produces a Sigma rule that
 * genuinely reflects its transcript's specific payload/route (not a generic
 * template); a static-proof-only finding still produces a valid, less
 * specific rule; a finding with no resolvable route degrades to a
 * file-scoped rule; the OTel/SIEM variants express equivalent logic to the
 * Sigma rule; the false-alarm-sources narrative is finding-specific (not
 * boilerplate); and `DetectionRule` records are correctly created via the
 * repository with proper `clientId` row-scoping.
 */
import { describe, it, expect, vi } from "vitest";
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  type AppMap,
  type ConfirmedFinding,
} from "@montr/contracts";
import type { StateStore } from "@montr/state-store";
import { generateDetectionRules, persistDetectionRules } from "./generate.js";

const NOW = "2026-08-22T00:00:00.000Z";

function makeLiveSqliFinding(overrides: Partial<ConfirmedFinding> = {}): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: "cf_live_sqli",
    scanId: "scan_1",
    clientId: "client_1",
    title: "SQL Injection in the login handler",
    category: "sql_injection",
    cwe: ["CWE-89"],
    owasp: "A03:2021",
    severity: "critical",
    exposure: "public",
    location: { file: "app/api/login/route.ts", line: 12 },
    impact: "An unauthenticated attacker can bypass authentication via SQL injection.",
    proofType: "live",
    proofArtifact: {
      kind: "live",
      target: "https://staging.example.com",
      transcript: [
        {
          request: { method: "GET", url: "https://staging.example.com/api/login?user=alice" },
          response: { status: 200, bodySnippet: "" },
          note: "baseline",
        },
        {
          request: {
            method: "GET",
            url: "https://staging.example.com/api/login?user=alice%27%20OR%20%271%27%3D%271",
          },
          response: { status: 500, bodySnippet: "syntax error near OR" },
          note: "boolean-based SQLi payload",
        },
      ],
    },
    createdAt: NOW,
    ...overrides,
  });
}

function makeStaticFinding(overrides: Partial<ConfirmedFinding> = {}): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: "cf_static_sqli",
    scanId: "scan_1",
    clientId: "client_1",
    title: "SQL Injection in the search handler",
    category: "sql_injection",
    cwe: ["CWE-89"],
    owasp: "A03:2021",
    severity: "high",
    exposure: "public",
    location: { file: "app/api/search/route.ts", line: 20 },
    impact: "A tainted query parameter reaches a raw SQL query with no sanitizer.",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: "Static proof of reachability: q flows unsanitized into a raw SQL query.",
      dataFlow: [],
      sanitizersBypassed: [],
    },
    createdAt: NOW,
    ...overrides,
  });
}

function makeAppMap(): AppMap {
  return AppMapSchema.parse({
    id: "am_1",
    clientId: "client_1",
    repo: "example/repo",
    branch: "main",
    commitSha: "a".repeat(40),
    createdAt: NOW,
    routes: [
      {
        path: "/api/search",
        method: "GET",
        authState: "public",
        isApiRoute: true,
        handler: { file: "app/api/search/route.ts", line: 5 },
      },
    ],
  });
}

describe("generateDetectionRules — live-DAST provenance", () => {
  const finding = makeLiveSqliFinding();
  const rules = generateDetectionRules(finding, { now: () => NOW });
  const sigma = rules.find((r) => r.format === "sigma")!;
  const otel = rules.find((r) => r.format === "otel")!;
  const siem = rules.find((r) => r.format === "siem_query")!;

  it("produces one rule per format, all row-scoped to the finding's client/scan/finding ids", () => {
    expect(rules).toHaveLength(3);
    for (const r of rules) {
      expect(r.clientId).toBe("client_1");
      expect(r.scanId).toBe("scan_1");
      expect(r.findingId).toBe(finding.id);
      expect(r.provenance).toBe("live");
    }
  });

  it("Sigma rule reflects the ACTUAL exploit signature from the transcript, not a generic template", () => {
    // The exact injected value, recovered by diffing the payload exchange
    // against the baseline — not one of the canonical static-fallback markers.
    expect(sigma.content).toContain("alice' OR '1'='1");
    expect(sigma.content).toContain("cs-uri-stem");
    expect(sigma.content).toContain("/api/login");
    expect(sigma.content).toContain("cs-method");
    expect(sigma.content).toContain("GET");
    expect(sigma.content).toContain("logsource:");
    expect(sigma.content).toContain("detection:");
    expect(sigma.content).toContain("condition:");
    expect(sigma.content).toMatch(/level:\s*critical/);
    // Genuinely YAML-shaped (not JSON, not a bare string).
    expect(sigma.content).toContain("title:");
    expect(sigma.content).toContain("id:");
  });

  it("OTel and SIEM variants express the SAME logic as the Sigma rule (same route + same marker)", () => {
    expect(otel.content).toContain("/api/login");
    expect(otel.content).toContain("alice' OR '1'='1");
    expect(otel.content).toContain("http.request.method");

    expect(siem.content).toContain("/api/login");
    expect(siem.content).toContain("alice' OR '1'='1");
    expect(siem.content).toContain("index=web");
  });

  it("attaches a B4 log-signature narrative that is finding-specific, not boilerplate", () => {
    expect(sigma.logSignature).toBeDefined();
    expect(sigma.logSignature!.pattern).toContain("/api/login");
    expect(sigma.logSignature!.pattern).toContain("alice' OR '1'='1");
    expect(sigma.logSignature!.falseAlarmSources[0]).toContain("reporting");
    expect(sigma.logSignature!.falseAlarmSources[0]).not.toMatch(/^may have false positives\.?$/i);
    // All three formats carry the SAME narrative (one logical rule, three renderings).
    expect(otel.logSignature).toEqual(sigma.logSignature);
    expect(siem.logSignature).toEqual(sigma.logSignature);
  });

  it("defaults mitreTechniques to B2's real category mapping (mitreTechniqueIdsForCategory)", () => {
    // sql_injection -> ["T1190", "T1213"] per packages/contracts/src/mitre.ts.
    expect(sigma.mitreTechniques).toEqual(["T1190", "T1213"]);
    expect(sigma.content).toContain("attack.t1190");
    expect(sigma.content).toContain("attack.t1213");
  });

  it("an explicit mitreTechniques override wins over the B2 category default", () => {
    const withMitre = generateDetectionRules(finding, {
      now: () => NOW,
      mitreTechniques: ["T9999"],
    });
    const s = withMitre.find((r) => r.format === "sigma")!;
    expect(s.mitreTechniques).toEqual(["T9999"]);
    expect(s.content).toContain("attack.t9999");
  });
});

describe("generateDetectionRules — static provenance, route resolved via App Map", () => {
  const finding = makeStaticFinding();
  const appMap = makeAppMap();
  const rules = generateDetectionRules(finding, { now: () => NOW, appMap });
  const sigma = rules.find((r) => r.format === "sigma")!;

  it("resolves the route from the App Map and uses canonical category markers (less precise, still real)", () => {
    expect(sigma.content).toContain("/api/search");
    expect(sigma.content).toContain("cs-method");
    // A canonical static-fallback marker, not an exact captured payload.
    expect(sigma.content).toMatch(/UNION SELECT|OR '1'='1/);
    expect(sigma.provenance).toBe("static");
    expect(sigma.content).toMatch(/level:\s*high/);
  });

  it("is still a schema-valid, real Sigma rule (logsource/detection/condition/level/tags all present)", () => {
    for (const key of ["logsource:", "detection:", "condition:", "level:", "tags:"]) {
      expect(sigma.content).toContain(key);
    }
  });

  it("differs materially from the live-transcript-backed rule for the same category", () => {
    const live = generateDetectionRules(makeLiveSqliFinding(), { now: () => NOW });
    const liveSigma = live.find((r) => r.format === "sigma")!;
    expect(sigma.content).not.toBe(liveSigma.content);
  });
});

describe("generateDetectionRules — no route resolves (file-scoped fallback)", () => {
  const finding = makeStaticFinding({
    id: "cf_static_no_route",
    category: "hardcoded_secret",
    cwe: ["CWE-798"],
    owasp: "A07:2021",
    location: { file: "lib/config/secrets.ts", line: 8 },
    impact: "A hard-coded API key is committed to source control.",
  });
  const rules = generateDetectionRules(finding, { now: () => NOW }); // no appMap at all
  const sigma = rules.find((r) => r.format === "sigma")!;
  const otel = rules.find((r) => r.format === "otel")!;
  const siem = rules.find((r) => r.format === "siem_query")!;

  it("degrades to a real file_event-category Sigma rule keyed on the finding's file", () => {
    expect(sigma.content).toContain("file_event");
    expect(sigma.content).toContain("TargetFilename");
    expect(sigma.content).toContain("lib/config/secrets.ts");
  });

  it("OTel/SIEM variants also degrade to a file-scoped equivalent", () => {
    // OTel's OTTL condition regex-escapes the file path (its "." becomes a
    // JSON-string-escaped "\\." — hence "lib/config/secrets" as the stable,
    // unescaped substring to assert on) and keys on the log.file.path attribute.
    expect(otel.content).toContain("lib/config/secrets");
    expect(otel.content).toContain("log.file.path");
    expect(siem.content).toContain("lib/config/secrets.ts");
    expect(siem.content).toContain("file_integrity");
  });

  it("false-alarm narrative is specific to this (no-route) category, not the route-based boilerplate", () => {
    expect(sigma.logSignature!.falseAlarmSources[0]).toMatch(/CI\/CD|IaC/);
    expect(sigma.logSignature!.fields).toEqual(["TargetFilename"]);
  });
});

describe("false-alarm narrative is category-specific across different categories", () => {
  it("SQLi and SSRF findings on the same route produce different false-alarm text", () => {
    const appMap = makeAppMap();
    const sqli = generateDetectionRules(makeStaticFinding(), { now: () => NOW, appMap });
    const ssrf = generateDetectionRules(
      makeStaticFinding({
        id: "cf_static_ssrf",
        category: "ssrf",
        cwe: ["CWE-918"],
        owasp: "A10:2021",
        impact: "The server fetches an attacker-controlled URL.",
      }),
      { now: () => NOW, appMap },
    );
    const sqliText = sqli.find((r) => r.format === "sigma")!.logSignature!.falseAlarmSources[0];
    const ssrfText = ssrf.find((r) => r.format === "sigma")!.logSignature!.falseAlarmSources[0];
    expect(sqliText).not.toBe(ssrfText);
    expect(ssrfText).toContain("169.254.169.254");
  });

  it("the same category on two different routes produces two different log patterns", () => {
    const appMapA = makeAppMap();
    const appMapB = AppMapSchema.parse({
      ...appMapA,
      routes: [
        {
          path: "/api/orders",
          method: "POST",
          authState: "authenticated",
          isApiRoute: true,
          handler: { file: "app/api/search/route.ts", line: 5 },
        },
      ],
    });
    const a = generateDetectionRules(makeStaticFinding(), { now: () => NOW, appMap: appMapA });
    const b = generateDetectionRules(makeStaticFinding(), { now: () => NOW, appMap: appMapB });
    const patternA = a.find((r) => r.format === "sigma")!.logSignature!.pattern;
    const patternB = b.find((r) => r.format === "sigma")!.logSignature!.pattern;
    expect(patternA).not.toBe(patternB);
    expect(patternA).toContain("/api/search");
    expect(patternB).toContain("/api/orders");
  });
});

describe("persistDetectionRules", () => {
  it("creates one DetectionRule row per format via the repository, row-scoped by clientId", async () => {
    const created: Array<{ clientId: string; rule: unknown }> = [];
    const fakeStore = {
      detectionRules: {
        create: vi.fn(async (clientId: string, rule: unknown) => {
          created.push({ clientId, rule });
          return rule;
        }),
      },
    } as unknown as StateStore;

    const finding = makeLiveSqliFinding();
    const result = await persistDetectionRules(fakeStore, finding, { now: () => NOW });

    expect(result).toHaveLength(3);
    expect(fakeStore.detectionRules.create).toHaveBeenCalledTimes(3);
    expect(created.every((c) => c.clientId === "client_1")).toBe(true);
    expect(new Set(result.map((r) => r.format))).toEqual(new Set(["sigma", "otel", "siem_query"]));
  });
});
