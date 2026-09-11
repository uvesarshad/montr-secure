import { describe, it, expect, vi } from "vitest";
import type {
  DetectionCoverage,
  DetectionVerificationResult,
  RedTeamScenario,
} from "@montr/contracts";
import {
  DastTargetNotAllowlistedError,
  HumanApprovalRequiredError,
  KillSwitchActivatedError,
} from "@montr/contracts";
import { getHardenedDefaults, type MontrConfig } from "@montr/config";
import {
  parseSigmaRule,
  evaluateSigmaRule,
  evaluateDetectionRuleAgainstScenario,
  runPurpleTeamScenario,
  findOrCreateDetectionCoverage,
  verifyScenarioDetection,
  summarizePurpleTeamRun,
  type LiveHttpTransport,
} from "@montr/confirm";
import { generateDetectionRules } from "@montr/report";
import { mockAppMap, mockConfirmedFindings, CLIENT_ID, FIXED_NOW } from "@montr/fixtures";

/**
 * B5 — purple-team verification loop. Runs a red-team scenario through the
 * SAME gated engine every other scenario caller uses, then checks whether a
 * real, B3-generated Sigma rule structurally covers the resulting transcript.
 */

const STAGING = "https://staging.acme.test";
const SQLI_FINDING = mockConfirmedFindings.find((f) => f.category === "sql_injection")!;

function configWith(overrides: Partial<MontrConfig["dast"]> = {}): MontrConfig {
  const base = getHardenedDefaults();
  return { ...base, dast: { ...base.dast, enabled: true, allowlist: [STAGING], ...overrides } };
}

function scenarioOf(overrides: Partial<RedTeamScenario> = {}): RedTeamScenario {
  return {
    id: "scn_sqli_1",
    clientId: CLIENT_ID,
    name: "SQLi login probe",
    category: "injection",
    steps: [{ order: 0, action: "GET users with SQLi payload", method: "GET", path: "/api/users" }],
    targetAllowlistRef: STAGING,
    version: 1,
    enabled: true,
    createdBy: "user_1",
    createdAt: FIXED_NOW,
    ...overrides,
  };
}

const passEgress = { assert: () => undefined, isAllowed: () => true };

function fakeEngine(status: (url: string) => number = () => 200) {
  const send = vi.fn(async (req: { url: string }) => ({
    status: status(req.url),
    headers: {},
    body: "ok",
  }));
  return { transport: { send } as LiveHttpTransport, send };
}

/** Real B3 sigma rule generated from a real fixture finding + AppMap. */
function realSqlInjectionRules() {
  return generateDetectionRules(SQLI_FINDING, {
    appMap: mockAppMap,
    now: () => FIXED_NOW,
  }).filter((r) => r.format === "sigma");
}

/* ============================ parseSigmaRule ============================ */

describe("parseSigmaRule — subset parser for B3's exact Sigma output shapes", () => {
  it("parses a route-based rule with payload markers (selection_route and 1 of selection_payload_*)", () => {
    const [rule] = realSqlInjectionRules();
    const parsed = parseSigmaRule(rule!.content);
    expect(parsed.kind).toBe("route");
    expect(parsed.pathStartsWith).toBe("/api/users");
    expect(parsed.method).toBe("GET");
    expect(parsed.queryContains).toContain("' OR '1'='1");
    expect(parsed.bodyContains).toContain("' OR '1'='1");
    expect(parsed.condition).toBe("selection_route and 1 of selection_payload_*");
  });

  it("parses a file-fallback rule (no App Map route resolves)", () => {
    const rules = generateDetectionRules(SQLI_FINDING, { now: () => FIXED_NOW }); // no appMap
    const sigma = rules.find((r) => r.format === "sigma")!;
    const parsed = parseSigmaRule(sigma.content);
    expect(parsed.kind).toBe("file-fallback");
    expect(parsed.fileTargetContains).toBe(SQLI_FINDING.location.file);
    expect(parsed.condition).toBe("selection");
  });
});

/* ======================== evaluateSigmaRule (unit, structural) ======================== */

describe("evaluateSigmaRule — structural evaluation, not a coin flip", () => {
  const [rule] = realSqlInjectionRules();
  const parsed = parseSigmaRule(rule!.content);

  it("fires when the request path/method/payload marker genuinely match", () => {
    const outcome = evaluateSigmaRule(parsed, {
      method: "GET",
      url: "https://staging.acme.test/api/users?id=1' OR '1'='1",
    });
    expect(outcome.fired).toBe(true);
    expect(outcome.matchedFields).toEqual(
      expect.arrayContaining(["cs-uri-stem", "cs-method", "cs-uri-query"]),
    );
    expect(outcome.reason).toMatch(/OR '1'='1/);
  });

  it("does NOT fire on a wrong path — specific, non-generic reason", () => {
    const outcome = evaluateSigmaRule(parsed, {
      method: "GET",
      url: "https://staging.acme.test/api/orders?id=1' OR '1'='1",
    });
    expect(outcome.fired).toBe(false);
    expect(outcome.reason).toMatch(/path starting with "\/api\/users"/);
    expect(outcome.reason).toMatch(/\/api\/orders/);
  });

  it("does NOT fire on the right path/method but a payload with no known marker — explains why", () => {
    const outcome = evaluateSigmaRule(parsed, {
      method: "GET",
      url: "https://staging.acme.test/api/users?id=1",
    });
    expect(outcome.fired).toBe(false);
    expect(outcome.matchedFields).toEqual(["cs-uri-stem", "cs-method"]);
    expect(outcome.reason).toMatch(/none of this rule's payload markers/);
  });

  it("flags a per-request body-marker gap: this exchange's RedTeamStep defined no body", () => {
    const outcome = evaluateSigmaRule(parsed, {
      method: "GET",
      url: "https://staging.acme.test/api/users?id=1",
      // no bodySnippet — mirrors a RedTeamStep with no `body` field set (runScenario
      // sends step.body when a step defines one, as of A10 — see scenarios.ts)
    });
    expect(outcome.reason).toMatch(/RedTeamStep\.body was unset for this step/);
  });

  it("tolerates dynamic route segments ([id]/:id) the same way scenarios.ts's concretePath does", () => {
    const dynamicRule = parseSigmaRule(
      [
        "logsource:",
        "    category: webserver",
        "detection:",
        "    selection_route:",
        '        cs-uri-stem|startswith: "/api/orders/[id]"',
        "    condition: selection_route",
      ].join("\n"),
    );
    const outcome = evaluateSigmaRule(dynamicRule, {
      method: "GET",
      url: "https://staging.acme.test/api/orders/42",
    });
    expect(outcome.fired).toBe(true);
  });
});

/* ==================== evaluateDetectionRuleAgainstScenario ==================== */

describe("evaluateDetectionRuleAgainstScenario", () => {
  const [rule] = realSqlInjectionRules();

  it("fires true when ANY transcript exchange matches", () => {
    const outcome = evaluateDetectionRuleAgainstScenario(rule!, {
      probed: true,
      transcript: [
        {
          request: { method: "GET", url: "https://staging.acme.test/api/users?id=1" },
          response: { status: 200 },
        },
        {
          request: { method: "GET", url: "https://staging.acme.test/api/users?id=1' OR '1'='1" },
          response: { status: 500 },
        },
      ],
    });
    expect(outcome.fired).toBe(true);
    expect(outcome.matchedExchange?.request.url).toContain("OR '1'='1");
  });

  it("fires false with the most informative near-miss when nothing matches", () => {
    const outcome = evaluateDetectionRuleAgainstScenario(rule!, {
      probed: true,
      transcript: [
        {
          request: { method: "GET", url: "https://staging.acme.test/other" },
          response: { status: 404 },
        },
      ],
    });
    expect(outcome.fired).toBe(false);
    expect(outcome.reason).toMatch(/path starting with/);
  });

  it("handles an empty transcript (gate-only mode) without throwing", () => {
    const outcome = evaluateDetectionRuleAgainstScenario(rule!, { probed: false, transcript: [] });
    expect(outcome.fired).toBe(false);
    expect(outcome.reason).toMatch(/gate-only\/authorize mode/);
  });
});

/* ============================ runPurpleTeamScenario (integration) ============================ */

describe("runPurpleTeamScenario — real gated scenario run + real Sigma evaluation", () => {
  it("detected: true when the scenario's actual request matches the real generated rule", async () => {
    const { transport } = fakeEngine();
    const rules = realSqlInjectionRules();
    const result = await runPurpleTeamScenario(
      {
        scenario: scenarioOf({
          steps: [
            { order: 0, action: "baseline", method: "GET", path: "/api/users?id=1" },
            { order: 1, action: "sqli payload", method: "GET", path: "/api/users?id=1' OR '1'='1" },
          ],
        }),
        finding: SQLI_FINDING,
        config: configWith(),
        allowLive: true,
      },
      { egressGuard: passEgress, transport, detectionRules: rules, now: () => FIXED_NOW },
    );
    expect(result.overall.fired).toBe(true);
    expect(result.overall.scenarioId).toBe("scn_sqli_1");
    expect(result.overall.evidence).toMatch(/OR '1'='1/);
  });

  it("A10: detected: true when the confirming marker lives ONLY in the step's request body", async () => {
    const { transport } = fakeEngine();
    const rules = realSqlInjectionRules();
    const result = await runPurpleTeamScenario(
      {
        scenario: scenarioOf({
          steps: [
            {
              order: 0,
              action: "sqli payload in the POST body, no query string",
              method: "GET",
              path: "/api/users",
              body: "id=1' OR '1'='1",
            },
          ],
        }),
        finding: SQLI_FINDING,
        config: configWith(),
        allowLive: true,
      },
      { egressGuard: passEgress, transport, detectionRules: rules, now: () => FIXED_NOW },
    );
    expect(result.overall.fired).toBe(true);
    expect(result.overall.evidence).toMatch(/request body/);
    expect(result.ruleEvaluations[0]?.matchedFields).toContain("cs-body");
  });

  it("detected: false with a concrete, non-generic reason when the rule genuinely doesn't cover the request shape", async () => {
    const { transport } = fakeEngine();
    const rules = realSqlInjectionRules();
    const result = await runPurpleTeamScenario(
      {
        scenario: scenarioOf({
          id: "scn_wrong_path",
          steps: [
            { order: 0, action: "hits an unrelated route", method: "GET", path: "/api/health" },
          ],
        }),
        finding: SQLI_FINDING,
        config: configWith(),
        allowLive: true,
      },
      { egressGuard: passEgress, transport, detectionRules: rules, now: () => FIXED_NOW },
    );
    expect(result.overall.fired).toBe(false);
    expect(result.overall.evidence).toMatch(/\/api\/users/); // names the expected path
  });

  it("reports 'no rule exists yet' when no detection rules are supplied", async () => {
    const { transport } = fakeEngine();
    const result = await runPurpleTeamScenario(
      { scenario: scenarioOf(), finding: SQLI_FINDING, config: configWith(), allowLive: true },
      { egressGuard: passEgress, transport, now: () => FIXED_NOW }, // no detectionRules
    );
    expect(result.overall.fired).toBe(false);
    expect(result.overall.evidence).toMatch(/no sigma detection rule exists yet/);
  });
});

/* ============================ B1 persistence wiring ============================ */

class FakeDetectionCoverageRepo {
  rows = new Map<string, DetectionCoverage>();

  async create(clientId: string, c: DetectionCoverage): Promise<DetectionCoverage> {
    const row = { ...c, clientId };
    this.rows.set(row.id, row);
    return row;
  }
  async get(clientId: string, id: string): Promise<DetectionCoverage | null> {
    const row = this.rows.get(id);
    return row && row.clientId === clientId ? row : null;
  }
  async list(clientId: string): Promise<DetectionCoverage[]> {
    return [...this.rows.values()].filter((r) => r.clientId === clientId);
  }
  async listByFinding(clientId: string, findingId: string): Promise<DetectionCoverage[]> {
    return [...this.rows.values()]
      .filter((r) => r.clientId === clientId && r.findingId === findingId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  async updateVerification(
    clientId: string,
    id: string,
    verification: DetectionVerificationResult,
  ): Promise<DetectionCoverage> {
    const row = this.rows.get(id);
    if (!row || row.clientId !== clientId)
      throw new Error(`detectionCoverage ${id} not found for client`);
    const updated = { ...row, verification };
    this.rows.set(id, updated);
    return updated;
  }
}

function fakeStore() {
  return {
    detectionCoverage: new FakeDetectionCoverageRepo(),
  } as unknown as import("@montr/state-store").StateStore;
}

describe("findOrCreateDetectionCoverage — read-only consumption of the B1 repository", () => {
  it("creates a fresh 'unknown' row when none exists yet", async () => {
    const store = fakeStore();
    const row = await findOrCreateDetectionCoverage(store, CLIENT_ID, SQLI_FINDING, {
      now: () => FIXED_NOW,
    });
    expect(row.detected).toBe("unknown");
    expect(row.findingId).toBe(SQLI_FINDING.id);
  });

  it("reuses the most recent existing row instead of creating a duplicate", async () => {
    const store = fakeStore();
    const first = await findOrCreateDetectionCoverage(store, CLIENT_ID, SQLI_FINDING, {
      now: () => FIXED_NOW,
    });
    const second = await findOrCreateDetectionCoverage(store, CLIENT_ID, SQLI_FINDING, {
      now: () => FIXED_NOW,
    });
    expect(second.id).toBe(first.id);
    expect((await store.detectionCoverage.list(CLIENT_ID)).length).toBe(1);
  });
});

describe("verifyScenarioDetection — full loop persists via the real updateVerification signature", () => {
  it("runs the scenario, evaluates the rule, and persists DetectionCoverage.verification", async () => {
    const { transport } = fakeEngine();
    const store = fakeStore();
    const rules = realSqlInjectionRules();

    const { scenarioResult, coverage } = await verifyScenarioDetection(
      store,
      CLIENT_ID,
      {
        scenario: scenarioOf({
          steps: [{ order: 0, action: "sqli", method: "GET", path: "/api/users?id=1' OR '1'='1" }],
        }),
        finding: SQLI_FINDING,
        config: configWith(),
        allowLive: true,
      },
      { egressGuard: passEgress, transport, detectionRules: rules, now: () => FIXED_NOW },
    );

    expect(scenarioResult.overall.fired).toBe(true);
    expect(coverage.verification).toEqual(scenarioResult.overall);
    expect(coverage.verification?.scenarioId).toBe("scn_sqli_1");
    expect(coverage.detectionRuleId).toBe(rules[0]!.id);

    // Persisted, not just returned — a fresh read confirms it landed on the row.
    const reread = await store.detectionCoverage.get(CLIENT_ID, coverage.id);
    expect(reread?.verification?.fired).toBe(true);
  });
});

/* ============================ summarizePurpleTeamRun ============================ */

describe("summarizePurpleTeamRun — standalone report structure, not wired into report-builder", () => {
  it("summarizes detected/undetected counts and per-scenario reasons", async () => {
    const { transport } = fakeEngine();
    const rules = realSqlInjectionRules();
    const hit = await runPurpleTeamScenario(
      {
        scenario: scenarioOf({
          steps: [{ order: 0, action: "sqli", method: "GET", path: "/api/users?id=1' OR '1'='1" }],
        }),
        finding: SQLI_FINDING,
        config: configWith(),
        allowLive: true,
      },
      { egressGuard: passEgress, transport, detectionRules: rules, now: () => FIXED_NOW },
    );
    const miss = await runPurpleTeamScenario(
      {
        scenario: scenarioOf({
          id: "scn_miss",
          steps: [{ order: 0, action: "x", method: "GET", path: "/api/health" }],
        }),
        finding: SQLI_FINDING,
        config: configWith(),
        allowLive: true,
      },
      { egressGuard: passEgress, transport, detectionRules: rules, now: () => FIXED_NOW },
    );

    const summary = summarizePurpleTeamRun("scan_fixture_0001", [
      { scenario: scenarioOf(), finding: SQLI_FINDING, result: hit },
      { scenario: scenarioOf({ id: "scn_miss" }), finding: SQLI_FINDING, result: miss },
    ]);

    expect(summary.totalScenarios).toBe(2);
    expect(summary.detectedCount).toBe(1);
    expect(summary.undetectedCount).toBe(1);
    expect(summary.entries.find((e) => e.scenarioId === "scn_sqli_1")?.detected).toBe(true);
    expect(summary.entries.find((e) => e.scenarioId === "scn_miss")?.detected).toBe(false);
    expect(summary.entries.find((e) => e.scenarioId === "scn_miss")?.reason).toMatch(
      /\/api\/users/,
    );
  });
});

/* ============================ ⛔ SAFETY-GATING REGRESSION ============================ */

describe("⛔ runPurpleTeamScenario is subject to the EXACT SAME gate as every other scenario caller", () => {
  it("refuses a non-allowlisted target — the transport is NEVER called, no verification produced", async () => {
    const { transport, send } = fakeEngine();
    await expect(
      runPurpleTeamScenario(
        {
          scenario: scenarioOf({ targetAllowlistRef: "https://evil.attacker.test" }),
          finding: SQLI_FINDING,
          config: configWith(),
          allowLive: true,
        },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError);
    expect(send).not.toHaveBeenCalled();
  });

  it("refuses a production-looking target even if allowlisted — transport never called", async () => {
    const { transport, send } = fakeEngine();
    const prod = "https://www.acme.com";
    await expect(
      runPurpleTeamScenario(
        {
          scenario: scenarioOf({ targetAllowlistRef: prod }),
          finding: SQLI_FINDING,
          config: configWith({ allowlist: [STAGING, prod] }),
          allowLive: true,
        },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError);
    expect(send).not.toHaveBeenCalled();
  });

  it("refuses when DAST is disabled by policy — transport never called", async () => {
    const { transport, send } = fakeEngine();
    await expect(
      runPurpleTeamScenario(
        {
          scenario: scenarioOf(),
          finding: SQLI_FINDING,
          config: configWith({ enabled: false }),
          allowLive: true,
        },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError);
    expect(send).not.toHaveBeenCalled();
  });

  it("refuses without approver authorization (allowLive=false) — transport never called", async () => {
    const { transport, send } = fakeEngine();
    await expect(
      runPurpleTeamScenario(
        { scenario: scenarioOf(), finding: SQLI_FINDING, config: configWith(), allowLive: false },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(HumanApprovalRequiredError);
    expect(send).not.toHaveBeenCalled();
  });

  it("halts instantly on an already-fired kill switch — transport never called", async () => {
    const { transport, send } = fakeEngine();
    const controller = new AbortController();
    controller.abort(new KillSwitchActivatedError("halt"));
    await expect(
      runPurpleTeamScenario(
        { scenario: scenarioOf(), finding: SQLI_FINDING, config: configWith(), allowLive: true },
        { egressGuard: passEgress, transport, signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(KillSwitchActivatedError);
    expect(send).not.toHaveBeenCalled();
  });

  it("verifyScenarioDetection propagates the same gate failure and never touches the store", async () => {
    const { transport } = fakeEngine();
    const store = fakeStore();
    await expect(
      verifyScenarioDetection(
        store,
        CLIENT_ID,
        {
          scenario: scenarioOf({ targetAllowlistRef: "https://evil.attacker.test" }),
          finding: SQLI_FINDING,
          config: configWith(),
          allowLive: true,
        },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError);
    expect(await store.detectionCoverage.list(CLIENT_ID)).toHaveLength(0);
  });
});
