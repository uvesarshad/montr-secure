/**
 * ⛔ THE E2E SCAN (build-plan §9.2, PRD §19 Definition of Done).
 *
 * A full end-to-end security scan of the fixtures' intentionally-VULNERABLE
 * Next.js/Prisma repo, driven through the orchestrator FSM + the apps/worker
 * IN-PROCESS driver (no Redis/BullMQ, no Postgres) with the FAKE LLM adapter and
 * an in-memory store. It exercises the REAL layer functions:
 *
 *     map (L0)  →  discovery (L1)  →  correlation (L2)  →  static confirmation
 *     (L3)      →  fix generation (L4)  →  report (L5)
 *
 * Layer 0 builds a REAL App Map from the checked-out repo. Discovery runs the
 * REAL scanners when semgrep+gitleaks are installed; otherwise it falls back to
 * the fixtures' seeded candidate pile so L2→L5 still run on real data (the mode
 * that ran is asserted + printed). Everything else (L2–L5) is the real pipeline.
 *
 * This test is the machine-checkable form of the DoD; `scripts/e2e-scan.mjs`
 * (`pnpm e2e`) runs the same thing and prints the money-shot report.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  CLIENT_ID,
  FIXED_NOW,
  SCAN_ID,
  createFakeLlmGateway,
  groundTruthManifest,
  mockLayer1Output,
} from "@montr/fixtures";
import {
  CandidateFindingSchema,
  ConfirmedFindingSchema,
  ReportSchema,
  complianceForCategory,
  type CandidateFinding,
  type Category,
  type ConfirmedFinding,
  type Layer2Output,
  type Layer3Output,
  type Layer4Output,
  type Layer5Output,
  type LLMGateway,
  type LLMRequest,
  type Report,
  type Scan,
} from "@montr/contracts";
import type { AuditEventInput } from "@montr/contracts";
import type { LayerRunners } from "@montr/orchestrator";
import { gradeScanResults } from "@montr/qa";
import {
  ALWAYS_HUMAN_REQUIRED_CATEGORIES,
  classifyConfirmedFindingRisk,
  createMapSourceReader,
  generateFixes,
} from "@montr/fix";
import { assertConfirmedOnlyHeadline, renderHeadline } from "@montr/report";
import { scrubValue } from "@montr/telemetry";
import { runScanInProcess } from "./pipeline.js";
import { createLayerRunners } from "./runners.js";
import { clone, hardenedConfig, instrument, makeInMemoryStore, silentLogger } from "./testkit.js";

/* ------------------------------------------------------------------------- *
 * Setup: real repo, tool detection, recording gateway, seeded fallback.
 * ------------------------------------------------------------------------- */

/** Absolute path to the checked-out vulnerable repo (a LOCAL path ⇒ real L0/L4). */
const VULN_REPO = fileURLToPath(
  new URL("../../../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);

type DiscoveryMode = "live-scanners" | "seeded-candidates";

/** Is a scanner binary on PATH? (`which` is fine on the CI/dev darwin+linux hosts). */
function onPath(bin: string): boolean {
  try {
    execFileSync("which", [bin], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Live mode requires BOTH real scanners so the candidate pile is complete;
// otherwise fall back to the seeded pile (still real vulns from this repo).
const SEMGREP = onPath("semgrep");
const GITLEAKS = onPath("gitleaks");
const DISCOVERY_MODE: DiscoveryMode = SEMGREP && GITLEAKS ? "live-scanners" : "seeded-candidates";

/**
 * ⛔ A recording wrapper over the ONLY egress path (the fake, in-process gateway).
 * Captures every request so the test can prove code went to the gateway and
 * NOWHERE else, and that the audit trail derived from these calls is metadata-only.
 */
function recordingGateway(): { gateway: LLMGateway; requests: LLMRequest[] } {
  const inner = createFakeLlmGateway();
  const requests: LLMRequest[] = [];
  const gateway: LLMGateway = {
    complete: (req) => {
      requests.push(req);
      return inner.complete(req);
    },
    stream: (req) => {
      requests.push(req);
      return inner.stream(req);
    },
    listModels: () => inner.listModels(),
    resolveModel: (t) => inner.resolveModel(t),
    estimateTokens: (req) => inner.estimateTokens?.(req) ?? Promise.resolve(0),
  };
  return { gateway, requests };
}

/** Real L0 + L2–L5; L1 = real scanners (live) or the seeded fixtures pile (fallback). */
function buildRunners(gateway: LLMGateway): LayerRunners {
  const real = createLayerRunners({ gateway });
  if (DISCOVERY_MODE === "live-scanners") return real;
  // ⛔ Fallback: seed L1 with the fixtures' candidate pile (real vulns from this
  // repo) so the L2→L5 chain runs on real data even without scanner binaries.
  return { ...real, layer1: () => Promise.resolve(clone(mockLayer1Output)) };
}

function scanInput() {
  return {
    clientId: CLIENT_ID,
    repo: VULN_REPO, // LOCAL path ⇒ Layer 0 builds a REAL map; Layer 4 reads real source.
    branch: "main",
    mode: "full" as const,
    scope: { mode: "full" as const, includePaths: [] as string[] },
    operator: "user_operator_0001",
  };
}

/* ------------------------------------------------------------------------- *
 * Run the scan ONCE; every assertion inspects the shared result.
 * ------------------------------------------------------------------------- */

interface ScanRun {
  scan: Scan;
  report: Report;
  layer2: Layer2Output;
  layer3: Layer3Output;
  layer4: Layer4Output;
  layer5: Layer5Output;
  audit: AuditEventInput[];
  llmRequests: LLMRequest[];
  layerCalls: Record<string, number>;
}

let run: ScanRun;

beforeAll(async () => {
  const { store, audit } = makeInMemoryStore();
  const { gateway, requests } = recordingGateway();
  const { runners, calls, outputs } = instrument(buildRunners(gateway));

  // ⛔ Default hardened config ⇒ the pre-scan cost gate is REQUIRED. The driver
  // approves it (a recorded cost decision) so the estimate is surfaced pre-scan
  // before any Layer-1 work runs (PRD §19).
  const scan = await runScanInProcess(
    {
      config: hardenedConfig(),
      store,
      gateway,
      logger: silentLogger,
      layerRunners: runners,
      ids: () => SCAN_ID,
      sleep: () => Promise.resolve(),
    },
    scanInput(),
    { approveEstimate: "user_approver_0001", timeoutMs: 60_000 },
  );

  const layer5 = outputs.layer5 as Layer5Output;
  run = {
    scan,
    report: layer5.report,
    layer2: outputs.layer2 as Layer2Output,
    layer3: outputs.layer3 as Layer3Output,
    layer4: outputs.layer4 as Layer4Output,
    layer5,
    audit,
    llmRequests: requests,
    layerCalls: calls,
  };
}, 60_000);

afterAll(() => {
  if (!process.env.E2E_PRINT || !run) return;
  const r = run.report;
  const lines = [
    "",
    "════════════════════════════════════════════════════════════════════",
    "  MONTR SECURE — END-TO-END SCAN (fixtures/vulnerable-nextjs)",
    "════════════════════════════════════════════════════════════════════",
    `  repo:            ${VULN_REPO}`,
    `  discovery mode:  ${DISCOVERY_MODE}${DISCOVERY_MODE === "seeded-candidates" ? " (semgrep/gitleaks not installed)" : ""}`,
    `  status:          ${run.scan.status}  (gate: ${run.scan.gateState})`,
    "  ── HEADLINE (confirmed + prioritized; never raw counts) ──",
    `  ${renderHeadline(r)}`,
    "  ── CONFIRMED FINDINGS ──",
    ...r.confirmedFindings.map(
      (rf) =>
        `   • [${rf.finding.severity}] ${rf.finding.title}\n` +
        `       CWE ${rf.compliance.cwe.join(",")} · OWASP ${rf.compliance.owasp} · proof=${rf.finding.proofType}` +
        ` · fix=${rf.fix?.riskClass ?? "none"} (proof-of-fix test: ${rf.fix?.proofOfFixTest.failsPrePatch ? "fails-pre" : "?"}/${rf.fix?.proofOfFixTest.passesPostPatch ? "passes-post" : "?"})`,
    ),
    `  ── APPENDIX (kept, not deleted): ${r.unconfirmedAppendix.length} unconfirmed ──`,
    `  tools consolidated: ${r.executiveSummary.toolsConsolidated.join(", ") || "(none)"}`,
    `  cost estimate (pre-scan): $${run.scan.costEstimate?.projectedUsd?.toFixed(4)} / ${run.scan.costEstimate?.projectedTotalTokens} tok`,
    `  cost actual:              $${run.scan.costActual?.actualUsd?.toFixed(4)} / ${run.scan.costActual?.usage.totalTokens} tok`,
    `  audit events: ${run.audit.length} · LLM calls via gateway: ${run.llmRequests.length}`,
    "════════════════════════════════════════════════════════════════════",
    "",
  ];
  console.log(lines.join("\n"));
});

/* ------------------------------------------------------------------------- *
 * Flow + shape: the pipeline walked every layer and produced a valid Report.
 * ------------------------------------------------------------------------- */

describe("E2E scan — full pipeline flow (map → discovery → correlation → confirm → fix → report)", () => {
  it("walks L0→L5 exactly once each and completes report-first", () => {
    for (const layer of ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"]) {
      expect(run.layerCalls[layer]).toBe(1);
    }
    expect(run.scan.status).toBe("completed");
    expect(run.scan.gateState).toBe("auto_approved"); // auto-fix OFF ⇒ report-first
  });

  it("ran discovery in a known mode and still produced probable → confirmed on real data", () => {
    expect(DISCOVERY_MODE === "live-scanners" || DISCOVERY_MODE === "seeded-candidates").toBe(true);
    // The moat (L2) corroborated candidates against the REAL App Map, then L3 confirmed.
    expect(run.layer2.probable.length).toBeGreaterThan(0);
    expect(run.layer3.confirmed.length).toBeGreaterThan(0);
    // Ground-truth: the SQL-injection on the public /api/users route is confirmed.
    expect(run.layer3.confirmed.some((c) => c.category === "sql_injection")).toBe(true);
    expect(run.layer3.confirmed.some((c) => c.category === "xss")).toBe(true);
  });

  it("⛔ produces a valid @montr/contracts Report whose HEADLINE is confirmed findings (never raw counts)", () => {
    // Re-validate against the frozen contract (defense in depth).
    const report = ReportSchema.parse(run.report);
    const rawCandidatePile = mockLayer1Output.candidates.length; // the "500 issues" pile

    // The headline is confirmed-only; it can never echo the raw candidate pile.
    assertConfirmedOnlyHeadline(report, rawCandidatePile);
    expect(report.executiveSummary.totalConfirmed).toBe(report.confirmedFindings.length);
    expect(report.executiveSummary.totalConfirmed).toBeLessThan(rawCandidatePile);
    // Breadth is preserved in the appendix, not deleted.
    expect(report.unconfirmedAppendix.length).toBeGreaterThan(0);
    // Prior point tools are consolidated into the one report.
    expect(report.executiveSummary.toolsConsolidated.length).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------------- *
 * DoD: every confirmed finding carries proof + merge-ready fix + test + mapping.
 * ------------------------------------------------------------------------- */

describe("E2E scan — confirmed findings are actionable (proof + fix + test + OWASP/CWE)", () => {
  it("⛔ each confirmed finding carries a static proof, a merge-ready Fix, a proof-of-fix test, and an OWASP/CWE mapping", () => {
    expect(run.report.confirmedFindings.length).toBeGreaterThan(0);

    for (const rf of run.report.confirmedFindings) {
      // Proof (static argument — no requests fired).
      expect(rf.finding.proofType).toBe("static");
      const proof = rf.finding.proofArtifact;
      expect(proof.kind).toBe("static");
      if (proof.kind === "static") {
        expect(proof.argument.length).toBeGreaterThan(0);
        expect(proof.dataFlow.length).toBeGreaterThan(0); // source→sink hops
      }

      // OWASP + CWE mapping on both the finding and the report's compliance cell.
      expect(rf.finding.cwe.length).toBeGreaterThan(0);
      expect(rf.compliance.cwe.length).toBeGreaterThan(0);
      expect(rf.compliance.owasp).toMatch(/^A\d{2}:2021$/);
      expect(rf.compliance.owaspTitle.length).toBeGreaterThan(0);

      // Merge-ready fix with a proof-of-fix test (fails pre-patch, passes post-patch).
      expect(rf.fix).toBeDefined();
      const fix = rf.fix!;
      expect(fix.patch.length).toBeGreaterThan(0); // a real unified diff
      expect(fix.rationale.length).toBeGreaterThan(0);
      expect(fix.riskClassRationale.length).toBeGreaterThan(0);
      expect(fix.proofOfFixTest.code.length).toBeGreaterThan(0);
      expect(fix.proofOfFixTest.failsPrePatch).toBe(true);
      expect(fix.proofOfFixTest.passesPostPatch).toBe(true);
    }
  });

  it("generates one Fix per confirmed finding and surfaces auto-eligible fixes for this repo's injection findings", () => {
    expect(run.layer4.fixes.length).toBe(run.layer3.confirmed.length);
    // SQLi + XSS are mechanical, low-blast-radius ⇒ auto-eligible for this repo.
    expect(run.report.fixStatus.autoEligibleFixIds.length).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------------- *
 * ⛔ Golden rule #3: auth/crypto/access-control fixes are ALWAYS human-required.
 * ------------------------------------------------------------------------- */

describe("E2E scan — ⛔ auth/crypto/access-control fixes classified human-required (100%)", () => {
  // The 100%-of-golden-corpus-cases guarantee (PRD §19). Static-only confirmation
  // (default) proves the injection classes; the config/crypto classes are deferred
  // to the appendix. So we assert BOTH: (a) any such finding that IS confirmed in
  // the scan gets a human-required fix, and (b) the Layer-4 classifier maps EVERY
  // auth/crypto/access-control category to human-required — the direct golden-rule
  // check over all such categories.
  const HUMAN_REQUIRED_CATEGORIES: readonly Category[] = [
    ...ALWAYS_HUMAN_REQUIRED_CATEGORIES,
    "hardcoded_secret",
    "broken_access_control",
    "broken_authentication",
    "weak_crypto",
  ];

  it("(a) any confirmed auth/crypto/access-control finding in THIS scan has a human-required fix", () => {
    for (const rf of run.report.confirmedFindings) {
      if (HUMAN_REQUIRED_CATEGORIES.includes(rf.finding.category)) {
        expect(rf.fix?.riskClass).toBe("human-required");
      }
    }
    // For this repo the confirmed set is injection-only ⇒ every confirmed fix is
    // auto-eligible (and none is human-required-by-category) — verified explicitly.
    expect(run.report.confirmedFindings.every((rf) => rf.fix?.riskClass === "auto-eligible")).toBe(
      true,
    );
  });

  it("⛔ (b) the deterministic Layer-4 classifier maps 100% of auth/crypto/access-control categories to human-required", () => {
    const categories: Category[] = [
      "broken_access_control",
      "broken_authentication",
      "weak_crypto",
      "idor",
      "csrf",
      "sensitive_data_exposure",
      "insecure_deserialization",
      "hardcoded_secret",
    ];
    for (const category of categories) {
      const finding = makeConfirmed(category);
      // Even a clean, tiny, cleanly-validated patch must NOT downgrade the class.
      const decision = classifyConfirmedFindingRisk(
        finding,
        {
          patch: "-x\n+y",
          changedFiles: [finding.location.file],
          changedLines: 1,
          uncertain: false,
        },
        { alwaysHumanCategories: hardenedConfig().autoFix.humanRequiredCategoriesAlways },
      );
      expect(decision.riskClass).toBe("human-required");
    }
  });

  it("⛔ (b') the real Layer-4 fix generator emits human-required fixes for all auth/crypto/access-control confirmed findings", async () => {
    const categories: Category[] = [
      "broken_access_control",
      "broken_authentication",
      "weak_crypto",
      "idor",
      "csrf",
      "sensitive_data_exposure",
      "hardcoded_secret",
    ];
    const confirmed = categories.map((c) => makeConfirmed(c));
    const { gateway } = recordingGateway();
    const out = await generateFixes({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      gateway,
      source: createMapSourceReader({}), // no mechanical fix available ⇒ advisory (human-required)
      humanRequiredCategoriesAlways: hardenedConfig().autoFix.humanRequiredCategoriesAlways,
      confirmed,
      now: () => FIXED_NOW,
    });
    expect(out.fixes.length).toBe(categories.length);
    expect(out.fixes.every((f) => f.riskClass === "human-required")).toBe(true);
  });
});

/* ------------------------------------------------------------------------- *
 * ⛔ Golden rule #1: no code egress; LLM logs are metadata-only.
 * ------------------------------------------------------------------------- */

describe("E2E scan — ⛔ no code egress; audit/LLM logs are metadata-only", () => {
  it("routes every LLM call through the single injected in-process gateway (the only egress path)", () => {
    // The gateway is the fake, in-process adapter — it opens NO sockets. Every
    // layer that reasons with the LLM went through it (nowhere else).
    expect(run.llmRequests.length).toBeGreaterThan(0);
    for (const req of run.llmRequests) {
      expect(req.metadata.purpose).toBeTruthy();
    }
  });

  it("⛔ the audit trail carries NO source-code bodies and NO secret values", () => {
    const auditText = JSON.stringify(run.audit);
    // The known hard-coded secret from the repo must never reach the audit log.
    expect(auditText).not.toContain("sk_live_");
    // No source-code bodies of the confirmed vulns leak into audit metadata.
    expect(auditText).not.toContain("queryRawUnsafe(");
    expect(auditText).not.toContain("dangerouslySetInnerHTML");
    expect(auditText).not.toContain("${q}");
  });

  it("⛔ every llm.call audit event is metadata-only (model + token counts, never prompt/code)", () => {
    const llmCalls = run.audit.filter((a) => a.action === "llm.call");
    expect(llmCalls.length).toBeGreaterThan(0);
    for (const call of llmCalls) {
      const meta = call.metadata ?? {};
      expect(meta).toHaveProperty("model");
      // All metadata values are scalars (counts, ids, model names) — no bodies.
      for (const value of Object.values(meta)) {
        expect(["string", "number", "boolean"]).toContain(typeof value);
      }
      const metaText = JSON.stringify(meta);
      expect(metaText).not.toMatch(/function |=>|SELECT .*FROM|dangerouslySetInnerHTML/);
    }
  });

  it("the telemetry scrubber neutralizes a code/secret body under an innocuous key (backstop)", () => {
    const scrubbed = scrubValue({
      // Innocuous key carrying THIS repo's Stripe secret — must be redacted by the
      // key-independent content guard (not just by key name).
      note: 'export const PAYMENTS_API_KEY = "sk_live_51H8xEXAMPLEhardcodedKeyDoNotUse0000";',
      // Sensitive key carrying a source-code body — redacted by key name.
      snippet: "await prisma.$queryRawUnsafe(`SELECT * FROM \"User\" WHERE name = '${q}'`)",
    }) as Record<string, string>;
    expect(scrubbed.snippet).toContain("[REDACTED]"); // key "snippet" is sensitive
    expect(scrubbed.note).toContain("[REDACTED]"); // Stripe secret caught by content guard
    expect(JSON.stringify(scrubbed)).not.toContain("sk_live_");
  });
});

/* ------------------------------------------------------------------------- *
 * ⛔ Cost is a first-class output: estimate pre-scan, actuals recorded.
 * ------------------------------------------------------------------------- */

describe("E2E scan — ⛔ cost estimate surfaced pre-scan; actuals recorded", () => {
  it("surfaces a cost estimate at the pre-scan gate before any Layer-1 work", () => {
    expect(run.scan.costEstimate).toBeDefined();
    expect(run.scan.costEstimate!.projectedTotalTokens).toBeGreaterThan(0);
    expect(run.scan.costEstimate!.projectedUsd).toBeGreaterThanOrEqual(0);
    // The estimate gate was presented (surfaced) and then approved.
    const actions = run.audit.map((a) => a.action);
    expect(actions).toContain("gate.estimate_presented");
    expect(actions).toContain("gate.estimate_approved");
  });

  it("records post-scan actuals on the scan and in the report cost rollup", () => {
    expect(run.scan.costActual).toBeDefined();
    expect(run.report.costAndScope.cost).toBeDefined();
    expect(run.report.costAndScope.cost.estimate.projectedTotalTokens).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------------- *
 * The golden-corpus gate can SCORE this real scan (PRD §15/§19 FP metric).
 * ------------------------------------------------------------------------- */

describe("E2E scan — golden-corpus gate scores the real scan (FP-rate < 5%)", () => {
  it("scores the confirmed findings against ground truth with zero false positives", () => {
    const { score } = gradeScanResults(
      [{ repo: "vulnerable-nextjs", confirmed: run.layer3.confirmed }],
      groundTruthManifest,
    );
    // ⛔ PRD §19 headline metric: false-positive rate < 5%. Static confirmation is
    // conservative — it confirms only proven-exploitable injection sinks, so it
    // never over-confirms (the demoted dep/CORS stay in the appendix).
    expect(score.fpRate).toBeLessThan(0.05);
    expect(score.falsePositives).toBe(0);
    expect(score.precision).toBe(1);
    expect(score.truePositives).toBeGreaterThanOrEqual(2); // sqli + xss
    expect(score.overConfirmed).toBe(0);
  });
});

/* ------------------------------------------------------------------------- *
 * ⛔ A6 — Blue Team report sections (B10) are genuinely non-empty from a REAL
 * pipeline run through Layer 5. Regression guard for A2's `resolveAppMap(ctx)`
 * wiring in apps/worker/src/runners.ts's Layer 5 handler: before A2, Layer 5
 * never resolved the App Map, so `buildReport`'s `appMap` input was always
 * `undefined` and `buildBlueTeamReport`'s detection-coverage/attack-path/
 * threat-model sections rendered permanently empty in production. A prior
 * mock-backed visual check of the console's Blue Team tab (apps/web/src/mocks/
 * data.ts) could not catch that gap — the mock populated exactly the fields
 * production left empty. This block is the real assertion the A6 audit
 * finding (docs/plan/26-09-12-audit-red-blue-agentic-posture.md) called for.
 *
 * Deliberately its OWN dedicated pipeline run (own beforeAll), not a reuse of
 * the shared `run` above, for two reasons:
 *
 *  1. `run`'s discovery mode is environment-dependent (`DISCOVERY_MODE`) and,
 *     whenever semgrep+gitleaks are on PATH, takes the SAME "live-scanners"
 *     path that carries this file's two known pre-existing, unrelated
 *     failures (a real SQL-injection candidate not reaching Layer 2's
 *     probable output — an environmental dependency on the hosted Semgrep
 *     registry, not something this task caused or fixes). This block instead
 *     always seeds Layer 1 directly, mirroring `buildRunners`'s own
 *     seeded-candidates fallback above, so it is fully deterministic
 *     regardless of the host environment or Semgrep registry reachability.
 *  2. `vulnerable-nextjs`'s two confirmed categories (sql_injection, xss)
 *     never satisfy any `packages/correlation/src/attack-paths/conditions.ts`
 *     chain condition (see that file's header) — B8 attack paths would be
 *     structurally empty on that fixture REGARDLESS of whether A2's wiring is
 *     present, making an `attackPaths.length > 0` assertion worthless as a
 *     regression guard there. `attack-chain-nextjs` (packages/fixtures/
 *     sample-repos/attack-chain-nextjs — see its README) is a small, dedicated
 *     fixture pairing an RCE-class finding (command_injection) with a second
 *     finding on a different route, which unconditionally forms the
 *     `rce-post-exploitation` chain condition — so a real attack path is
 *     genuinely producible here. It is NOT part of the golden corpus and never
 *     affects corpus/baseline.json or the shared `run`'s false-positive
 *     grading above.
 * ------------------------------------------------------------------------- */
describe("E2E scan — ⛔ Blue Team report sections are non-empty (A6, A2 regression guard)", () => {
  const ATTACK_CHAIN_REPO = fileURLToPath(
    new URL("../../../packages/fixtures/sample-repos/attack-chain-nextjs", import.meta.url),
  );
  const BLUE_TEAM_SCAN_ID = "scan_fixture_blueteam_0001";

  /**
   * Deterministic Layer-1 seed for `attack-chain-nextjs`, hand-built in the
   * same shape/convention as `@montr/fixtures`' `mockCandidateFindings` —
   * never the live semgrep/gitleaks scanners (see header: this must not
   * depend on the same flaky discovery path as the two known failures above).
   */
  function seededAttackChainCandidates(): CandidateFinding[] {
    return [
      CandidateFindingSchema.parse({
        id: "cand_ac_sqli_0001",
        scanId: BLUE_TEAM_SCAN_ID,
        clientId: CLIENT_ID,
        source: "semgrep",
        ruleId: "typescript.prisma.raw-query-unsafe",
        category: "sql_injection",
        cwe: ["CWE-89"],
        location: { file: "app/api/users/route.ts", line: 9 },
        rawSeverity: "high",
        evidenceSnippet: "prisma.$queryRawUnsafe(`SELECT * FROM \"User\" WHERE name = '${q}'`)",
        title: "Unsafe raw SQL query via string interpolation",
        createdAt: FIXED_NOW,
      }),
      CandidateFindingSchema.parse({
        id: "cand_ac_cmdi_0001",
        scanId: BLUE_TEAM_SCAN_ID,
        clientId: CLIENT_ID,
        source: "semgrep",
        ruleId: "nodejs.child-process.exec-unsanitized",
        category: "command_injection",
        cwe: ["CWE-78"],
        location: { file: "app/api/run/route.ts", line: 7 },
        rawSeverity: "critical",
        evidenceSnippet: "execSync(cmd)",
        title: "OS command injection via unsanitized child_process.execSync",
        createdAt: FIXED_NOW,
      }),
    ];
  }

  let btReport: Report;

  beforeAll(async () => {
    const { store } = makeInMemoryStore();
    const { gateway } = recordingGateway();
    const real = createLayerRunners({ gateway });
    const { runners, outputs } = instrument({
      ...real,
      layer1: () => Promise.resolve({ candidates: seededAttackChainCandidates() }),
    });

    await runScanInProcess(
      {
        config: hardenedConfig(),
        store,
        gateway,
        logger: silentLogger,
        layerRunners: runners,
        ids: () => BLUE_TEAM_SCAN_ID,
        sleep: () => Promise.resolve(),
      },
      {
        clientId: CLIENT_ID,
        repo: ATTACK_CHAIN_REPO, // LOCAL path ⇒ real Layer 0 App Map, exactly like the main run.
        branch: "main",
        mode: "full" as const,
        scope: { mode: "full" as const, includePaths: [] as string[] },
        operator: "user_operator_0001",
      },
      { approveEstimate: "user_approver_0001", timeoutMs: 60_000 },
    );

    btReport = (outputs.layer5 as Layer5Output).report;
  }, 60_000);

  it("confirms both fixture vulnerabilities (sanity: the chain below has real findings to work with)", () => {
    expect(btReport.confirmedFindings.length).toBeGreaterThanOrEqual(2);
    const categories = btReport.confirmedFindings.map((rf) => rf.finding.category);
    expect(categories).toContain("sql_injection");
    expect(categories).toContain("command_injection");
  });

  it("⛔ detectionEngineering.coverage (B6) is non-empty — requires the A2-resolved App Map", () => {
    expect(btReport.blueTeam.detectionEngineering.coverage.length).toBeGreaterThan(0);
    // Every confirmed finding gets a tri-state coverage verdict (B6) grounded
    // in a real generated rule (see buildBlueTeamReport) — never a guess.
    for (const c of btReport.blueTeam.detectionEngineering.coverage) {
      expect([true, false, "unknown"]).toContain(c.detected);
      expect(c.reasoning.length).toBeGreaterThan(0);
    }
  });

  it("⛔ attackPaths (B8) is non-empty — the RCE-class finding chains to the other confirmed finding", () => {
    expect(btReport.blueTeam.attackPaths.length).toBeGreaterThan(0);
    const path = btReport.blueTeam.attackPaths[0]!;
    expect(path.steps.length).toBeGreaterThanOrEqual(2);
    // End-to-end severity is force-bumped to "critical" whenever an RCE hop
    // participates (packages/correlation/src/attack-paths/graph.ts).
    expect(path.severity).toBe("critical");
  });

  it("⛔ threatModel.present (B7) is true — the App Map's baseline threat model reached the report", () => {
    expect(btReport.blueTeam.threatModel.present).toBe(true);
    expect(btReport.blueTeam.threatModel.summary?.length ?? 0).toBeGreaterThan(0);
    expect(btReport.blueTeam.threatModel.markdown?.length ?? 0).toBeGreaterThan(0);
  });

  it("hardening (B9) degrades to an honest advisory-only shape (real repo checkout, no crash)", () => {
    // Not asserted non-empty: whether this specific fixture trips any
    // particular hardening heuristic is incidental to the A2 regression this
    // block guards against — the section's SHAPE (never a guess, always
    // advisory-only) is what buildBlueTeamReport guarantees unconditionally.
    expect(btReport.blueTeam.hardening.advisoryOnly).toBe(true);
    expect(Array.isArray(btReport.blueTeam.hardening.recommendations)).toBe(true);
  });

  it("mitreAttack (B2) maps both confirmed findings to ATT&CK techniques", () => {
    // Unlike coverage/attackPaths/threatModel, this section does not depend on
    // `appMap` (buildMitreAttackSection works off `confirmedFindings` alone) —
    // included for completeness, not as an A2 regression signal.
    expect(btReport.blueTeam.mitreAttack.findings.length).toBeGreaterThanOrEqual(2);
    expect(btReport.blueTeam.mitreAttack.coverage.length).toBeGreaterThan(0);
  });

  // NOT covered here, by design: `purpleTeam` (B5) entries require a real,
  // approver-gated live-DAST run against a staging target (job.allowLive +
  // stagingUrl — apps/worker/src/runners.ts's Layer 3 wiring, A8) — real
  // network access this deterministic, offline e2e suite does not have. That
  // path already has its own real end-to-end coverage in
  // apps/worker/src/runners.test.ts (A2/A7/A8/A13's "an actual scenario
  // against a real local HTTP server" test cited in docs/overview.md's
  // 2026-09-12 A2/A7/A8/A13 entry) — duplicating a live HTTP server here would
  // test the same wiring twice for no added regression-guard value on the A2
  // App Map question this block exists to answer.
});

/* ------------------------------------------------------------------------- *
 * helpers
 * ------------------------------------------------------------------------- */

/** Build a minimal, contract-valid ConfirmedFinding for a category (classifier tests). */
function makeConfirmed(category: Category): ConfirmedFinding {
  const c = complianceForCategory(category);
  return ConfirmedFindingSchema.parse({
    id: `cf_${category}`,
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    probableId: `pf_${category}`,
    title: `${c.owaspTitle} finding`,
    category,
    cwe: c.cwe.length > 0 ? c.cwe : ["CWE-693"],
    owasp: c.owasp,
    severity: "high",
    exposure: "authed",
    location: { file: `app/security/${category}.ts`, line: 12 },
    impact: "Constructed confirmed finding for the risk-classifier golden-rule check.",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: "constructed for the classifier golden-rule assertion",
      dataFlow: [
        { location: { file: `app/security/${category}.ts`, line: 12 }, authState: "authenticated" },
      ],
      sanitizersBypassed: [],
    },
    createdAt: FIXED_NOW,
  });
}
