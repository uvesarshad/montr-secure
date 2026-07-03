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
  ConfirmedFindingSchema,
  ReportSchema,
  complianceForCategory,
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
