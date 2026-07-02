/**
 * WS-F / Layer 1 — pipeline tests for `runDiscovery` and friends: the three
 * concurrent detectors, dedupe, optional LLM triage (via the fixtures fake
 * gateway), persistence + audit, determinism, and the ⛔ kill switch. Fully
 * offline: Semgrep/gitleaks are mocked with injected runners, files come from
 * the @montr/fixtures sample repos, and the LLM is the deterministic fake.
 */
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import {
  Layer1OutputSchema,
  type AuditEvent,
  type AuditEventInput,
  type CandidateFinding,
  type ScanScope,
} from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import { createFakeLlmGateway, mockAppMap, CLIENT_ID, SCAN_ID } from "@montr/fixtures";
import {
  runDiscovery,
  runDiscoveryDetailed,
  runDiscoveryToStore,
  persistCandidates,
  type RunDiscoveryInput,
  type SemgrepRunner,
  type GitleaksRunner,
  type CandidatePersister,
  type AuditAppender,
} from "@montr/discovery";

const FIXED_NOW = "2026-01-15T10:00:00.000Z";
const VULN_REPO = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);
const CLEAN_REPO = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/clean-nextjs", import.meta.url),
);

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

const vulnSemgrep: SemgrepRunner = async () => ({
  results: [
    {
      check_id: "typescript.prisma.raw-query-unsafe",
      path: "app/api/users/route.ts",
      start: { line: 9 },
      extra: {
        severity: "ERROR",
        message: "Unsafe raw SQL query",
        lines: "$queryRawUnsafe(`... ${q} ...`)",
        metadata: { cwe: ["CWE-89"] },
      },
    },
    {
      check_id: "react.dangerouslySetInnerHTML",
      path: "app/search/page.tsx",
      start: { line: 8 },
      extra: {
        severity: "WARNING",
        message: "Reflected XSS",
        lines: "dangerouslySetInnerHTML={{ __html: q }}",
        metadata: { cwe: ["CWE-79"] },
      },
    },
  ],
});
const emptySemgrep: SemgrepRunner = async () => ({ results: [] });
const noGitleaks: GitleaksRunner = async () => [];

function vulnInput(overrides: Partial<RunDiscoveryInput> = {}): RunDiscoveryInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    appMap: mockAppMap,
    scope: FULL_SCOPE,
    config: getHardenedDefaults(),
    repoRoot: VULN_REPO,
    deps: { now: () => FIXED_NOW, semgrep: vulnSemgrep, gitleaks: noGitleaks },
    ...overrides,
  };
}

describe("discovery/runDiscovery over the vulnerable sample", () => {
  it("emits the exact Layer1Output contract with the expected finding categories", async () => {
    const output = await runDiscovery(vulnInput());
    // Exact contract shape — only `candidates`.
    expect(() => Layer1OutputSchema.parse(output)).not.toThrow();
    expect(Object.keys(output)).toEqual(["candidates"]);

    const cats = new Set(output.candidates.map((c) => c.category));
    for (const expected of [
      "sql_injection",
      "xss",
      "hardcoded_secret",
      "permissive_cors",
      "vulnerable_dependency",
    ]) {
      expect(cats.has(expected as CandidateFinding["category"])).toBe(true);
    }
  });

  it("fans out across all three sources (semgrep + custom/gitleaks + osv/ghsa)", async () => {
    const { output, bySource } = await runDiscoveryDetailed(vulnInput());
    const sources = new Set(output.candidates.map((c) => c.source));
    expect(sources.has("semgrep")).toBe(true); // SAST
    expect(sources.has("custom")).toBe(true); // secrets/config
    expect(sources.has("ghsa")).toBe(true); // SCA
    expect(bySource["semgrep"]).toBeGreaterThanOrEqual(2);
  });

  it("tags every candidate per §5.2 (source, rule, category, cwe, file, line, severity, evidence)", async () => {
    const { output } = await runDiscoveryDetailed(vulnInput());
    for (const c of output.candidates) {
      expect(c.source).toBeTruthy();
      expect(c.ruleId).toBeTruthy();
      expect(c.category).toBeTruthy();
      expect(Array.isArray(c.cwe)).toBe(true);
      expect(c.location.file).toBeTruthy();
      expect(typeof c.location.line).toBe("number");
      expect(c.rawSeverity).toBeTruthy();
      expect(typeof c.evidenceSnippet).toBe("string");
      expect(c.status).toBe("candidate");
    }
  });

  it("is deterministic + idempotent — identical candidate ids across runs", async () => {
    const a = await runDiscovery(vulnInput());
    const b = await runDiscovery(vulnInput());
    expect(a.candidates.map((c) => c.id).sort()).toEqual(b.candidates.map((c) => c.id).sort());
    // ids are unique (dedupe held).
    const ids = a.candidates.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("⛔ never leaks the raw secret value into any candidate", async () => {
    const { output } = await runDiscoveryDetailed(vulnInput());
    const blob = JSON.stringify(output);
    expect(blob).not.toContain("sk_live_51H8xEXAMPLEhardcodedKeyDoNotUse0000");
    expect(blob).not.toContain("hardcodedKeyDoNotUse");
  });

  it("honors the ⛔ kill switch (aborted signal → no work)", async () => {
    const ac = new AbortController();
    ac.abort();
    const input = vulnInput();
    const { output } = await runDiscoveryDetailed({
      ...input,
      deps: { ...input.deps, signal: ac.signal },
    });
    expect(output.candidates).toEqual([]);
  });
});

describe("discovery/runDiscovery over the clean sample", () => {
  it("produces zero candidates (supports the <5% FP posture)", async () => {
    const output = await runDiscovery(
      vulnInput({
        repoRoot: CLEAN_REPO,
        deps: { now: () => FIXED_NOW, semgrep: emptySemgrep, gitleaks: noGitleaks },
      }),
    );
    expect(output.candidates).toEqual([]);
  });
});

describe("discovery/triage (LLM enriches, never detects)", () => {
  it("annotates candidates with a triage verdict via the fake gateway", async () => {
    const gateway = createFakeLlmGateway();
    const input = vulnInput({
      deps: { now: () => FIXED_NOW, semgrep: vulnSemgrep, gitleaks: noGitleaks, gateway },
    });
    const withTriage = await runDiscovery(input);
    expect(withTriage.candidates.length).toBeGreaterThan(0);
    for (const c of withTriage.candidates) {
      const triage = c.metadata?.["triage"] as { keep?: boolean } | undefined;
      expect(triage?.keep).toBe(true);
    }
  });

  it("does not change the candidate COUNT (deterministic tools detect, not the LLM)", async () => {
    const gateway = createFakeLlmGateway();
    const withTriage = await runDiscovery(
      vulnInput({
        deps: { now: () => FIXED_NOW, semgrep: vulnSemgrep, gitleaks: noGitleaks, gateway },
      }),
    );
    const withoutTriage = await runDiscovery(vulnInput());
    expect(withTriage.candidates.length).toBe(withoutTriage.candidates.length);
  });

  it("skips triage when no gateway is provided (no metadata.triage)", async () => {
    const output = await runDiscovery(vulnInput());
    expect(output.candidates.some((c) => c.metadata?.["triage"] !== undefined)).toBe(false);
  });
});

describe("discovery/persist + audit", () => {
  function fakeStore(): { store: CandidatePersister; stored: CandidateFinding[] } {
    const stored: CandidateFinding[] = [];
    return {
      stored,
      store: {
        bulkCreate: async (_clientId, findings) => {
          stored.push(...findings);
          return findings;
        },
      },
    };
  }

  function fakeAudit(): { audit: AuditAppender; events: AuditEventInput[] } {
    const events: AuditEventInput[] = [];
    return {
      events,
      audit: {
        append: async (input) => {
          events.push(input);
          return {
            id: `audit_${events.length}`,
            clientId: input.clientId,
            sequence: events.length,
            scanId: input.scanId,
            actor: input.actor,
            action: input.action,
            targetType: input.targetType,
            targetId: input.targetId,
            summary: input.summary,
            metadata: input.metadata ?? {},
            prevHash: "",
            hash: "hash",
            at: FIXED_NOW,
          } satisfies AuditEvent;
        },
      },
    };
  }

  it("persists all candidates and audit-logs ONE metadata-only event", async () => {
    const { store, stored } = fakeStore();
    const { audit, events } = fakeAudit();
    const result = await runDiscoveryToStore(vulnInput(), { store, audit });

    expect(stored.length).toBe(result.output.candidates.length);
    expect(stored.length).toBeGreaterThan(0);

    expect(events).toHaveLength(1);
    const ev = events[0];
    expect(ev?.action).toBe("finding.candidate_created");
    expect(ev?.targetType).toBe("CandidateFinding");
    expect(ev?.metadata?.["count"]).toBe(stored.length);
    // ⛔ Audit metadata is counts only — no snippets / code / secrets.
    expect(JSON.stringify(ev?.metadata)).not.toContain("hardcodedKeyDoNotUse");
    expect(JSON.stringify(ev?.metadata)).not.toContain("dangerouslySetInnerHTML");
  });

  it("persistCandidates is a no-op on an empty pile (no write, no audit)", async () => {
    let writes = 0;
    let appends = 0;
    const store: CandidatePersister = {
      bulkCreate: async (_c, f) => {
        writes++;
        return f;
      },
    };
    const audit: AuditAppender = {
      append: async (input) => {
        appends++;
        return { ...({} as AuditEvent), ...input } as AuditEvent;
      },
    };
    const out = await persistCandidates({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      candidates: [],
      store,
      audit,
    });
    expect(out).toEqual([]);
    expect(writes).toBe(0);
    expect(appends).toBe(0);
  });
});
