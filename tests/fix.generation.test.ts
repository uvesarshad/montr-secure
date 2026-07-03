import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateFixes,
  validatePatch,
  pickStrategy,
  createFsSourceReader,
  createMapSourceReader,
  createNodeProofRunner,
  type GenerateFixesInput,
  type ProofTestRunner,
} from "@montr/fix";
import {
  mockConfirmedFindings,
  createFakeLlmGateway,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  CONFIRMED_SQLI_ID,
  CONFIRMED_XSS_ID,
} from "@montr/fixtures";
import {
  Layer4OutputSchema,
  type AuditEvent,
  type AuditEventInput,
  type Category,
  type ConfirmedFinding,
  type LLMGateway,
  type LLMRequest,
} from "@montr/contracts";
import type { AuditLogClient } from "@montr/telemetry";

const VULN_ROOT = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);
const read = (p: string): string => readFileSync(join(VULN_ROOT, p), "utf8");

const SQLI = mockConfirmedFindings.find((f) => f.id === CONFIRMED_SQLI_ID) as ConfirmedFinding;
const XSS = mockConfirmedFindings.find((f) => f.id === CONFIRMED_XSS_ID) as ConfirmedFinding;

/** Captures audit appends without a DB (metadata-only assertions). */
class CapturingAudit implements AuditLogClient {
  readonly events: AuditEventInput[] = [];
  append(input: AuditEventInput): Promise<AuditEvent> {
    this.events.push(input);
    return Promise.resolve({
      id: `audit_${this.events.length}`,
      clientId: input.clientId,
      sequence: this.events.length,
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
    } as AuditEvent);
  }
  list(): Promise<AuditEvent[]> {
    return Promise.resolve([]);
  }
  verifyChain(): Promise<boolean> {
    return Promise.resolve(true);
  }
}

/** Wraps a gateway to record the requests it receives. */
function recordingGateway(inner: LLMGateway): { gateway: LLMGateway; requests: LLMRequest[] } {
  const requests: LLMRequest[] = [];
  const gateway: LLMGateway = {
    complete: (req) => {
      requests.push(req);
      return inner.complete(req);
    },
    stream: (req) => inner.stream(req),
    listModels: () => inner.listModels(),
    resolveModel: (t) => inner.resolveModel(t),
  };
  return { gateway, requests };
}

function baseInput(overrides: Partial<GenerateFixesInput> = {}): GenerateFixesInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    confirmed: [SQLI, XSS],
    gateway: createFakeLlmGateway(),
    source: createFsSourceReader(VULN_ROOT),
    now: () => FIXED_NOW,
    ...overrides,
  };
}

describe("@montr/fix — generateFixes (Layer 4)", () => {
  it("emits a validated, diff-ready, auto-eligible Fix for each confirmed finding", async () => {
    const out = await generateFixes(baseInput());

    // Exact Layer 4 output contract.
    expect(() => Layer4OutputSchema.parse(out)).not.toThrow();
    expect(out.fixes).toHaveLength(2);

    for (const fix of out.fixes) {
      expect(fix.status).toBe("proposed");
      expect(fix.riskClass).toBe("auto-eligible");
      expect(fix.patch.length).toBeGreaterThan(0);
      expect(fix.rationale.length).toBeGreaterThan(0);
      expect(fix.riskClassRationale.length).toBeGreaterThan(0);
      expect(fix.proofOfFixTest.failsPrePatch).toBe(true);
      expect(fix.proofOfFixTest.passesPostPatch).toBe(true);
      expect(fix.proofOfFixTest.code).toContain("readFileSync");
      expect(fix.proofOfFixTest.code).toContain("not.toMatch");
    }

    const sqliFix = out.fixes.find((f) => f.confirmedFindingId === CONFIRMED_SQLI_ID)!;
    const xssFix = out.fixes.find((f) => f.confirmedFindingId === CONFIRMED_XSS_ID)!;
    expect(sqliFix.id).toBe(`fix_${CONFIRMED_SQLI_ID}`);
    expect(xssFix.id).toBe(`fix_${CONFIRMED_XSS_ID}`);

    // Independently re-validate the emitted patches against the ORIGINAL source:
    // patch applies AND the vulnerability is gone post-patch (proof-of-fix holds).
    const sqli = validatePatch(read("app/api/users/route.ts"), sqliFix.patch, (s) =>
      /\$queryRawUnsafe/.test(s),
    );
    expect(sqli.applies).toBe(true);
    expect(sqli.passesPostPatch).toBe(true);
    expect(sqli.appliedSource).toContain("$queryRaw`");

    const xss = validatePatch(read("app/search/page.tsx"), xssFix.patch, (s) =>
      /dangerouslySetInnerHTML/.test(s),
    );
    expect(xss.applies).toBe(true);
    expect(xss.passesPostPatch).toBe(true);
  });

  it("⛔ auth/crypto/access-control confirmed findings are ALWAYS human-required (100% rule)", async () => {
    const authFindings: ConfirmedFinding[] = (
      ["broken_authentication", "weak_crypto", "broken_access_control", "idor"] as Category[]
    ).map((category, i) => ({
      ...SQLI,
      id: `conf_auth_${i}`,
      category,
      title: `${category} finding`,
      location: { ...SQLI.location, file: `app/api/thing_${i}/route.ts` },
    }));

    // Even when the model is (wrongly) told the fix is auto-eligible, the
    // DETERMINISTIC classifier keeps it human-required — the LLM cannot override safety.
    const gateway = createFakeLlmGateway({
      cannedByPurpose: {
        fix_generation: JSON.stringify({ fixedSource: "whatever", riskClass: "auto-eligible" }),
      },
    });

    const out = await generateFixes(
      baseInput({ confirmed: authFindings, gateway, source: createMapSourceReader({}) }),
    );

    expect(out.fixes).toHaveLength(authFindings.length);
    for (const fix of out.fixes) {
      expect(fix.riskClass).toBe("human-required");
      expect(fix.status).toBe("proposed");
    }
  });

  it("⛔ a validated model patch that touches crypto is STILL escalated to human-required", async () => {
    const original = read("app/search/page.tsx");
    const detFixed = pickStrategy("xss")!.apply(original)!; // removes dangerouslySetInnerHTML
    const craftedCryptoFix = `import crypto from "node:crypto";\nconst _h = crypto.createHash("sha256");\n${detFixed}`;

    const gateway = createFakeLlmGateway({
      cannedByPurpose: {
        fix_generation: JSON.stringify({
          fixedSource: craftedCryptoFix,
          rationale: "added hashing",
        }),
      },
    });

    const out = await generateFixes(baseInput({ confirmed: [XSS], gateway }));
    const fix = out.fixes[0]!;

    // The patch is a genuine, validated fix (the XSS is removed)...
    const v = validatePatch(original, fix.patch, (s) => /dangerouslySetInnerHTML/.test(s));
    expect(v.applies).toBe(true);
    expect(v.passesPostPatch).toBe(true);
    expect(v.appliedSource).toContain("crypto.createHash");
    // ...yet it is human-required because the patch touches crypto (deterministic gate).
    expect(fix.riskClass).toBe("human-required");
    expect(fix.riskClassRationale.toLowerCase()).toContain("crypto");
  });

  it("prefers a cleanly-validated model-proposed patch over the deterministic transform", async () => {
    const original = read("app/api/users/route.ts");
    const findManyFix = original.replace(
      /const rows = await prisma\.\$queryRawUnsafe\([\s\S]*?\);/,
      "const rows = await prisma.user.findMany({ where: { name: q } });",
    );
    expect(findManyFix).not.toContain("$queryRawUnsafe"); // sanity: the craft removes the vuln

    const gateway = createFakeLlmGateway({
      cannedByPurpose: {
        fix_generation: JSON.stringify({
          fixedSource: findManyFix,
          rationale: "use the typed API",
        }),
      },
    });

    const out = await generateFixes(baseInput({ confirmed: [SQLI], gateway }));
    const fix = out.fixes[0]!;

    const v = validatePatch(original, fix.patch, (s) => /\$queryRawUnsafe/.test(s));
    expect(v.applies).toBe(true);
    expect(v.passesPostPatch).toBe(true);
    expect(v.appliedSource).toContain("findMany"); // the MODEL's patch was used
    expect(v.appliedSource).not.toContain("$queryRaw`"); // not the deterministic one
    expect(fix.riskClass).toBe("auto-eligible");
    expect(fix.rationale).toContain("Model-proposed");
  });

  it("routes all fix synthesis through the gateway with fix_generation / layer4 metadata", async () => {
    const { gateway, requests } = recordingGateway(createFakeLlmGateway());
    await generateFixes(baseInput({ gateway }));

    expect(requests.length).toBeGreaterThanOrEqual(2);
    for (const req of requests) {
      expect(req.metadata.purpose).toBe("fix_generation");
      expect(req.metadata.layer).toBe("layer4");
      expect(req.metadata.scanId).toBe(SCAN_ID);
      expect(req.metadata.clientId).toBe(CLIENT_ID);
      expect(req.responseFormat).toBe("json");
      expect(req.tier).toBe("default");
    }
  });

  it("audit-logs a fix.generated event per fix — METADATA ONLY, never code bodies", async () => {
    const audit = new CapturingAudit();
    await generateFixes(baseInput({ audit }));

    expect(audit.events).toHaveLength(2);
    for (const e of audit.events) {
      expect(e.action).toBe("fix.generated");
      expect(e.targetType).toBe("fix");
      expect(e.actor).toEqual({ type: "agent", id: "montr-fix" });
      expect(e.clientId).toBe(CLIENT_ID);
      expect(e.scanId).toBe(SCAN_ID);

      // ⛔ golden rule #1: no patch/source/test bodies leak into audit metadata.
      const meta = e.metadata ?? {};
      expect(Object.keys(meta)).not.toContain("patch");
      expect(Object.keys(meta)).not.toContain("code");
      expect(Object.keys(meta)).not.toContain("source");
      const serialized = JSON.stringify(meta);
      expect(serialized).not.toContain("queryRawUnsafe");
      expect(serialized).not.toContain("dangerouslySetInnerHTML");
      expect(serialized).not.toContain("SELECT * FROM");
      expect(serialized).not.toContain("readFileSync");
    }
  });

  it("⛔ coding-agent loop iterates against the oracle: invalid proposal → feedback → valid fix", async () => {
    const original = read("app/api/users/route.ts");
    // Attempt 1: a change that does NOT remove the vulnerability ($queryRawUnsafe stays).
    const invalid = JSON.stringify({ fixedSource: `${original}\n// noop`, rationale: "attempt 1" });
    // Attempt 2: a genuine fix (typed query API) that passes the oracle.
    const valid = JSON.stringify({
      fixedSource: original.replace(
        /const rows = await prisma\.\$queryRawUnsafe\([\s\S]*?\);/,
        "const rows = await prisma.user.findMany({ where: { name: q } });",
      ),
      rationale: "use the typed API",
    });

    const inner = createFakeLlmGateway();
    let call = 0;
    const requests: LLMRequest[] = [];
    const gateway: LLMGateway = {
      complete: async (req) => {
        requests.push(req);
        const base = await inner.complete(req);
        return { ...base, content: call++ === 0 ? invalid : valid };
      },
      stream: (req) => inner.stream(req),
      listModels: () => inner.listModels(),
      resolveModel: (t) => inner.resolveModel(t),
    };

    const audit = new CapturingAudit();
    const out = await generateFixes(
      baseInput({
        confirmed: [SQLI],
        gateway,
        audit,
        agentLoop: { enabled: true, maxIterations: 3 },
      }),
    );
    const fix = out.fixes[0]!;

    // The second (valid) proposal was accepted through the SAME gate.
    expect(fix.riskClass).toBe("auto-eligible");
    const v = validatePatch(original, fix.patch, (s) => /\$queryRawUnsafe/.test(s));
    expect(v.applies && v.passesPostPatch).toBe(true);
    expect(v.appliedSource).toContain("findMany");
    // The loop iterated exactly once after the failed attempt (2 gateway round-trips),
    // and the retry carried the accumulated feedback conversation.
    expect(requests.length).toBe(2);
    expect(requests[1]!.messages.length).toBeGreaterThan(1);
    expect((audit.events[0]!.metadata as { iterations?: number }).iterations).toBe(2);
  });

  it("⛔ tool-using agent: calls read_file on a sibling, then proposes an accepted fix", async () => {
    const original = read("app/api/users/route.ts");
    const valid = JSON.stringify({
      fixedSource: original.replace(
        /const rows = await prisma\.\$queryRawUnsafe\([\s\S]*?\);/,
        "const rows = await prisma.user.findMany({ where: { name: q } });",
      ),
      rationale: "use the typed API",
    });
    // Sandboxed source with the target + a sibling the agent will read via the tool.
    const source = createMapSourceReader({
      "app/api/users/route.ts": original,
      "lib/db.ts": "export const db = 'the shared prisma client';",
    });

    const inner = createFakeLlmGateway();
    let call = 0;
    const requests: LLMRequest[] = [];
    const gateway: LLMGateway = {
      complete: async (req) => {
        requests.push(req);
        const base = await inner.complete(req);
        // Turn 1: the model calls read_file. Turn 2: it returns the fix.
        return call++ === 0
          ? {
              ...base,
              content: "",
              stopReason: "tool_use" as const,
              toolCalls: [{ id: "c1", name: "read_file", arguments: { path: "lib/db.ts" } }],
            }
          : { ...base, content: valid };
      },
      stream: (req) => inner.stream(req),
      listModels: () => inner.listModels(),
      resolveModel: (t) => inner.resolveModel(t),
    };

    const audit = new CapturingAudit();
    const out = await generateFixes(
      baseInput({
        confirmed: [SQLI],
        source,
        gateway,
        audit,
        agentLoop: { enabled: true, maxIterations: 3, maxToolCalls: 3 },
      }),
    );
    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("auto-eligible");

    // Turn 1 offered the read_file tool; two round-trips total (1 tool + 1 proposal).
    expect(requests[0]!.tools?.some((t) => t.name === "read_file")).toBe(true);
    expect(requests.length).toBe(2);
    // Turn 2 carried the tool RESULT (the sibling's contents) back to the model.
    const toolMsg = requests[1]!.messages.find((m) => m.role === "tool");
    expect(toolMsg).toBeDefined();
    expect(typeof toolMsg!.content === "string" ? toolMsg!.content : "").toContain(
      "shared prisma client",
    );
    // The tool round did NOT count as a fix attempt (iterations = 1).
    expect((audit.events[0]!.metadata as { iterations?: number }).iterations).toBe(1);
  });

  it("single-shot (agent loop OFF) makes exactly one gateway call per finding", async () => {
    const { gateway, requests } = recordingGateway(createFakeLlmGateway());
    await generateFixes(baseInput({ confirmed: [SQLI], gateway }));
    expect(requests.length).toBe(1);
  });

  it("⛔ createNodeProofRunner actually RUNS the proof test: fails-pre, passes-post", async () => {
    const runner = createNodeProofRunner({ timeoutMs: 20_000 });
    const strategy = pickStrategy("sql_injection")!;
    const original = read("app/api/users/route.ts");
    const fixed = strategy.apply(original)!; // deterministic fix removes $queryRawUnsafe
    const testCode = strategy.proofTestCode("app/api/users/route.ts", SQLI);

    // Real subprocess: the synthesized test FAILS on the vulnerable file, PASSES on the fix.
    expect(
      await runner.run({ testCode, targetPath: "app/api/users/route.ts", source: original }),
    ).toBe(false);
    expect(
      await runner.run({ testCode, targetPath: "app/api/users/route.ts", source: fixed }),
    ).toBe(true);
  }, 40_000);

  it("⛔ execution-backed gate accepts only when the proof test fails-pre AND passes-post", async () => {
    const original = read("app/api/users/route.ts");
    // Honest runner: FAILS on the original (vuln present), PASSES on any patched source.
    const honest: ProofTestRunner = { run: async ({ source }) => source !== original };
    const ok = await generateFixes(baseInput({ confirmed: [SQLI], proofRunner: honest }));
    expect(ok.fixes[0]!.riskClass).toBe("auto-eligible");

    // Contradicting runner: the test PASSES even on the original (never fails-pre) ⇒ no
    // candidate is execution-confirmed ⇒ fail-safe advisory (human-required).
    const wrong: ProofTestRunner = { run: async () => true };
    const adv = await generateFixes(baseInput({ confirmed: [SQLI], proofRunner: wrong }));
    expect(adv.fixes[0]!.riskClass).toBe("human-required");
    expect(adv.fixes[0]!.patch).toBe("");
  });

  it("emits an advisory human-required fix when no strategy matches", async () => {
    const ssrf: ConfirmedFinding = {
      ...SQLI,
      id: "conf_ssrf_0001",
      category: "ssrf",
      title: "SSRF in image proxy",
      location: { ...SQLI.location, file: "app/api/proxy/route.ts" },
    };
    const out = await generateFixes(
      baseInput({ confirmed: [ssrf], source: createMapSourceReader({}) }),
    );
    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("human-required");
    expect(fix.patch).toBe("");
    expect(fix.proofOfFixTest.failsPrePatch).toBe(false);
    expect(fix.proofOfFixTest.passesPostPatch).toBe(false);
    expect(fix.rationale.toLowerCase()).toContain("manual remediation");
  });

  it("emits an advisory fix (source unavailable) when the file cannot be read", async () => {
    const out = await generateFixes(
      baseInput({ confirmed: [SQLI], source: createMapSourceReader({}) }),
    );
    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("human-required");
    expect(fix.rationale.toLowerCase()).toContain("source unavailable");
  });
});
