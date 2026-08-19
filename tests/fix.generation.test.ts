import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateFixes,
  validatePatch,
  pickStrategy,
  createFsSourceReader,
  createMapSourceReader,
  type GenerateFixesInput,
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

// `validatePatch` now runs real `vitest` subprocesses (per candidate, and again
// per independent re-validation below) — several sequential/parallel subprocess
// runs per test comfortably exceed vitest's default 5s budget.
vi.setConfig({ testTimeout: 30_000 });

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

    // Independently re-validate the emitted patches against the ORIGINAL source,
    // by REALLY EXECUTING the exact proof-of-fix test the pipeline shipped:
    // patch applies AND a real vitest run proves the vulnerability is gone post-patch.
    const sqli = await validatePatch(read("app/api/users/route.ts"), sqliFix.patch, {
      filePath: "app/api/users/route.ts",
      proofTestCode: sqliFix.proofOfFixTest.code,
    });
    expect(sqli.executionError).toBeUndefined();
    expect(sqli.applies).toBe(true);
    expect(sqli.passesPostPatch).toBe(true);
    expect(sqli.appliedSource).toContain("$queryRaw`");

    const xss = await validatePatch(read("app/search/page.tsx"), xssFix.patch, {
      filePath: "app/search/page.tsx",
      proofTestCode: xssFix.proofOfFixTest.code,
    });
    expect(xss.executionError).toBeUndefined();
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

    // The patch is a genuine, validated fix (the XSS is removed) — proven by
    // REALLY EXECUTING the shipped proof-of-fix test against original vs. patched...
    const v = await validatePatch(original, fix.patch, {
      filePath: "app/search/page.tsx",
      proofTestCode: fix.proofOfFixTest.code,
    });
    expect(v.executionError).toBeUndefined();
    expect(v.applies).toBe(true);
    expect(v.passesPostPatch).toBe(true);
    expect(v.appliedSource).toContain("crypto.createHash");
    // ...yet it is human-required because the patch touches crypto (deterministic gate).
    expect(fix.riskClass).toBe("human-required");
    expect(fix.riskClassRationale.toLowerCase()).toContain("crypto");
  });

  it("prefers a cleanly-validated model-proposed patch over the deterministic transform", async () => {
    const original = read("app/api/users/route.ts");
    // A genuinely different model proposal that must ALSO satisfy the real
    // generated proof test — including its "uses the remediated pattern"
    // assertion (`toMatch(/\$(?:queryRaw|executeRaw)\`/)`), not just the
    // "vulnerability gone" one. `findMany({...})` (the pre-real-execution
    // version of this fixture) genuinely does NOT satisfy that second
    // assertion, so under real vitest execution it would (correctly) fail
    // validation and fall through to the deterministic transform — real
    // execution catching exactly the kind of gap this rework exists to close.
    // This craft keeps the model's proposal in the same "parameterized
    // tagged template" family (so it REALLY passes) while staying textually
    // distinguishable from the deterministic transform's own output.
    const modelFix = original.replace(
      /const rows = await prisma\.\$queryRawUnsafe\([\s\S]*?\);/,
      'const rows = await prisma.$queryRaw`SELECT * FROM "User" WHERE name = ${q}` /* model-proposed */;',
    );
    expect(modelFix).not.toContain("$queryRawUnsafe"); // sanity: the craft removes the vuln
    expect(modelFix).toContain("$queryRaw`"); // sanity: satisfies the strategy's "safe" pattern too

    const gateway = createFakeLlmGateway({
      cannedByPurpose: {
        fix_generation: JSON.stringify({
          fixedSource: modelFix,
          rationale: "use a tagged-template parameterized query",
        }),
      },
    });

    const out = await generateFixes(baseInput({ confirmed: [SQLI], gateway }));
    const fix = out.fixes[0]!;

    const v = await validatePatch(original, fix.patch, {
      filePath: "app/api/users/route.ts",
      proofTestCode: fix.proofOfFixTest.code,
    });
    expect(v.executionError).toBeUndefined();
    expect(v.applies).toBe(true);
    expect(v.passesPostPatch).toBe(true);
    expect(v.appliedSource).toContain("model-proposed"); // the MODEL's patch was used, not the deterministic one
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

  // A14 — full pipeline coverage for the newly-implemented mechanical strategies
  // (nosql_injection, insecure_cookie, missing_security_headers, open_redirect):
  // each must come out auto-eligible with a validated, fail-before/pass-after patch.
  it("emits validated, auto-eligible fixes for the newly-implemented mechanical categories", async () => {
    const files: Record<string, string> = {
      "app/api/accounts/route.ts": `export async function POST(req) {\n  const user = await db.collection("users").findOne({ username: req.body.username, password: req.body.password });\n  return user;\n}\n`,
      "app/api/preferences/route.ts": `export function setSessionCookie(res, token) {\n  res.cookie("session", token);\n}\n`,
      "next.config.js": `/** @type {import('next').NextConfig} */\nconst nextConfig = {\n  reactStrictMode: true,\n};\nmodule.exports = nextConfig;\n`,
      "app/api/goto/route.ts": `export function handler(req, res) {\n  return res.redirect(req.query.next);\n}\n`,
    };

    const findings: ConfirmedFinding[] = [
      {
        ...SQLI,
        id: "conf_nosqli_0001",
        category: "nosql_injection",
        title: "NoSQL operator injection in login",
        location: { ...SQLI.location, file: "app/api/accounts/route.ts" },
      },
      {
        ...SQLI,
        id: "conf_cookie_0001",
        category: "insecure_cookie",
        title: "Session cookie missing Secure/HttpOnly/SameSite",
        location: { ...SQLI.location, file: "app/api/preferences/route.ts" },
      },
      {
        ...SQLI,
        id: "conf_headers_0001",
        category: "missing_security_headers",
        title: "No baseline security headers configured",
        location: { ...SQLI.location, file: "next.config.js" },
      },
      {
        ...SQLI,
        id: "conf_redirect_0001",
        category: "open_redirect",
        title: "Open redirect via ?next=",
        location: { ...SQLI.location, file: "app/api/goto/route.ts" },
      },
    ];

    const out = await generateFixes(
      baseInput({ confirmed: findings, source: createMapSourceReader(files) }),
    );

    expect(out.fixes).toHaveLength(findings.length);
    for (const fix of out.fixes) {
      expect(fix.riskClass, fix.confirmedFindingId).toBe("auto-eligible");
      expect(fix.patch.length).toBeGreaterThan(0);
      expect(fix.proofOfFixTest.failsPrePatch).toBe(true);
      expect(fix.proofOfFixTest.passesPostPatch).toBe(true);
    }

    const nosqli = out.fixes.find((f) => f.confirmedFindingId === "conf_nosqli_0001")!;
    const nosqliCheck = await validatePatch(files["app/api/accounts/route.ts"]!, nosqli.patch, {
      filePath: "app/api/accounts/route.ts",
      proofTestCode: nosqli.proofOfFixTest.code,
    });
    expect(nosqliCheck.executionError).toBeUndefined();
    expect(nosqliCheck.applies).toBe(true);
    expect(nosqliCheck.passesPostPatch).toBe(true);
    expect(nosqliCheck.appliedSource).toContain("String(req.body.username)");

    const cookie = out.fixes.find((f) => f.confirmedFindingId === "conf_cookie_0001")!;
    const cookieCheck = await validatePatch(files["app/api/preferences/route.ts"]!, cookie.patch, {
      filePath: "app/api/preferences/route.ts",
      proofTestCode: cookie.proofOfFixTest.code,
    });
    expect(cookieCheck.executionError).toBeUndefined();
    expect(cookieCheck.applies).toBe(true);
    expect(cookieCheck.passesPostPatch).toBe(true);
    expect(cookieCheck.appliedSource).toContain("secure: true");
    expect(cookieCheck.appliedSource).toContain("httpOnly: true");

    const headers = out.fixes.find((f) => f.confirmedFindingId === "conf_headers_0001")!;
    const headersCheck = await validatePatch(files["next.config.js"]!, headers.patch, {
      filePath: "next.config.js",
      proofTestCode: headers.proofOfFixTest.code,
    });
    expect(headersCheck.executionError).toBeUndefined();
    expect(headersCheck.applies).toBe(true);
    expect(headersCheck.passesPostPatch).toBe(true);
    expect(headersCheck.appliedSource).toContain("Strict-Transport-Security");

    const redirect = out.fixes.find((f) => f.confirmedFindingId === "conf_redirect_0001")!;
    const redirectCheck = await validatePatch(files["app/api/goto/route.ts"]!, redirect.patch, {
      filePath: "app/api/goto/route.ts",
      proofTestCode: redirect.proofOfFixTest.code,
    });
    expect(redirectCheck.executionError).toBeUndefined();
    expect(redirectCheck.applies).toBe(true);
    expect(redirectCheck.passesPostPatch).toBe(true);
    expect(redirectCheck.appliedSource).toContain('.startsWith("/")');
  });
});
