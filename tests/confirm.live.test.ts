import { describe, it, expect } from "vitest";
import { KillSwitchActivatedError, type AuditEventInput } from "@montr/contracts";
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import { mockAppMap, mockProbableFindings, CLIENT_ID, SCAN_ID, FIXED_NOW } from "@montr/fixtures";
import {
  confirmFindings,
  type AuditSink,
  type BrowserDriver,
  type ConfirmDeps,
  type ConfirmInput,
  type LiveHttpTransport,
} from "@montr/confirm";
import { createEgressGuard } from "../packages/security/src/egress-guard";

/**
 * WS-H Layer-3b LIVE DAST (build-plan §5.4). Crafted, non-destructive probes at
 * an approver-authorized, allowlisted staging target; the request/response
 * transcript is the proof. Fully OFFLINE — HTTP + browser are mocked; guardrails
 * (egress, kill switch, allowlist) are the REAL ones.
 */

const STAGING = "https://staging.example.internal";
const SQLI = mockProbableFindings[0]!; // rank 1, sql_injection, public /api/users
const XSS = mockProbableFindings[1]!; // rank 2, xss, public /search

function liveConfig(overrides: Record<string, unknown> = {}): MontrConfig {
  return MontrConfigSchema.parse({ dast: { enabled: true, allowlist: [STAGING], ...overrides } });
}

/** Mutating-method (POST/PUT/PATCH/DELETE) blast-radius cap defaults to 0 — an
 * operator must explicitly raise it, which is what XXE/deserialization probes
 * (the only two categories that must POST a body) require in these tests. */
function mutatingConfig(): MontrConfig {
  return liveConfig({ scope: { maxMutatingRequests: 5 } });
}

function realEgress(config: MontrConfig) {
  return createEgressGuard(config, { includeDastTargets: true });
}

function recordingAudit(): { sink: AuditSink; events: AuditEventInput[] } {
  const events: AuditEventInput[] = [];
  return {
    sink: {
      append(e: AuditEventInput) {
        events.push(e);
        return Promise.resolve({});
      },
    },
    events,
  };
}

function liveInput(overrides: Partial<ConfirmInput> = {}): ConfirmInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    appMap: mockAppMap,
    probable: [SQLI],
    allowLive: true,
    stagingUrl: STAGING,
    config: liveConfig(),
    ...overrides,
  };
}

function offlineDeps(extra: ConfirmDeps): ConfirmDeps {
  return {
    egressGuard: realEgress(liveConfig()),
    now: () => FIXED_NOW,
    clockMs: () => 0,
    sleep: () => Promise.resolve(),
    ...extra,
  };
}

describe("confirmFindings — live DAST confirmation", () => {
  it("confirms SQLi live and captures the request/response transcript as proof", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.url.includes("montr_baseline")) {
          return Promise.resolve({ status: 200, headers: {}, body: '[{"id":1}]' });
        }
        return Promise.resolve({
          status: 200,
          headers: {},
          body: '[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5},{"id":6}] — all rows returned',
        });
      },
    };
    const rec = recordingAudit();
    const out = await confirmFindings(liveInput(), offlineDeps({ transport, audit: rec.sink }));

    expect(out.confirmed).toHaveLength(1);
    const f = out.confirmed[0]!;
    expect(f.proofType).toBe("live");
    if (f.proofArtifact.kind !== "live") throw new Error("expected live proof");
    expect(f.proofArtifact.target).toBe(STAGING);
    expect(f.proofArtifact.transcript).toHaveLength(2); // baseline + payload
    expect(f.proofArtifact.transcript[1]?.response.status).toBe(200);
    expect(f.proofArtifact.transcript[1]?.response.bodySnippet).toBeTruthy();

    const actions = rec.events.map((e) => e.action);
    expect(actions).toContain("dast.authorized");
    expect(actions.filter((a) => a === "dast.probe")).toHaveLength(2);
    expect(actions).toContain("finding.confirmed");

    // ⛔ probe audit metadata is metadata-only (no request/response bodies).
    const probe = rec.events.find((e) => e.action === "dast.probe");
    expect(probe?.metadata).toMatchObject({ method: "GET", status: 200 });
    expect(JSON.stringify(probe?.metadata)).not.toMatch(/id":1|all rows/);
  });

  it("confirms reflected XSS live when the payload is reflected unescaped", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        const q = new URL(req.url).searchParams.get("q") ?? "";
        return Promise.resolve({
          status: 200,
          headers: { "content-type": "text/html" },
          body: `<html><body><div>${q}</div></body></html>`,
        });
      },
    };
    const out = await confirmFindings(liveInput({ probable: [XSS] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
  });

  it("falls back to the STATIC proof when the XSS payload is HTML-escaped (not exploitable live)", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        const q = new URL(req.url).searchParams.get("q") ?? "";
        const escaped = q.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        return Promise.resolve({ status: 200, headers: {}, body: `<div>${escaped}</div>` });
      },
    };
    const out = await confirmFindings(liveInput({ probable: [XSS] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("static"); // live failed → static stands
  });

  it("falls back to the STATIC proof when SQLi probes yield no injection signal", async () => {
    const transport: LiveHttpTransport = {
      send: () => Promise.resolve({ status: 200, headers: {}, body: "[]" }),
    };
    const out = await confirmFindings(liveInput(), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("static");
  });
});

describe("confirmFindings — A9: NoSQL operator payload (fixed)", () => {
  it("confirms NoSQL injection via a real $ne bracket-notation operator payload, not a SQL string", async () => {
    let payloadUrl = "";
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.url.includes("montr_baseline")) {
          return Promise.resolve({ status: 200, headers: {}, body: "[]" });
        }
        payloadUrl = req.url;
        return Promise.resolve({
          status: 200,
          headers: {},
          body: '[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5},{"id":6}] — every document returned',
        });
      },
    };
    const nosqli = structuredClone(SQLI);
    nosqli.category = "nosql_injection";
    const out = await confirmFindings(
      liveInput({ probable: [nosqli] }),
      offlineDeps({ transport }),
    );

    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
    // The payload must be a Mongo/NoSQL OPERATOR (bracket-notation `[$ne]`), never
    // the SQL string `' OR '1'='1` the old (buggy) implementation reused.
    expect(payloadUrl).toMatch(/%5B%24ne%5D|\[\$ne\]/);
    expect(payloadUrl).not.toContain("1%3D%271"); // no SQL boolean payload present
  });

  it("falls back to STATIC when the NoSQL operator payload yields no injection signal", async () => {
    const transport: LiveHttpTransport = {
      send: () => Promise.resolve({ status: 200, headers: {}, body: "[]" }),
    };
    const nosqli = structuredClone(SQLI);
    nosqli.category = "nosql_injection";
    const out = await confirmFindings(
      liveInput({ probable: [nosqli] }),
      offlineDeps({ transport }),
    );
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("static"); // live failed → static proof stands
  });
});

describe("confirmFindings — A9: expanded live DAST categories", () => {
  it("confirms SSRF when the response leaks cloud-metadata contents", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.url.includes("example.com")) {
          return Promise.resolve({ status: 200, headers: {}, body: "ok" });
        }
        return Promise.resolve({
          status: 200,
          headers: {},
          body: '{"ami-id":"ami-0123","instance-id":"i-0123"}',
        });
      },
    };
    const ssrf = structuredClone(SQLI);
    ssrf.category = "ssrf";
    const out = await confirmFindings(liveInput({ probable: [ssrf] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
  });

  it("does NOT confirm SSRF when the response carries no metadata-service signal", async () => {
    const transport: LiveHttpTransport = {
      send: () => Promise.resolve({ status: 200, headers: {}, body: "no such host" }),
    };
    const ssrf = structuredClone(SQLI);
    ssrf.category = "ssrf";
    const out = await confirmFindings(liveInput({ probable: [ssrf] }), offlineDeps({ transport }));
    // No static sink for ssrf on this fixture either, so the finding stays unconfirmed.
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
  });

  it("confirms IDOR when a different resource id returns distinct, non-denied data", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        const q = new URL(req.url).searchParams.get("q");
        return Promise.resolve({
          status: 200,
          headers: {},
          body: q === "1" ? '{"id":1,"owner":"alice"}' : '{"id":2,"owner":"bob"}',
        });
      },
    };
    const idor = structuredClone(SQLI);
    idor.category = "idor";
    const out = await confirmFindings(liveInput({ probable: [idor] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
  });

  it("does NOT confirm IDOR when the other resource id is denied", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        const q = new URL(req.url).searchParams.get("q");
        return Promise.resolve({
          status: q === "1" ? 200 : 403,
          headers: {},
          body: q === "1" ? '{"id":1,"owner":"alice"}' : "forbidden",
        });
      },
    };
    const idor = structuredClone(SQLI);
    idor.category = "idor";
    const out = await confirmFindings(liveInput({ probable: [idor] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
  });

  it("confirms broken access control when the route succeeds without auth headers", async () => {
    const authedMap = structuredClone(mockAppMap);
    authedMap.routes[0]!.authState = "authenticated";
    const bac = structuredClone(SQLI);
    bac.category = "broken_access_control";
    bac.exposure = "authed";
    const browser: BrowserDriver = {
      login: () => Promise.resolve({ headers: { cookie: "session=abc" } }),
    };
    const transport: LiveHttpTransport = {
      send: () => Promise.resolve({ status: 200, headers: {}, body: "ok" }), // succeeds either way
    };
    const out = await confirmFindings(
      liveInput({ appMap: authedMap, probable: [bac] }),
      offlineDeps({ transport, browser }),
    );
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
  });

  it("does NOT confirm broken access control when the stripped request is denied", async () => {
    const authedMap = structuredClone(mockAppMap);
    authedMap.routes[0]!.authState = "authenticated";
    const bac = structuredClone(SQLI);
    bac.category = "broken_access_control";
    bac.exposure = "authed";
    const browser: BrowserDriver = {
      login: () => Promise.resolve({ headers: { cookie: "session=abc" } }),
    };
    const transport: LiveHttpTransport = {
      send(req) {
        const hasCookie = Boolean(req.headers?.cookie);
        return Promise.resolve({ status: hasCookie ? 200 : 401, headers: {}, body: "x" });
      },
    };
    const out = await confirmFindings(
      liveInput({ appMap: authedMap, probable: [bac] }),
      offlineDeps({ transport, browser }),
    );
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
  });

  it("skips broken-access-control probing entirely when the route has no session to strip", async () => {
    const bac = structuredClone(SQLI); // ROUTE_USERS_ID is public — no session obtained
    bac.category = "broken_access_control";
    let sends = 0;
    const transport: LiveHttpTransport = {
      send() {
        sends += 1;
        return Promise.resolve({ status: 200, headers: {}, body: "x" });
      },
    };
    const out = await confirmFindings(liveInput({ probable: [bac] }), offlineDeps({ transport }));
    expect(sends).toBe(0);
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
  });

  it("confirms path traversal when the payload discloses /etc/passwd contents", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.url.includes("readme.txt")) {
          return Promise.resolve({ status: 200, headers: {}, body: "hello" });
        }
        return Promise.resolve({
          status: 200,
          headers: {},
          body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        });
      },
    };
    const pt = structuredClone(SQLI);
    pt.category = "path_traversal";
    const out = await confirmFindings(liveInput({ probable: [pt] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
  });

  it("confirms command injection when the injected marker is reflected in the response", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        // The shell "executed" the chained command and echoed its output back —
        // simulated here by reflecting the decoded `q` param, which carries the
        // unique marker embedded in the payload.
        const q = new URL(req.url).searchParams.get("q") ?? "";
        return Promise.resolve({ status: 200, headers: {}, body: `output: ${q}` });
      },
    };
    const ci = structuredClone(SQLI);
    ci.category = "command_injection";
    const out = await confirmFindings(liveInput({ probable: [ci] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
  });

  it("confirms XXE via a POST body carrying an external entity, and discloses /etc/passwd", async () => {
    let sawEntity = false;
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.body?.includes("<!ENTITY")) {
          sawEntity = true;
          return Promise.resolve({
            status: 200,
            headers: {},
            body: "root:x:0:0:root:/root:/bin/bash",
          });
        }
        return Promise.resolve({
          status: 200,
          headers: {},
          body: "<root><value>montr_baseline</value></root>",
        });
      },
    };
    const xxe = structuredClone(SQLI);
    xxe.category = "xxe";
    // XXE is delivered via POST (a mutating method) — the blast-radius cap on
    // mutating requests defaults to 0 (see `packages/config/src/schema.ts`), so a
    // real deployment must opt in. Raise it here the same way an operator would.
    const out = await confirmFindings(
      liveInput({ probable: [xxe], config: mutatingConfig() }),
      offlineDeps({ transport }),
    );
    expect(sawEntity).toBe(true);
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
    if (out.confirmed[0]?.proofArtifact.kind !== "live") throw new Error("expected live proof");
    expect(out.confirmed[0]?.proofArtifact.transcript[1]?.request.method).toBe("POST");
    expect(out.confirmed[0]?.proofArtifact.transcript[1]?.request.bodySnippet).toContain(
      "<!ENTITY",
    );
  });

  it("confirms insecure deserialization when a malformed typed payload triggers a deserializer error", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.body?.includes("@type")) {
          return Promise.resolve({
            status: 500,
            headers: {},
            body: "com.fasterxml.jackson.databind.exc.InvalidClassException: unknown type",
          });
        }
        return Promise.resolve({ status: 200, headers: {}, body: "{}" });
      },
    };
    const deser = structuredClone(SQLI);
    deser.category = "insecure_deserialization";
    const out = await confirmFindings(
      liveInput({ probable: [deser], config: mutatingConfig() }),
      offlineDeps({ transport }),
    );
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
    if (out.confirmed[0]?.proofArtifact.kind !== "live") throw new Error("expected live proof");
    expect(out.confirmed[0]?.proofArtifact.transcript[1]?.request.method).toBe("POST");
  });

  it("does NOT confirm insecure deserialization when the response shows no deserializer signal", async () => {
    const transport: LiveHttpTransport = {
      send: () => Promise.resolve({ status: 200, headers: {}, body: "{}" }),
    };
    const deser = structuredClone(SQLI);
    deser.category = "insecure_deserialization";
    const out = await confirmFindings(
      liveInput({ probable: [deser], config: mutatingConfig() }),
      offlineDeps({ transport }),
    );
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
  });
});

describe("confirmFindings — A7: successful live-DAST proof is executable evidence", () => {
  it("promotes to confirmed:true on a successful live probe even though the LLM veto path never ran", async () => {
    const transport: LiveHttpTransport = {
      send(req) {
        if (req.url.includes("montr_baseline")) {
          return Promise.resolve({ status: 200, headers: {}, body: "[]" });
        }
        return Promise.resolve({ status: 200, headers: {}, body: "sql syntax error near '1'" });
      },
    };
    const out = await confirmFindings(liveInput(), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.status).toBe("confirmed");
    expect(out.confirmed[0]?.proofType).toBe("live");
    expect(out.confirmed[0]?.proofArtifact.kind).toBe("live");
  });

  it("a failed live probe never promotes on its own — the finding stays unconfirmed when static also fails", async () => {
    const ssrf = structuredClone(SQLI); // no static sink for ssrf in this fixture
    ssrf.category = "ssrf";
    const transport: LiveHttpTransport = {
      send: () => Promise.resolve({ status: 200, headers: {}, body: "nothing interesting here" }),
    };
    const out = await confirmFindings(liveInput({ probable: [ssrf] }), offlineDeps({ transport }));
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
    expect(out.unconfirmed[0]?.status).toBe("unconfirmed");
  });
});

describe("confirmFindings — ⛔ live DAST kill switch", () => {
  it("halts all probing instantly and audits the kill", async () => {
    const controller = new AbortController();
    let sends = 0;
    const transport: LiveHttpTransport = {
      send() {
        sends += 1;
        controller.abort(new KillSwitchActivatedError("kill mid-probe"));
        return Promise.reject(controller.signal.reason as Error);
      },
    };
    const rec = recordingAudit();

    await expect(
      confirmFindings(
        liveInput(),
        offlineDeps({ transport, audit: rec.sink, signal: controller.signal }),
      ),
    ).rejects.toThrow(KillSwitchActivatedError);

    expect(sends).toBe(1); // stopped after the first probe — no further requests
    expect(rec.events.map((e) => e.action)).toContain("dast.kill_switch");
  });
});

describe("confirmFindings — ⛔ production target is never probed", () => {
  it("refuses live authorization and degrades to static-only (no requests fired)", async () => {
    const prod = liveConfig({ allowlist: ["https://www.acme-prod.com"] });
    let sends = 0;
    const transport: LiveHttpTransport = {
      send() {
        sends += 1;
        return Promise.resolve({ status: 200, headers: {}, body: "x" });
      },
    };
    const warns: string[] = [];
    const rec = recordingAudit();

    const out = await confirmFindings(
      {
        clientId: CLIENT_ID,
        scanId: SCAN_ID,
        appMap: mockAppMap,
        probable: mockProbableFindings,
        allowLive: true,
        stagingUrl: "https://www.acme-prod.com",
        config: prod,
      },
      {
        transport,
        egressGuard: realEgress(prod),
        now: () => FIXED_NOW,
        audit: rec.sink,
        logger: {
          info() {},
          warn(m) {
            warns.push(m);
          },
          error() {},
        },
      },
    );

    expect(sends).toBe(0); // ⛔ production target never contacted
    expect(out.confirmed).toHaveLength(2);
    expect(out.confirmed.every((c) => c.proofType === "static")).toBe(true);
    expect(rec.events.map((e) => e.action)).not.toContain("dast.authorized");
    expect(warns.some((w) => /not authorized|static-only/i.test(w))).toBe(true);
  });
});

describe("confirmFindings — authenticated live flow", () => {
  it("uses the browser driver to obtain a session and carries it into probes", async () => {
    const authedMap = structuredClone(mockAppMap);
    authedMap.routes[0]!.authState = "authenticated";
    authedMap.routes[0]!.authGate = "requireSession";
    const authedProbable = structuredClone(SQLI);
    authedProbable.exposure = "authed";

    let loginCalls = 0;
    const browser: BrowserDriver = {
      login() {
        loginCalls += 1;
        return Promise.resolve({ cookies: { session: "abc" }, headers: { cookie: "session=abc" } });
      },
    };
    let capturedCookie: string | undefined;
    const transport: LiveHttpTransport = {
      send(req) {
        capturedCookie = req.headers?.cookie;
        if (req.url.includes("montr_baseline")) {
          return Promise.resolve({ status: 200, headers: {}, body: '[{"id":1}]' });
        }
        return Promise.resolve({
          status: 200,
          headers: {},
          body: '[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5}] more rows returned here',
        });
      },
    };

    const out = await confirmFindings(
      liveInput({ appMap: authedMap, probable: [authedProbable] }),
      offlineDeps({ transport, browser }),
    );

    expect(loginCalls).toBe(1);
    expect(capturedCookie).toBe("session=abc");
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("live");
    expect(out.confirmed[0]?.exposure).toBe("authed");
  });

  it("keeps the static proof when the browser session is unavailable for an authed route", async () => {
    const authedMap = structuredClone(mockAppMap);
    authedMap.routes[0]!.authState = "authenticated";
    const authedProbable = structuredClone(SQLI);
    authedProbable.exposure = "authed";

    // Browser login fails (e.g. playwright unavailable) ⇒ live probe skipped, static stands.
    const browser: BrowserDriver = {
      login: () => Promise.reject(new Error("playwright-core is not available")),
    };
    let sends = 0;
    const transport: LiveHttpTransport = {
      send() {
        sends += 1;
        return Promise.resolve({ status: 200, headers: {}, body: "[]" });
      },
    };
    const out = await confirmFindings(
      liveInput({ appMap: authedMap, probable: [authedProbable] }),
      offlineDeps({ transport, browser }),
    );
    expect(sends).toBe(0); // no probe fired without a session
    expect(out.confirmed).toHaveLength(1);
    expect(out.confirmed[0]?.proofType).toBe("static");
  });
});
