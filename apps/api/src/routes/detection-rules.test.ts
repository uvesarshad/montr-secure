/**
 * Detection-rule push routes (suggested enhancement, 2026-09-12 red/blue
 * agentic-posture audit). Covers: approver-only target configuration, the
 * secret never leaking through the metadata GET, operator+approver push
 * access, the egress guard blocking an unallowlisted endpoint (and allowing
 * one added to `security.allowedEgressHosts`), and a push failure being
 * reported honestly (never silently swallowed) — end to end through the real
 * HTTP route. The transport itself is a fake `HecHttpClient` injected via
 * `ApiServerDeps.detectionRulePushHttpClient` (never a real `undici` call in
 * tests) — the Splunk HEC wire shape itself (headers, body, non-2xx/transport
 * failure handling) is exercised directly against `SplunkHecPusher` in
 * packages/report/src/detection-rules/push/splunk-hec.test.ts; this suite
 * proves the route plumbing: RBAC, config storage/encryption boundary,
 * egress enforcement, and audit wiring.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { DetectionRule } from "@montr/contracts";
import type { HecHttpClient } from "@montr/report";
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import { buildServer, createInMemoryDeps } from "../server.js";

const PASSWORD = "correct-horse-battery-staple";
const HEC_HOST = "splunk.example.internal";
const HEC_URL = `https://${HEC_HOST}:8088/services/collector/event`;

interface Session {
  token: string;
  id: string;
}

async function register(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver",
): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/register",
    payload: { email, password: PASSWORD, ...(role ? { role } : {}) },
  });
  return (res.json() as { user: { id: string } }).user.id;
}

async function login(app: FastifyInstance, email: string): Promise<Session> {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email, password: PASSWORD },
  });
  const body = res.json() as { token: string; user: { id: string } };
  return { token: body.token, id: body.user.id };
}

async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver",
): Promise<Session> {
  await register(app, email, role);
  return login(app, email);
}

const auth = (t: string) => ({ authorization: `Bearer ${t}` });

function configWithAllowedHost(): MontrConfig {
  return MontrConfigSchema.parse({ security: { allowedEgressHosts: [HEC_HOST] } });
}

function makeRule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    id: "detrule_1",
    clientId: "unused-overwritten-by-store",
    scanId: "scan_1",
    findingId: "cf_1",
    format: "siem_query",
    content: 'search index=web sourcetype=access_combined uri_query="*OR*1=1*"',
    mitreTechniques: ["T1190"],
    provenance: "static",
    createdAt: "2026-09-12T00:00:00.000Z",
    ...overrides,
  } as DetectionRule;
}

/** A fake `HecHttpClient` whose behavior each test controls via `.respond`/`.calls`. */
function fakeHecHttpClient() {
  const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
  let handler: HecHttpClient["request"] = async () => ({
    statusCode: 200,
    body: { text: async () => "ok" },
  });
  const client: HecHttpClient = {
    async request(url, init) {
      calls.push({ url, headers: init.headers, body: init.body });
      return handler(url, init);
    },
  };
  return {
    client,
    calls,
    respondWith(fn: HecHttpClient["request"]) {
      handler = fn;
    },
  };
}

describe("detection-rule push routes", () => {
  let app: FastifyInstance;
  let hec: ReturnType<typeof fakeHecHttpClient>;
  let approver: Session;
  let operator: Session;
  let viewer: Session;

  beforeEach(async () => {
    hec = fakeHecHttpClient();
    const deps = createInMemoryDeps({
      config: configWithAllowedHost(),
      detectionRulePushHttpClient: hec.client,
    });
    app = await buildServer(deps);
    // Requested role is honored ONLY for the first (bootstrap) user of a
    // client (apps/api/src/schemas.ts's RegisterBodySchema) — every
    // subsequent self-registration is forced to viewer, so operator/viewer
    // here are granted via the approver-only role-elevation route, exactly
    // like apps/api/src/routes/dast.test.ts's precedent.
    approver = await registerAndLogin(app, "approver@example.com", "approver");
    const operatorId = await register(app, "operator@example.com");
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/role",
      headers: auth(approver.token),
      payload: { userId: operatorId, role: "operator" },
    });
    operator = await login(app, "operator@example.com");
    viewer = await registerAndLogin(app, "viewer@example.com");
  });

  afterEach(async () => {
    await app.close();
  });

  it("refuses target configuration for anyone but an approver", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(operator.token),
      payload: { endpointUrl: HEC_URL, hecToken: "hec-token-abc" },
    });
    expect(res.statusCode).toBe(403);
  });

  it("lets an approver configure a push target, and GET never returns the token", async () => {
    const create = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(approver.token),
      payload: { endpointUrl: HEC_URL, hecToken: "hec-token-abc", index: "montr_detections" },
    });
    expect(create.statusCode).toBe(201);
    expect(create.body).not.toContain("hec-token-abc");

    const get = await app.inject({
      method: "GET",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(operator.token),
    });
    expect(get.statusCode).toBe(200);
    const body = get.json() as { target: { endpointUrl: string; index: string } };
    expect(body.target.endpointUrl).toBe(HEC_URL);
    expect(body.target.index).toBe("montr_detections");
    expect(get.body).not.toContain("hec-token-abc");
  });

  it("returns a clear conflict when pushing with no target configured", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push",
      headers: auth(operator.token),
      payload: { rule: makeRule() },
    });
    expect(res.statusCode).toBe(409);
    expect(hec.calls).toHaveLength(0);
  });

  it("blocks a push to a host not on the egress allowlist — an honest 403, not a silent no-op", async () => {
    await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(approver.token),
      payload: { endpointUrl: "https://not-allowlisted.example.com/collector", hecToken: "t" },
    });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push",
      headers: auth(operator.token),
      payload: { rule: makeRule() },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: { code: "EGRESS_BLOCKED" } });
    // The egress guard denies before the adapter ever dispatches.
    expect(hec.calls).toHaveLength(0);
  });

  it("pushes a rule successfully and records an audit event", async () => {
    await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(approver.token),
      payload: { endpointUrl: HEC_URL, hecToken: "hec-token-abc" },
    });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push",
      headers: auth(operator.token),
      payload: { rule: makeRule() },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { result: { success: boolean; statusCode: number } };
    expect(body.result.success).toBe(true);
    expect(body.result.statusCode).toBe(200);

    expect(hec.calls).toHaveLength(1);
    expect(hec.calls[0]!.url).toBe(HEC_URL);
    expect(hec.calls[0]!.headers.authorization).toBe("Splunk hec-token-abc");
    const sentEvent = JSON.parse(hec.calls[0]!.body) as { event: { ruleContent: string } };
    expect(sentEvent.event.ruleContent).toBe(makeRule().content);

    const audit = await app.inject({
      method: "GET",
      url: "/api/v1/audit/export?format=json",
      headers: auth(approver.token),
    });
    const events = audit.json() as Array<{ action: string }>;
    expect(events.some((e) => e.action === "detection_rule.pushed")).toBe(true);
  });

  it("reports a rejected push (e.g. bad HEC token) honestly — never a silent success", async () => {
    await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(approver.token),
      payload: { endpointUrl: HEC_URL, hecToken: "wrong-token" },
    });
    hec.respondWith(async () => ({
      statusCode: 401,
      body: { text: async () => '{"text":"Invalid token","code":4}' },
    }));

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push",
      headers: auth(operator.token),
      payload: { rule: makeRule() },
    });

    expect(res.statusCode).toBe(502);
    expect(res.json()).toMatchObject({ error: { code: "DETECTION_RULE_PUSH_FAILED" } });

    const audit = await app.inject({
      method: "GET",
      url: "/api/v1/audit/export?format=json",
      headers: auth(approver.token),
    });
    const events = audit.json() as Array<{ action: string }>;
    expect(events.some((e) => e.action === "detection_rule.push_failed")).toBe(true);
  });

  it("viewers can neither configure nor push", async () => {
    const configure = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(viewer.token),
      payload: { endpointUrl: HEC_URL, hecToken: "t" },
    });
    expect(configure.statusCode).toBe(403);

    const push = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push",
      headers: auth(viewer.token),
      payload: { rule: makeRule() },
    });
    expect(push.statusCode).toBe(403);
  });

  it("push-bundle reports per-rule results and never aborts on one failure", async () => {
    await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-targets",
      headers: auth(approver.token),
      payload: { endpointUrl: HEC_URL, hecToken: "hec-token-abc" },
    });

    let call = 0;
    hec.respondWith(async () => {
      call += 1;
      if (call === 1) return { statusCode: 200, body: { text: async () => "ok" } };
      return { statusCode: 500, body: { text: async () => "server error" } };
    });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/detection-rules/push-bundle",
      headers: auth(operator.token),
      payload: { rules: [makeRule({ id: "rule_a" }), makeRule({ id: "rule_b" })] },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { results: Array<{ ruleId: string; success: boolean }> };
    expect(body.results).toHaveLength(2);
    expect(body.results.find((r) => r.ruleId === "rule_a")?.success).toBe(true);
    expect(body.results.find((r) => r.ruleId === "rule_b")?.success).toBe(false);
    expect(hec.calls).toHaveLength(2);
  });
});
