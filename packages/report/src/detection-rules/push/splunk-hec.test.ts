/**
 * Splunk HEC push adapter tests (suggested-enhancement follow-up, 2026-09-12
 * red/blue agentic-posture audit). Proves against a FAKE HTTP endpoint (never
 * real network I/O):
 *   - the adapter sends the correct authenticated HEC event payload shape,
 *   - a non-2xx / transport failure is surfaced honestly, never swallowed,
 *   - the egress guard is asserted before every dispatch (and a denial stops
 *     the request from ever being sent),
 *   - the honest NotImplementedError stub for Elastic/Sentinel.
 */
import { describe, it, expect, vi } from "vitest";
import { DetectionRuleSchema, type DetectionRule } from "@montr/contracts";
import { buildHecEvent, SplunkHecPusher, type HecHttpClient } from "./splunk-hec.js";
import { createDetectionRulePusher } from "./index.js";
import type { DetectionRulePushTargetConfig, EgressGuardLike } from "./types.js";

function makeRule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return DetectionRuleSchema.parse({
    id: "detrule_1",
    clientId: "client_1",
    scanId: "scan_1",
    findingId: "cf_1",
    format: "siem_query",
    content: 'search index=web sourcetype=access_combined uri_query="*OR*1=1*"',
    mitreTechniques: ["T1190"],
    provenance: "static",
    createdAt: "2026-09-12T00:00:00.000Z",
    ...overrides,
  });
}

const TARGET: DetectionRulePushTargetConfig = {
  type: "splunk_hec",
  endpointUrl: "https://splunk.example.com:8088/services/collector/event",
  index: "montr_detections",
  sourcetype: "montr:detection_rule",
};

function allowGuard(): EgressGuardLike {
  return { assert: vi.fn(), isAllowed: vi.fn(() => true) };
}

function denyGuard(): EgressGuardLike {
  return {
    assert: vi.fn(() => {
      throw new Error("egress denied: host is not on the allowlist");
    }),
    isAllowed: vi.fn(() => false),
  };
}

describe("buildHecEvent", () => {
  it("carries the rule content and metadata under event, plus index/sourcetype/source", () => {
    const rule = makeRule();
    const event = buildHecEvent(rule, TARGET);
    expect(event).toMatchObject({
      index: "montr_detections",
      sourcetype: "montr:detection_rule",
      source: "montr-secure",
      event: {
        montrDetectionRuleId: "detrule_1",
        clientId: "client_1",
        scanId: "scan_1",
        findingId: "cf_1",
        format: "siem_query",
        provenance: "static",
        mitreTechniques: ["T1190"],
        ruleContent: rule.content,
        generatedAt: "2026-09-12T00:00:00.000Z",
      },
    });
  });

  it("omits index when the target carries none (Splunk HEC default index applies)", () => {
    const rule = makeRule();
    const event = buildHecEvent(rule, { ...TARGET, index: undefined });
    expect(event).not.toHaveProperty("index");
  });
});

describe("SplunkHecPusher.pushRule", () => {
  it("sends one authenticated POST with the Splunk HEC bearer scheme and the correct event body", async () => {
    const rule = makeRule();
    const requestSpy = vi.fn(async (url: string, init: Parameters<HecHttpClient["request"]>[1]) => {
      expect(url).toBe(TARGET.endpointUrl);
      expect(init.method).toBe("POST");
      expect(init.headers.authorization).toBe("Splunk hec-token-abc123");
      expect(init.headers["content-type"]).toBe("application/json");
      expect(JSON.parse(init.body)).toEqual(buildHecEvent(rule, TARGET));
      return { statusCode: 200, body: { text: async () => '{"text":"Success","code":0}' } };
    });
    const client: HecHttpClient = { request: requestSpy };
    const guard = allowGuard();

    const pusher = new SplunkHecPusher(client, () => "2026-09-12T00:00:01.000Z");
    const result = await pusher.pushRule(rule, TARGET, { token: "hec-token-abc123" }, guard);

    expect(requestSpy).toHaveBeenCalledTimes(1);
    expect(guard.assert).toHaveBeenCalledWith(TARGET.endpointUrl);
    expect(result).toEqual({
      success: true,
      targetType: "splunk_hec",
      ruleId: "detrule_1",
      statusCode: 200,
      message: "Rule delivered to Splunk HEC",
      pushedAt: "2026-09-12T00:00:01.000Z",
    });
  });

  it("never silently swallows a non-2xx response — reports failure honestly with the status and body", async () => {
    const rule = makeRule();
    const client: HecHttpClient = {
      request: vi.fn(async () => ({
        statusCode: 401,
        body: { text: async () => '{"text":"Invalid token","code":4}' },
      })),
    };
    const pusher = new SplunkHecPusher(client, () => "2026-09-12T00:00:02.000Z");

    const result = await pusher.pushRule(rule, TARGET, { token: "bad" }, allowGuard());

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
    expect(result.message).toContain("HTTP 401");
    expect(result.message).toContain("Invalid token");
  });

  it("never silently swallows a transport-level failure (network error)", async () => {
    const rule = makeRule();
    const client: HecHttpClient = {
      request: vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    };
    const pusher = new SplunkHecPusher(client);

    const result = await pusher.pushRule(rule, TARGET, { token: "t" }, allowGuard());

    expect(result.success).toBe(false);
    expect(result.message).toContain("ECONNREFUSED");
  });

  it("asserts the egress guard before dispatching, and a denial stops the request from ever being sent", async () => {
    const rule = makeRule();
    const requestSpy = vi.fn();
    const client: HecHttpClient = { request: requestSpy };
    const pusher = new SplunkHecPusher(client);

    await expect(pusher.pushRule(rule, TARGET, { token: "t" }, denyGuard())).rejects.toThrow(
      /egress denied/,
    );
    expect(requestSpy).not.toHaveBeenCalled();
  });
});

describe("createDetectionRulePusher", () => {
  it("returns a real SplunkHecPusher for 'splunk_hec'", () => {
    const pusher = createDetectionRulePusher("splunk_hec");
    expect(pusher.type).toBe("splunk_hec");
    expect(pusher).toBeInstanceOf(SplunkHecPusher);
  });

  it.each(["elastic", "sentinel"] as const)(
    "throws NotImplementedError for the honestly-unimplemented '%s' target — never a fake success",
    async (type) => {
      const pusher = createDetectionRulePusher(type);
      expect(pusher.type).toBe(type);
      await expect(
        pusher.pushRule(
          makeRule(),
          { type, endpointUrl: "https://example.com" },
          { token: "t" },
          allowGuard(),
        ),
      ).rejects.toMatchObject({ name: "NotImplementedError" });
    },
  );
});
