/**
 * Splunk HTTP Event Collector (HEC) push adapter — the one real,
 * fully-working detection-rule push integration this module ships (see
 * ./types.ts's header for why Elastic/Sentinel are honest stubs, not this
 * file).
 *
 * DELIVERY MODEL: a single authenticated HTTPS POST per rule, carrying one
 * HEC event. Auth is HEC's own scheme — `Authorization: Splunk <token>`, a
 * bearer token minted in Splunk's Data Inputs > HTTP Event Collector UI, NOT
 * this platform's LLM/DAST credentials (a structurally distinct secret —
 * see {@link DetectionRulePushCredential}). The rule's already-generated SPL
 * content (packages/report/src/detection-rules/siem.ts's `buildSiemQuery`,
 * `DetectionRule.format === "siem_query"`) travels as the event's
 * `event.ruleContent` field alongside structured metadata (finding id,
 * format, provenance, MITRE techniques, the B4 log signature) — this indexes
 * the rule as a searchable, alertable event inside Splunk itself, which is
 * genuinely "a surface a SOC team touches weekly" (this task's framing). It
 * is deliberately a different — and simpler, single-POST — delivery model
 * than authoring a saved Correlation Search via Splunk's separate
 * `services/saved/searches` REST API, which would let the rule auto-fire
 * inside Splunk on its own schedule; that is a real, documented follow-up
 * (see docs/modules/reporting-vcs.md), not built here.
 *
 * TRANSPORT: the SAME lazily-imported `undici` `request` function
 * `packages/confirm/src/live.ts`'s `defaultTransport` (reused by
 * `packages/confirm/src/purple-loop.ts`) already uses for outbound HTTP — no
 * new HTTP client dependency, same lazy-import convention as every other
 * outbound SDK call in this codebase (`packages/report/src/vcs.ts`'s lazy
 * Octokit/gitbeaker imports).
 */
import type { DetectionRule } from "@montr/contracts";
import type {
  DetectionRulePushCredential,
  DetectionRulePushResult,
  DetectionRulePushTargetConfig,
  DetectionRulePusher,
  EgressGuardLike,
} from "./types.js";

const DEFAULT_SOURCETYPE = "montr:detection_rule";
const DEFAULT_SOURCE = "montr-secure";
const RESPONSE_SNIPPET_MAX = 300;

/** Minimal `undici`-`request`-shaped HTTP client this adapter needs (injectable for tests — never real network I/O in offline test runs). */
export interface HecHttpClient {
  request(
    url: string,
    init: {
      method: "POST";
      headers: Record<string, string>;
      body: string;
      signal?: AbortSignal;
    },
  ): Promise<{ statusCode: number; body: { text(): Promise<string> } }>;
}

async function defaultHecHttpClient(): Promise<HecHttpClient> {
  const { request } = await import("undici");
  return {
    async request(url, init) {
      const res = await request(url, {
        method: init.method,
        headers: init.headers,
        body: init.body,
        ...(init.signal ? { signal: init.signal } : {}),
      });
      return { statusCode: res.statusCode, body: { text: () => res.body.text() } };
    },
  };
}

/** Build the HEC event payload for one rule. Exported so tests can assert the exact wire shape without duplicating it. */
export function buildHecEvent(
  rule: DetectionRule,
  target: DetectionRulePushTargetConfig,
): Record<string, unknown> {
  return {
    ...(target.index ? { index: target.index } : {}),
    sourcetype: target.sourcetype ?? DEFAULT_SOURCETYPE,
    source: DEFAULT_SOURCE,
    event: {
      montrDetectionRuleId: rule.id,
      clientId: rule.clientId,
      scanId: rule.scanId,
      findingId: rule.findingId,
      format: rule.format,
      provenance: rule.provenance,
      mitreTechniques: rule.mitreTechniques,
      ruleContent: rule.content,
      logSignature: rule.logSignature ?? null,
      generatedAt: rule.createdAt,
    },
  };
}

function truncate(s: string, n = RESPONSE_SNIPPET_MAX): string {
  return s.length > n ? `${s.slice(0, n)}…[truncated ${s.length - n} chars]` : s;
}

export class SplunkHecPusher implements DetectionRulePusher {
  readonly type = "splunk_hec" as const;

  constructor(
    private readonly httpClient?: HecHttpClient,
    private readonly clock: () => string = () => new Date().toISOString(),
  ) {}

  async pushRule(
    rule: DetectionRule,
    target: DetectionRulePushTargetConfig,
    credential: DetectionRulePushCredential,
    egress: EgressGuardLike,
    signal?: AbortSignal,
  ): Promise<DetectionRulePushResult> {
    if (target.type !== "splunk_hec") {
      throw new Error(`SplunkHecPusher cannot handle target type '${target.type}'`);
    }

    // ⛔ Egress guard — asserted immediately before dispatch, exactly like
    // every other outbound adapter in this codebase (packages/llm-gateway's
    // provider adapters, packages/confirm's ScopeGuard). Throws
    // EgressBlockedError (never caught here) when the operator has not
    // explicitly allowlisted this host — see ./types.ts's header.
    egress.assert(target.endpointUrl);

    const client = this.httpClient ?? (await defaultHecHttpClient());
    const body = JSON.stringify(buildHecEvent(rule, target));

    let res: { statusCode: number; body: { text(): Promise<string> } };
    try {
      res = await client.request(target.endpointUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // HEC's own auth scheme — NOT this platform's LLM/DAST
          // credentials. Never logged (the credential object never appears
          // in a log call anywhere in this file).
          authorization: `Splunk ${credential.token}`,
        },
        body,
        ...(signal ? { signal } : {}),
      });
    } catch (err) {
      // Never silently swallow a transport failure — surface it honestly so
      // the caller (apps/api's push route) can audit-log and report it.
      return {
        success: false,
        targetType: "splunk_hec",
        ruleId: rule.id,
        message: `Splunk HEC request failed: ${err instanceof Error ? err.message : String(err)}`,
        pushedAt: this.clock(),
      };
    }

    const responseText = await res.body.text().catch(() => "");
    if (res.statusCode < 200 || res.statusCode >= 300) {
      return {
        success: false,
        targetType: "splunk_hec",
        ruleId: rule.id,
        statusCode: res.statusCode,
        message: `Splunk HEC rejected the event (HTTP ${res.statusCode}): ${truncate(responseText)}`,
        pushedAt: this.clock(),
      };
    }

    return {
      success: true,
      targetType: "splunk_hec",
      ruleId: rule.id,
      statusCode: res.statusCode,
      message: "Rule delivered to Splunk HEC",
      pushedAt: this.clock(),
    };
  }
}
