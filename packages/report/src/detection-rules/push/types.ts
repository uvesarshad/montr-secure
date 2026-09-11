/**
 * Detection-rule PUSH integrations (suggested enhancement, 2026-09-12
 * red/blue agentic-posture audit's "Suggested enhancements" section: "ship
 * detection rules as a real push integration (Splunk, Elastic, Sentinel)
 * rather than only a download, converting an advisory artifact into a
 * surface a SOC team touches weekly"). Until now, generated Sigma/OTel/SIEM
 * rules (packages/report/src/detection-rules, B3/B4) only ever left the
 * process as a browser download (apps/web/src/lib/exports.ts's
 * `downloadDetectionRule`/`downloadDetectionRuleBundle`, B11/A5) — nothing
 * pushed them anywhere. This module is that push path.
 *
 * PROVIDER-AGNOSTIC CONTRACT ({@link DetectionRulePusher}) so a second real
 * adapter (Elastic, Sentinel) can be added later without redesigning this
 * interface. Deliberately scoped like A9's `EmbeddingProviderAdapter`/
 * `createEmbeddingAdapter` matrix (packages/llm-gateway/src/embeddings.ts):
 * ONE real, fully-implemented, tested adapter (Splunk HTTP Event Collector —
 * see ./splunk-hec.ts) plus an honest `NotImplementedError` stub (./index.ts)
 * for every unimplemented target. Never a fake adapter that silently no-ops
 * or claims success it didn't earn.
 *
 * ⛔ EGRESS: every {@link DetectionRulePusher.pushRule} implementation takes
 * a REQUIRED (never defaulted-internally) {@link EgressGuardLike} from its
 * caller — the identical required-parameter convention
 * `packages/confirm/src/guard.ts`'s `ScopeGuardOptions.egressGuard` already
 * uses, so this package (@montr/report) never grows a hard dependency on
 * @montr/security, and a caller can never accidentally forget to pass one.
 * apps/api's push route builds the real guard via `createEgressGuard(config)`
 * (@montr/security is already a direct dependency there) and passes it in.
 *
 * Because a push target's endpoint is an OPERATOR-ENTERED value (not a fixed
 * provider host baked into this codebase, unlike the LLM providers
 * `packages/security/src/egress-guard.ts`'s `PROVIDER_DEFAULT_HOSTS` knows
 * about), the egress guard only allows it through when the operator has ALSO
 * added that host to the existing `MONTR_ALLOWED_EGRESS_HOSTS` env var
 * (docs/infra/environment.md — already consumed by @montr/security, already
 * documented as "additional outbound network hosts permitted by the egress
 * firewall"). This is a deliberate choice, not an accident: this codebase's
 * two other real outbound, operator-configured third-party integrations —
 * GitHub/GitLab PR posting (packages/report/src/vcs.ts) and the scan-trigger
 * webhook's PR-comment call (apps/api/src/routes/webhooks.ts, both via
 * `postGitHubComment`) — do NOT route through the egress guard at all; it is
 * scoped (see egress-guard.ts's own header) to "the configured client LLM
 * endpoint (plus any explicitly operator-approved infra host)", and VCS/
 * webhook calls predate this feature's use of that "explicitly
 * operator-approved infra host" allowance. A detection-rule push target is a
 * NEW class of outbound, credentialed destination (unlike a fixed VCS SaaS
 * host, it is entirely operator-defined — anywhere the operator's own Splunk
 * instance happens to live), so this module opts into the stricter,
 * already-provisioned default-deny mechanism rather than following the
 * looser VCS/webhook precedent — see docs/modules/reporting-vcs.md for the
 * full rationale. No new bypass path is introduced.
 */
import type { DetectionRule } from "@montr/contracts";

/** Structural subset of @montr/security's `EgressGuard` — mirrors packages/confirm/src/types.ts's `EgressGuardLike` precedent exactly (kept local so this package never depends on @montr/security). */
export interface EgressGuardLike {
  assert(target: string): void;
  isAllowed(target: string): boolean;
}

/** Push targets this module can genuinely deliver to today. */
export const IMPLEMENTED_PUSH_TARGET_TYPES = ["splunk_hec"] as const;
export type ImplementedDetectionRulePushTargetType = (typeof IMPLEMENTED_PUSH_TARGET_TYPES)[number];

/**
 * ⛔ HONEST SCOPE: Elastic and Sentinel are NOT implemented. Listed here only
 * so `createDetectionRulePusher` (./index.ts) can name them explicitly in a
 * `NotImplementedError` rather than silently mis-routing an unrecognised
 * string to the wrong adapter. Real follow-up scope for each (not built
 * here, exactly as A9's embeddings adapter precedent documents for its own
 * unimplemented providers — each is a genuinely different wire protocol, not
 * a copy-paste of splunk-hec.ts):
 *   - "elastic": Kibana's Detection Engine API
 *     (`PUT /api/detection_engine/rules`), authenticated by an Elastic API
 *     key, with its own JSON rule schema (query/KQL/EQL-typed rules, not a
 *     single opaque string) — a real rule-authoring API, not an event
 *     ingest, so it is not a drop-in swap for HEC's single-POST model.
 *   - "sentinel": an Azure Sentinel scheduled analytics-rule ARM/REST call
 *     (`PUT .../providers/Microsoft.SecurityInsights/alertRules/{id}`),
 *     credentialed by an Azure AD app registration (client id/secret/tenant
 *     + OAuth2 token exchange), a materially different auth model from a
 *     single bearer token.
 */
export const UNIMPLEMENTED_PUSH_TARGET_TYPES = ["elastic", "sentinel"] as const;

export type DetectionRulePushTargetType =
  ImplementedDetectionRulePushTargetType | (typeof UNIMPLEMENTED_PUSH_TARGET_TYPES)[number];

/** Non-secret target configuration — what's stored and returned as metadata (never the credential). */
export interface DetectionRulePushTargetConfig {
  type: DetectionRulePushTargetType;
  /** Full collector/ingest URL, e.g. https://splunk.example.com:8088/services/collector/event */
  endpointUrl: string;
  /** Optional Splunk index override. */
  index?: string;
  /** Optional Splunk sourcetype override (default: "montr:detection_rule"). */
  sourcetype?: string;
}

/** Secret material, kept structurally separate from the config above so it can never be accidentally logged or returned as metadata. */
export interface DetectionRulePushCredential {
  /** Plaintext token for this call. NEVER log this value. */
  token: string;
}

export interface DetectionRulePushResult {
  success: boolean;
  targetType: DetectionRulePushTargetType;
  /** The rule that was (attempted to be) pushed. */
  ruleId: string;
  statusCode?: number;
  /** Human-readable outcome — on failure, the REAL reason, never swallowed. */
  message: string;
  pushedAt: string;
}

export interface DetectionRulePusher {
  readonly type: DetectionRulePushTargetType;
  pushRule(
    rule: DetectionRule,
    target: DetectionRulePushTargetConfig,
    credential: DetectionRulePushCredential,
    egress: EgressGuardLike,
    signal?: AbortSignal,
  ): Promise<DetectionRulePushResult>;
}
