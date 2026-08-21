/**
 * B4 — "what this looks like in your logs" narrative. Human-readable
 * companion to B3's generated rule content (sigma.ts/otel.ts/siem.ts):
 * concrete fields to alert on, the exact log pattern, and — the
 * differentiated part an AppSec buyer actually pays for — FINDING-SPECIFIC
 * expected false-alarm sources, never a generic "may have false positives"
 * placeholder. Built from the SAME `RuleContext` (context.ts) B3 renders
 * from, so the narrative always describes the SAME detection logic as the
 * rule it's attached to.
 *
 * `FALSE_ALARM_SOURCES` is a `Record<Category, ...>` (not `Partial<...>`) —
 * TypeScript enforces every current and future `Category` value gets a real,
 * category-specific entry here, so a new category can never silently fall
 * through to a generic message.
 */
import type { Category, ConfirmedFinding, DetectionLogSignature } from "@montr/contracts";
import type { RuleContext } from "./context.js";

type FalseAlarmFn = (ctx: RuleContext, finding: ConfirmedFinding) => string;

const routeDesc = (ctx: RuleContext): string =>
  ctx.kind === "file-fallback"
    ? `reads/writes of ${ctx.fileTarget}`
    : `${ctx.method === "ANY" ? "requests" : ctx.method} requests to ${ctx.path || "this route"}`;

const FALSE_ALARM_SOURCES: Record<Category, FalseAlarmFn> = {
  sql_injection: (ctx) =>
    `An internal reporting/BI tool or admin search box that legitimately builds free-text filter queries against ${routeDesc(
      ctx,
    )} can contain quotes or SQL keywords in normal use — scope the alert to non-admin-role sessions, or allowlist the known reporting-service account, rather than blocking on the raw substring match alone.`,
  nosql_injection: (ctx) =>
    `A legitimate admin dashboard building dynamic MongoDB filter objects against ${routeDesc(
      ctx,
    )} (e.g. a "greater than" date-range filter) can produce operator keys like $gt/$where that match this rule's markers — scope to non-admin-role sessions or exclude the known dashboard's service account.`,
  command_injection: (ctx) =>
    `A CI/automation or admin diagnostics endpoint that legitimately shells out with operator-supplied flags (a git ref, a filename) against ${routeDesc(
      ctx,
    )} can resemble the shell-metacharacter markers this rule matches — scope to non-admin-role sessions or allowlist the known automation service account.`,
  xss: (ctx) =>
    `A CMS/rich-text or support-ticket field that legitimately accepts formatted HTML on ${routeDesc(
      ctx,
    )} (e.g. a WYSIWYG editor save) will contain script-adjacent markup as part of normal use — scope the rule to routes that do not accept rich HTML input, or diff against your sanitizer's allowed-tag list before alerting.`,
  ssrf: (ctx) =>
    `A URL-preview/link-unfurl or webhook-validation feature on ${routeDesc(
      ctx,
    )} that legitimately fetches user-supplied URLs (including health-checking loopback/internal addresses) can trip a broad "internal address" match — scope the rule to the specific cloud metadata literal (169.254.169.254) rather than all loopback/internal addresses to cut noise.`,
  path_traversal: (ctx) =>
    `A legitimate nested file-download/export endpoint on ${routeDesc(
      ctx,
    )} (e.g. "documents/{folder}/{file}") can contain "../"-shaped segments in normal, non-malicious client requests if the client doesn't URL-encode the path — scope the rule to routes that should never accept nested paths, or require canonicalized/encoded paths only.`,
  insecure_deserialization: (ctx) =>
    `A scheduled batch-import job or legacy client integration that legitimately submits typed/serialized payloads to ${routeDesc(
      ctx,
    )} as part of normal operation can resemble this signature — scope to unexpected content-types on this route, or exclude the known batch-import service account.`,
  hardcoded_secret: (ctx) =>
    `Routine CI/CD or IaC-scanning tooling that reads ${routeDesc(
      ctx,
    )} as part of a normal build/audit pass will also touch this file — scope the alert to writes/modifications of the file rather than reads, or exclude your known CI/CD service account's file-access paths.`,
  vulnerable_dependency: () =>
    `A scheduled SCA/dependency-audit job re-scanning the manifest for the same known-vulnerable package will re-emit this signature on every run by design — this is expected, recurring noise, not a false positive; suppress duplicate alerts for the SAME package+version pair rather than the whole rule.`,
  permissive_cors: (ctx) =>
    `A legitimate first-party subdomain or an approved partner integration making a cross-origin request to ${routeDesc(
      ctx,
    )} will also carry an Origin header — scope the alert to Origins OUTSIDE your configured allowlist, not to the mere presence of a cross-origin request.`,
  missing_security_headers: (ctx) =>
    `A health-check or synthetic-monitoring probe hitting ${routeDesc(
      ctx,
    )} may be excluded from your header-injection middleware's route matcher entirely (by design, for uptime probes) and will show the same "missing header" signature — exclude known monitoring/health-check user agents or source IPs from this alert.`,
  insecure_cookie: (ctx) =>
    `A local-development or staging environment serving ${routeDesc(
      ctx,
    )} over plain HTTP by design (no TLS terminator in front of it) will legitimately omit the Secure cookie flag — scope this alert to your production ingest source/environment tag only.`,
  weak_crypto: (ctx) =>
    `A legacy compatibility code path intentionally using a weaker cipher/hash for interop with an old client on ${routeDesc(
      ctx,
    )} (e.g. a deprecated mobile app version still in the field) can legitimately produce this same signature — scope to new/current API versions only, or track the legacy path as a separately accepted-risk exception.`,
  broken_access_control: (ctx) =>
    `A support/admin "impersonate user" or bulk-export tool legitimately acting on behalf of many resource owners against ${routeDesc(
      ctx,
    )} in a single authorized session can resemble a cross-tenant access pattern — scope the alert to non-admin-role sessions or a known internal support-tooling service account.`,
  broken_authentication: (ctx) =>
    `A password-manager browser extension or a legitimate retry after a typo can produce several failed-then-successful auth attempts against ${routeDesc(
      ctx,
    )} in quick succession — scope the alert to a materially higher attempt count / distinct-username-per-IP ratio than normal user mistyping produces.`,
  open_redirect: (ctx) =>
    `A marketing/campaign link or an SSO callback flow using a legitimate, allowlisted cross-domain "next"/"redirect_uri" parameter on ${routeDesc(
      ctx,
    )} will match an off-site-domain pattern — scope the rule to destination domains OUTSIDE your configured redirect allowlist.`,
  xxe: (ctx) =>
    `A legacy XML-based partner integration or a scheduled XML batch-import against ${routeDesc(
      ctx,
    )} that legitimately declares a DOCTYPE for validation (without an external entity) can partially match this signature — scope to payloads containing an external ENTITY/SYSTEM declaration specifically, not any DOCTYPE.`,
  csrf: (ctx) =>
    `A legitimate cross-site navigation (e.g. an email link or a bookmarked deep link) landing a state-changing request on ${routeDesc(
      ctx,
    )} without a Referer header (privacy-mode browsers strip it) can resemble a missing-CSRF-token pattern — scope the alert to state-changing (POST/PUT/DELETE) requests specifically, not GETs, and require the token check to fail rather than the header merely being absent.`,
  sensitive_data_exposure: (ctx) =>
    `An authorized support/debugging tool intentionally requesting the full record (including normally-masked fields) on ${routeDesc(
      ctx,
    )} for a legitimate support ticket can resemble this pattern — scope the alert to non-support-role sessions or requests missing the ticket-reference header your support tooling attaches.`,
  insufficient_logging: () =>
    `A brand-new route added after this rule's telemetry baseline was captured may legitimately show as "under-logged" until its instrumentation catches up — re-baseline the expected logging rate before this rule is enabled for a newly deployed route.`,
  idor: (ctx) =>
    `A bulk-export/admin tool enumerating sequential resource ids on behalf of an authorized operator against ${routeDesc(
      ctx,
    )} in a single session can resemble this rule's "many distinct ids from one session" pattern — scope the alert to non-admin-role sessions or a known internal batch-job service account.`,
  mass_assignment: (ctx) =>
    `An internal admin panel that legitimately needs to set normally-protected fields (e.g. a role or status field) on ${routeDesc(
      ctx,
    )} as part of its intended function will match this rule's "unexpected field present in body" signature — scope the alert to non-admin-role sessions submitting the same protected field names.`,
  rate_limit_missing: (ctx) =>
    `A legitimate bulk browser extension or corporate NAT gateway sharing one egress IP across many real users can produce a request volume against ${routeDesc(
      ctx,
    )} that resembles this rule's threshold — scope by authenticated session/user id rather than source IP alone where the route supports it.`,
  prompt_injection: (ctx) =>
    `A user legitimately pasting untrusted third-party text (an email thread, a support ticket body) for the LLM feature at ${routeDesc(
      ctx,
    )} to summarize will often contain imperative-sounding language that resembles an injection attempt — scope the alert to content that changes the SYSTEM behavior/tool-call pattern, not merely imperative phrasing in user-supplied text.`,
  insecure_configuration: (_ctx) =>
    `A local/dev-environment deployment of the same IaC template intentionally relaxing a setting (e.g. running as non-root is skipped for a throwaway sandbox) will match this rule outside production — scope the alert to your production environment tag/namespace only.`,
  other: (ctx) =>
    `This finding's category doesn't map to one of the well-known false-alarm patterns above — treat ${routeDesc(
      ctx,
    )} conservatively and validate the first several alerts manually before tuning scope further.`,
};

function fieldsFor(ctx: RuleContext): string[] {
  if (ctx.kind === "file-fallback") return ["TargetFilename"];
  const fields = ["cs-uri-stem"];
  if (ctx.method !== "ANY") fields.push("cs-method");
  if (ctx.markers.length > 0) fields.push("cs-uri-query", "cs-body");
  return fields;
}

function patternFor(ctx: RuleContext, finding: ConfirmedFinding): string {
  if (ctx.kind === "file-fallback") {
    return `Any read or write of ${ctx.fileTarget} recorded by your file-integrity/config-audit log, in the window around ${finding.createdAt} — this finding has no HTTP route, so there is no request-log pattern to key on.`;
  }
  const routePart = `${ctx.method === "ANY" ? "any-method" : ctx.method} requests to ${ctx.path}`;
  if (ctx.markers.length === 0) {
    return `${routePart[0]!.toUpperCase()}${routePart.slice(1)}, with no distinguishing payload marker available from this finding's proof — alert on volume/anomaly against this route rather than content matching.`;
  }
  const quoted = ctx.markers.map((m) => `"${m}"`).join(", ");
  const provenance =
    ctx.kind === "live-request"
      ? "the exact payload observed in this finding's live-DAST transcript"
      : `a known ${finding.category.replace(/_/g, " ")} payload marker`;
  return `${routePart[0]!.toUpperCase()}${routePart.slice(1)} whose query string or request body contains ${provenance}: ${quoted}.`;
}

export function buildLogSignature(
  finding: ConfirmedFinding,
  ctx: RuleContext,
): DetectionLogSignature {
  return {
    fields: fieldsFor(ctx),
    pattern: patternFor(ctx, finding),
    falseAlarmSources: [FALSE_ALARM_SOURCES[finding.category](ctx, finding)],
  };
}
