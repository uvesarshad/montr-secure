/**
 * Shared detection-rule generation context (B3/B4). Builds ONE `RuleContext`
 * per confirmed finding — the method/path/payload-marker signature every
 * format generator (sigma.ts, otel.ts, siem.ts) and the B4 narrative
 * (narrative.ts) render from, so all three rule formats and the log-signature
 * narrative express the SAME underlying detection logic.
 *
 * Two provenance paths (mirrors `ConfirmedFinding.proofType`):
 *  - "live": the real HTTP request/response transcript IS the signature. The
 *    exact exploit payload is recovered by diffing the LAST transcript
 *    exchange (the strongest confirming probe — `confirmLive` in
 *    packages/confirm/src/live.ts pushes exchanges in order
 *    [baseline, payload, ...adaptive rounds], so the last entry is always the
 *    most refined attempt) against the FIRST ("baseline") exchange: whatever
 *    query-param values or request body changed between them is the actual
 *    injected content, with no per-category guessing required. Falls back to
 *    the primary exchange's whole query string/body when no clean diff is
 *    available (e.g. a single-exchange transcript).
 *  - "static": no request was ever fired, so there is nothing to diff. Falls
 *    back to a small table of well-known, category-specific payload markers
 *    (independent of — not copied from — @montr/confirm's live-probe payload
 *    catalog in live.ts, which fires real requests; these are just common,
 *    publicly-known signature substrings) plus the App Map route resolved by
 *    `resolveRoute` (route.ts). When no route resolves either (a
 *    non-request-shaped, config/component-class category — see
 *    `isDataFlowConfirmable`), degrades further to a file-scoped rule keyed
 *    on `finding.location.file`.
 */
import {
  type AppMap,
  type Category,
  type ConfirmedFinding,
  type LiveProof,
  type Route,
  type TaintSinkKind,
} from "@montr/contracts";
import { DATAFLOW_SINK_KINDS, isDataFlowConfirmable } from "@montr/confirm";
import { resolveRoute } from "./route.js";

export type RuleContextKind = "live-request" | "static-request" | "file-fallback";

export interface RuleContext {
  kind: RuleContextKind;
  /** HTTP method ("ANY" when genuinely unknown — never invented). */
  method: string;
  /** Route path; empty string only for the file-fallback case. */
  path: string;
  route?: Route;
  /** Suspicious substrings to match in the query/body (may be empty). */
  markers: string[];
  bodyExample?: string;
  sinkKindLabel?: TaintSinkKind;
  /** Only set for `kind: "file-fallback"`. */
  fileTarget?: string;
  /** Human-readable provenance sentence reused verbatim by narrative.ts. */
  provenanceNote: string;
}

/**
 * Well-known, category-specific payload marker substrings — the STATIC
 * fallback used only when no live transcript exists to diff. Deliberately
 * generic/public-knowledge patterns, not an attempt to replicate
 * @montr/confirm's exact probe payloads.
 */
export const CATEGORY_MARKERS: Partial<Record<Category, readonly string[]>> = {
  sql_injection: ["' OR '1'='1", "' OR 1=1--", "UNION SELECT", "; DROP TABLE", "SLEEP(5)--"],
  nosql_injection: ['{"$ne":null}', '{"$gt":""}', "$where", "$regex"],
  command_injection: ["; cat /etc/passwd", "&& id", "| whoami", "$(id)", "`id`"],
  xss: ["<script>", "onerror=", "javascript:", "<img src=x onerror="],
  ssrf: ["169.254.169.254", "file://", "http://localhost", "http://127.0.0.1"],
  path_traversal: ["../../../../etc/passwd", "..%2f..%2f", "....//"],
  open_redirect: ["//evil.", "http://evil.", "@evil.com"],
  insecure_deserialization: ["rO0AB", "__proto__", '"@type"'],
  xxe: ["<!DOCTYPE", "<!ENTITY", 'SYSTEM "file:'],
};

const MAX_MARKER_LEN = 160;

function truncate(s: string, n = MAX_MARKER_LEN): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function safeUrl(raw: string, base: string): URL | undefined {
  try {
    return new URL(raw);
  } catch {
    try {
      return new URL(raw, base);
    } catch {
      return undefined;
    }
  }
}

function diffQueryMarkers(primary: URL, baseline: URL | undefined): string[] {
  const out: string[] = [];
  for (const [key, value] of primary.searchParams) {
    if (!value) continue;
    if (value !== baseline?.searchParams.get(key)) out.push(truncate(value));
  }
  return out;
}

function diffBodyMarkers(
  primaryBody: string | undefined,
  baselineBody: string | undefined,
): string[] {
  if (!primaryBody) return [];
  return primaryBody !== baselineBody ? [truncate(primaryBody)] : [];
}

function sinkKindLabelFor(category: Category): TaintSinkKind | undefined {
  return isDataFlowConfirmable(category) ? DATAFLOW_SINK_KINDS[category][0] : undefined;
}

function buildFromLiveProof(finding: ConfirmedFinding, proof: LiveProof): RuleContext | undefined {
  const transcript = proof.transcript;
  if (transcript.length === 0) return undefined;
  const primaryExchange = transcript[transcript.length - 1];
  const baselineExchange = transcript.length > 1 ? transcript[0] : undefined;
  if (!primaryExchange) return undefined;

  const primaryUrl = safeUrl(primaryExchange.request.url, proof.target);
  if (!primaryUrl) return undefined;
  const baselineUrl = baselineExchange
    ? safeUrl(baselineExchange.request.url, proof.target)
    : undefined;

  const markers = [
    ...diffQueryMarkers(primaryUrl, baselineUrl),
    ...diffBodyMarkers(primaryExchange.request.bodySnippet, baselineExchange?.request.bodySnippet),
  ];
  // No clean diff (single-exchange transcript, or the diff happened to be
  // empty) — fall back to whatever was actually observed rather than nothing.
  if (markers.length === 0) {
    if (primaryUrl.search) markers.push(truncate(primaryUrl.search.replace(/^\?/, "")));
    if (primaryExchange.request.bodySnippet)
      markers.push(truncate(primaryExchange.request.bodySnippet));
  }

  return {
    kind: "live-request",
    method: primaryExchange.request.method || "ANY",
    path: primaryUrl.pathname || "/",
    markers,
    ...(primaryExchange.request.bodySnippet
      ? { bodyExample: truncate(primaryExchange.request.bodySnippet) }
      : {}),
    sinkKindLabel: sinkKindLabelFor(finding.category),
    provenanceNote: `a real live-DAST transcript (${transcript.length} exchange${
      transcript.length === 1 ? "" : "s"
    } captured against ${proof.target})`,
  };
}

function buildFromStaticProof(finding: ConfirmedFinding, appMap: AppMap | undefined): RuleContext {
  const route = resolveRoute(appMap, finding);
  const markers = [...(CATEGORY_MARKERS[finding.category] ?? [])];
  const sinkKindLabel = sinkKindLabelFor(finding.category);

  if (route) {
    return {
      kind: "static-request",
      method: route.method,
      path: route.path,
      route,
      markers,
      sinkKindLabel,
      provenanceNote:
        "a static data-flow proof (no requests fired); the route was resolved from the App Map",
    };
  }

  return {
    kind: "file-fallback",
    method: "ANY",
    path: "",
    markers,
    fileTarget: finding.location.file,
    sinkKindLabel,
    provenanceNote: `a static data-flow proof (no requests fired); no App Map route matched ${finding.location.file}, so this rule is scoped to the file instead`,
  };
}

/** Builds the shared detection context every format generator renders from. */
export function buildRuleContext(finding: ConfirmedFinding, appMap?: AppMap): RuleContext {
  const proof = finding.proofArtifact;
  if (proof.kind === "live") {
    const fromLive = buildFromLiveProof(finding, proof);
    if (fromLive) return fromLive;
  }
  return buildFromStaticProof(finding, appMap);
}
