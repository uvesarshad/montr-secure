/**
 * Deterministic classification tables + helpers for static confirmation.
 * Everything here is pure (no LLM, no I/O) — this is the "tools detect" half of
 * the golden rule; the LLM only narrates and vetoes (see `static.ts`).
 */
import {
  CATEGORY_TAXONOMY,
  type Category,
  type Exposure,
  type Route,
  type Severity,
  type TaintSink,
  type TaintSinkKind,
} from "@montr/contracts";
import type { ResolvedHeuristics } from "./heuristics/types.js";

/**
 * Which sink kinds a category's tainted-flow can terminate in. An EMPTY list
 * means the category is not confirmable by source→sink data-flow (it is a
 * configuration/component-class issue — e.g. permissive CORS, a vulnerable dep,
 * a hard-coded secret) and static confirmation defers it to the appendix unless
 * live DAST proves it.
 */
export const DATAFLOW_SINK_KINDS: Record<Category, readonly TaintSinkKind[]> = {
  sql_injection: ["sql_query", "orm_raw_query"],
  nosql_injection: ["sql_query", "orm_raw_query"],
  command_injection: ["command_exec", "eval"],
  xss: ["html_render", "template_render", "http_response"],
  ssrf: ["http_client"],
  path_traversal: ["fs_read", "fs_write"],
  open_redirect: ["redirect"],
  insecure_deserialization: ["deserialize"],
  xxe: ["deserialize"],
  // Configuration / component-class — not a taint data-flow:
  hardcoded_secret: [],
  vulnerable_dependency: [],
  permissive_cors: [],
  missing_security_headers: [],
  insecure_cookie: [],
  weak_crypto: [],
  broken_access_control: [],
  broken_authentication: [],
  csrf: [],
  sensitive_data_exposure: [],
  insufficient_logging: [],
  idor: [],
  mass_assignment: [],
  rate_limit_missing: [],
  // No dedicated TaintSinkKind exists for "reaches an LLM prompt" (E11 scoped
  // Layer 1 detection only; a real data-flow sink kind + static/live Layer 3
  // confirmation path for prompt_injection is a documented follow-up, out of
  // this change's file scope for packages/confirm). Treated as a
  // configuration/component-class category like the others above: it defers
  // to the Unconfirmed appendix rather than claiming a static proof it can't
  // back up (fail-safe, golden rule #4).
  prompt_injection: [],
  // Configuration/component-class, same shape as vulnerable_dependency /
  // hardcoded_secret above — an IaC misconfiguration (E16) has no source→sink
  // taint flow to prove; it defers to the Unconfirmed appendix unless a future
  // dedicated IaC confirmation path is built.
  insecure_configuration: [],
  other: [],
};

export function isDataFlowConfirmable(category: Category): boolean {
  return DATAFLOW_SINK_KINDS[category].length > 0;
}

/** Sink kinds that are inherently raw/dangerous absent an explicit sanitizer. */
const RAW_SINK_KINDS = new Set<TaintSinkKind>([
  "orm_raw_query",
  "command_exec",
  "eval",
  "deserialize",
  "html_render",
  "template_render",
]);

/** Substrings signalling an UNSANITIZED construct (raw interpolation, unsafe API). */
const UNSAFE_MARKERS = [
  "unsafe",
  "queryrawunsafe",
  "executerawunsafe",
  "dangerouslysetinnerhtml",
  "innerhtml",
  "${",
  "eval(",
  "exec(",
  "child_process",
  "string interpolation",
  "interpolat",
  "concat",
];

/** Substrings signalling a sanitizer/validator interrupts the path. */
const SAFE_MARKERS = [
  "parameterized",
  "parameterised",
  "prepared",
  "sanitiz",
  "sanitis",
  "escap",
  "validated",
  "allowlist",
  "whitelist",
  "encoded",
  "dompurify",
  "findmany",
  "findunique",
  "findfirst",
  "where:",
  "placeholder",
  "bound param",
];

export interface SinkAssessment {
  dangerous: boolean;
  /** The sanitizer marker that interrupts the path, when `dangerous` is false. */
  sanitizer?: string;
  reason: string;
}

/**
 * Decide whether tainted input reaching this sink is dangerous. Fail-safe: on
 * ambiguity (conflicting or absent markers on a non-raw sink) it resolves toward
 * NOT dangerous so uncertain findings stay in the appendix (golden rule #4).
 *
 * `extra` carries per-language heuristics (from the registry) APPENDED after the
 * stack-agnostic base; when empty (the Phase-1 TS/JS path) the result is
 * identical to the base-only assessment.
 */
export function assessSink(sink: TaintSink, extra?: ResolvedHeuristics): SinkAssessment {
  const d = (sink.description ?? "").toLowerCase();
  const unsafeMarkers =
    extra && extra.unsafeMarkers.length > 0
      ? [...UNSAFE_MARKERS, ...extra.unsafeMarkers]
      : UNSAFE_MARKERS;
  const safeMarkers =
    extra && extra.safeMarkers.length > 0 ? [...SAFE_MARKERS, ...extra.safeMarkers] : SAFE_MARKERS;
  const rawSinkKinds =
    extra && extra.rawSinkKinds.length > 0
      ? new Set<TaintSinkKind>([...RAW_SINK_KINDS, ...extra.rawSinkKinds])
      : RAW_SINK_KINDS;

  const unsafe = unsafeMarkers.find((k) => d.includes(k));
  const safe = safeMarkers.find((k) => d.includes(k));

  if (unsafe && !safe)
    return { dangerous: true, reason: `unsanitized sink construct ("${unsafe}")` };
  if (safe && !unsafe)
    return {
      dangerous: false,
      sanitizer: safe,
      reason: `sink is sanitized/parameterized ("${safe}")`,
    };
  if (safe && unsafe)
    // Conflicting evidence → treat as sanitized (do not confirm on ambiguity).
    return {
      dangerous: false,
      sanitizer: safe,
      reason: `ambiguous sink (both unsafe and safe markers); treated as sanitized (fail-safe)`,
    };
  // No description markers → fall back to the sink kind.
  if (rawSinkKinds.has(sink.kind))
    return {
      dangerous: true,
      reason: `raw sink kind "${sink.kind}" with no sanitizer on the path`,
    };
  return {
    dangerous: false,
    reason: `sink kind "${sink.kind}" shows no evidence of an unsanitized construct (fail-safe)`,
  };
}

/** Base severity per finding class (final severity is set here at confirmation). */
const BASE_SEVERITY: Record<Category, Severity> = {
  sql_injection: "critical",
  command_injection: "critical",
  insecure_deserialization: "critical",
  nosql_injection: "high",
  xss: "high",
  ssrf: "high",
  path_traversal: "high",
  xxe: "high",
  broken_access_control: "high",
  broken_authentication: "high",
  idor: "high",
  hardcoded_secret: "high",
  sensitive_data_exposure: "high",
  open_redirect: "medium",
  csrf: "medium",
  permissive_cors: "medium",
  missing_security_headers: "medium",
  insecure_cookie: "medium",
  weak_crypto: "medium",
  vulnerable_dependency: "medium",
  mass_assignment: "medium",
  rate_limit_missing: "low",
  insufficient_logging: "low",
  // On par with the other "high" injection-family categories (xss, ssrf) —
  // see packages/correlation/src/taxonomy.ts's CATEGORY_IMPACT_BASE comment
  // for the same reasoning (E11).
  prompt_injection: "high",
  // On par with the other config-class categories (permissive_cors,
  // missing_security_headers, insecure_cookie) — real risk, but a rawSeverity
  // override from the specific check (e.g. a privileged container) can still
  // push an individual finding higher (E16).
  insecure_configuration: "medium",
  other: "low",
};

/**
 * A category's severity class before any exposure discount — used to gate
 * expensive per-category work (e.g. A3's investigation-loop eligibility)
 * where the decision should track "is this category inherently high-value"
 * rather than "is this specific finding's exposure narrow enough to earn a
 * discount." Using the exposure-discounted `deriveSeverity` for that gate
 * would silently exclude the common authenticated-only idor/broken_access_control
 * case (both "high" base, downgraded to "medium" once exposure != "public")
 * from a default `severities: ["high", "critical"]` scope — defeating the
 * whole point of a feature built specifically to raise recall on those two
 * categories, which otherwise have zero static data-flow proof at all.
 */
export function baseSeverityForCategory(category: Category): Severity {
  return BASE_SEVERITY[category];
}

/**
 * Final severity for a confirmed finding. Proven-exploitable public findings keep
 * their class base; an authed exploit is downgraded one notch (harder to reach)
 * unless the class is already critical.
 */
export function deriveSeverity(category: Category, exposure: Exposure): Severity {
  const base = BASE_SEVERITY[category];
  if (exposure === "public" || base === "critical") return base;
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  const i = order.indexOf(base);
  return order[Math.max(0, i - 1)] ?? base;
}

const CATEGORY_IMPACT: Partial<Record<Category, string>> = {
  sql_injection:
    "An attacker can read or modify arbitrary database contents and may escalate to write or RCE depending on DB privileges.",
  nosql_injection: "An attacker can bypass query logic to read or alter unauthorized documents.",
  command_injection: "An attacker can execute arbitrary OS commands on the host.",
  xss: "Arbitrary script executes in the victim's browser session, enabling session theft and account takeover.",
  ssrf: "The server can be coerced into making attacker-controlled requests to internal services.",
  path_traversal: "An attacker can read or write files outside the intended directory.",
  open_redirect:
    "Users can be redirected to attacker-controlled sites for phishing or token theft.",
  insecure_deserialization: "Untrusted data is deserialized, enabling object injection or RCE.",
  xxe: "External-entity resolution enables file disclosure or SSRF.",
};

/** Human-readable impact statement, grounded in the correlation exploit hypothesis. */
export function deriveImpact(category: Category, exploitHypothesis: string): string {
  const base = CATEGORY_IMPACT[category] ?? `Confirmed ${CATEGORY_TAXONOMY[category].title}.`;
  const hyp = exploitHypothesis.trim();
  return hyp ? `${base} ${hyp}` : base;
}

/** Confirmed-finding title, e.g. "SQL Injection in GET /api/users (q parameter)". */
export function deriveTitle(
  category: Category,
  route: Route | undefined,
  file: string,
  line: number,
  param?: string,
): string {
  const t = CATEGORY_TAXONOMY[category].title;
  if (route) {
    const p = param ? ` (${param} parameter)` : "";
    return `${t} in ${route.method} ${route.path}${p}`;
  }
  return `${t} at ${file}:${line}`;
}

const PARAM_PATTERNS: readonly RegExp[] = [
  /\.get\(['"]([A-Za-z0-9_]+)['"]\)/,
  /searchParams\.([A-Za-z0-9_]+)/,
  /\.query\.([A-Za-z0-9_]+)/,
  /\.body\.([A-Za-z0-9_]+)/,
  /\bparams\.([A-Za-z0-9_]+)/,
  /\bcookies?\.([A-Za-z0-9_]+)/,
];

/**
 * Best-effort request-parameter name from a taint-source description. `extra`
 * appends per-language patterns after the base ones; empty extras (Phase-1
 * TS/JS) leave the result identical to the base.
 */
export function extractParam(description?: string, extra?: ResolvedHeuristics): string | undefined {
  if (!description) return undefined;
  const patterns =
    extra && extra.paramPatterns.length > 0
      ? [...PARAM_PATTERNS, ...extra.paramPatterns]
      : PARAM_PATTERNS;
  for (const re of patterns) {
    const m = re.exec(description);
    if (m?.[1]) return m[1];
  }
  return undefined;
}
