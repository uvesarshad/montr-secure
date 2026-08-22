/**
 * B5 — the purple-team verification loop: run a red-team scenario through the
 * existing gated Layer-3 engine (scenarios.ts), then check whether the
 * B3-generated `DetectionRule` for the SAME finding would actually have fired
 * against the scenario's real request/response transcript. This is what makes
 * the product genuinely PURPLE (attack -> did telemetry catch it?) rather than
 * red-with-a-report.
 *
 * ⛔ SAFETY: this module adds NO new execution path. `runPurpleTeamScenario`
 * below calls {@link runScenario} from ./scenarios.js verbatim — the exact
 * same function every other scenario caller uses, with the exact same
 * `ScenarioRunDeps` (egress guard, transport, kill-switch signal, throttle) —
 * so it is subject to the identical `assertScenarioAuthorized` +
 * `ScopeGuard.assertProbeAllowed` gate (kill switch, allowlist, production
 * block, blast-radius/rate caps, egress guard) as every existing caller. This
 * module contains zero HTTP/transport code of its own; everything after the
 * scenario run is pure, read-only post-processing of the transcript
 * `runScenario` already produced.
 *
 * THE DETECTION CHECK (structural, not a coin flip): B3
 * (packages/report/src/detection-rules/sigma.ts) emits Sigma YAML from a
 * small, fixed set of shapes — never hand-authored, never arbitrary Sigma.
 * `parseSigmaRule` below parses exactly those shapes (route-based
 * `cs-uri-stem|startswith` / `cs-method` / `cs-uri-query|contains` /
 * `cs-body|contains` selections joined by `and`/`1 of`, or the file-fallback
 * `TargetFilename|contains` selection) back into a structured spec, and
 * `evaluateSigmaRule` evaluates that spec against the scenario's actual
 * request method/URL/body. This is a real, faithful SUBSET evaluator for
 * precisely what sigma.ts's generator produces — not a generic Sigma engine
 * for the full upstream spec (see that file's own header for why a subset is
 * the right scope here).
 *
 * A real, structural gap this evaluator surfaces "for free": `RedTeamStep`
 * (packages/contracts/src/phase4.ts) carries no request-body field, and
 * `runScenario` never sends one (scenarios.ts's transport.send call passes
 * only method/url/signal) — so a rule whose condition depends on
 * `cs-body|contains` can currently never fire against a scenario-run
 * transcript. `evaluateSigmaRule` reports this explicitly in its `reason`
 * rather than silently returning `fired: false` with no explanation.
 */
import type {
  Category,
  ConfirmedFinding,
  DetectionCoverage,
  DetectionRule,
  DetectionVerificationResult,
  HttpExchange,
  RedTeamCategory,
  RedTeamScenario,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { StateStore } from "@montr/state-store";
import { runScenario, type ScenarioRunDeps, type ScenarioRunResult } from "./scenarios.js";

/* ============================ Sigma subset parser ============================ */

/**
 * A parsed subset of one `DetectionRule.content` Sigma rule — only the fields
 * sigma.ts's generator ever emits (see this file's header). `condition` is
 * kept verbatim for the evaluation `reason` text; the actual condition
 * SEMANTICS (`selection_route` alone, vs. `selection_route and 1 of
 * selection_payload_*`) are inferred structurally from which selections are
 * present, mirroring sigma.ts's own `if (ctx.markers.length > 0)` branch.
 */
export interface ParsedSigmaRule {
  kind: "file-fallback" | "route";
  /** `kind: "file-fallback"` only — the `TargetFilename|contains` value. */
  fileTargetContains?: string;
  /** `kind: "route"` only — the `cs-uri-stem|startswith` value. */
  pathStartsWith?: string;
  /** `kind: "route"` only — the exact `cs-method` value, if the rule pins one. */
  method?: string;
  /** `cs-uri-query|contains` list values (may be empty — no payload condition). */
  queryContains: string[];
  /** `cs-body|contains` list values (may be empty — no payload condition). */
  bodyContains: string[];
  /** Raw `condition:` line value, verbatim, for human-readable evidence text. */
  condition: string;
}

const QUOTED = '"((?:[^"\\\\]|\\\\.)*)"';

/** Reverses sigma.ts's `yamlQuote` escaping (`\"` -> `"`, then `\\` -> `\`). */
function yamlUnquote(raw: string): string {
  return raw.replace(/\\"/g, '"').replace(/\\\\/g, "\\");
}

function extractOne(content: string, re: RegExp): string | undefined {
  const m = re.exec(content);
  return m?.[1] !== undefined ? yamlUnquote(m[1]) : undefined;
}

/** Collects the `- "value"` list lines immediately following a `key:` header line. */
function extractList(content: string, headerRe: RegExp): string[] {
  const m = headerRe.exec(content);
  if (!m) return [];
  const after = content.slice(m.index + m[0].length);
  const out: string[] = [];
  for (const line of after.split("\n")) {
    const im = /^\s*-\s*"((?:[^"\\]|\\.)*)"\s*$/.exec(line);
    if (!im?.[1]) break;
    out.push(yamlUnquote(im[1]));
  }
  return out;
}

/**
 * Parse a `DetectionRule.content` Sigma YAML string (as produced by
 * `buildSigmaRule` in packages/report/src/detection-rules/sigma.ts) into a
 * {@link ParsedSigmaRule}. Line/regex-based by design (see module header) —
 * this is NOT a general Sigma/YAML parser and will not correctly parse
 * hand-authored or third-party Sigma content outside the fixed shapes B3's
 * generator emits.
 */
export function parseSigmaRule(content: string): ParsedSigmaRule {
  const conditionMatch = /condition:\s*(.+?)\s*$/m.exec(content);
  const condition = conditionMatch?.[1] ?? "";
  const isFileEvent = /category:\s*file_event/.test(content);

  if (isFileEvent) {
    const fileTargetContains = extractOne(
      content,
      new RegExp(`TargetFilename\\|contains:\\s*${QUOTED}`),
    );
    return {
      kind: "file-fallback",
      fileTargetContains,
      queryContains: [],
      bodyContains: [],
      condition,
    };
  }

  const pathStartsWith = extractOne(content, new RegExp(`cs-uri-stem\\|startswith:\\s*${QUOTED}`));
  const method = extractOne(content, new RegExp(`cs-method:\\s*${QUOTED}`));
  const queryContains = extractList(content, /cs-uri-query\|contains:\s*\n/);
  const bodyContains = extractList(content, /cs-body\|contains:\s*\n/);

  return { kind: "route", pathStartsWith, method, queryContains, bodyContains, condition };
}

/* ============================ structural evaluation ============================ */

export interface EvaluableRequest {
  method: string;
  url: string;
  bodySnippet?: string;
}

export interface SigmaEvalOutcome {
  fired: boolean;
  /** Which selection fields actually matched (e.g. ["cs-uri-stem", "cs-uri-query"]). */
  matchedFields: string[];
  /** Human-readable explanation of what matched, or specifically why it didn't. */
  reason: string;
}

/**
 * Dynamic-segment-tolerant prefix match: a rule path segment written as
 * `[id]` (Next.js-style, from an AppMap `Route.path`) or `:id` (the
 * placeholder convention `RedTeamStep.path` templates use, see
 * redteam-catalogue.ts) matches any single concrete path segment, mirroring
 * scenarios.ts's own `concretePath` substitution at run time. All other
 * segments must match literally. Implements Sigma's `|startswith` semantics
 * (prefix, not exact).
 */
function pathMatchesStartsWith(pattern: string, actualPath: string): boolean {
  const segs = pattern
    .split("/")
    .map((seg) =>
      /^\[[^\]]+\]$/.test(seg) || /^:[A-Za-z0-9_]+$/.test(seg)
        ? "[^/]+"
        : seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    );
  const re = new RegExp(`^${segs.join("/")}`);
  return re.test(actualPath);
}

/** Sigma `|contains` semantics — substring match, case-insensitive (common backend default). */
function containsMarker(haystack: string, marker: string): boolean {
  return haystack.toLowerCase().includes(marker.toLowerCase());
}

/**
 * Evaluate one parsed Sigma rule against one concrete HTTP request. Real
 * structural evaluation — never randomized — see module header.
 */
export function evaluateSigmaRule(
  parsed: ParsedSigmaRule,
  request: EvaluableRequest,
): SigmaEvalOutcome {
  if (parsed.kind === "file-fallback") {
    return {
      fired: false,
      matchedFields: [],
      reason: `rule matches file-system telemetry (TargetFilename contains "${
        parsed.fileTargetContains ?? ""
      }") — an HTTP scenario transcript carries no file-event signal to evaluate this against`,
    };
  }

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return {
      fired: false,
      matchedFields: [],
      reason: `scenario request URL "${request.url}" could not be parsed as a URL`,
    };
  }

  const matchedFields: string[] = [];
  const routeMatched =
    parsed.pathStartsWith !== undefined &&
    pathMatchesStartsWith(parsed.pathStartsWith, url.pathname);
  if (routeMatched) matchedFields.push("cs-uri-stem");

  if (!routeMatched) {
    return {
      fired: false,
      matchedFields,
      reason: `rule requires a path starting with "${parsed.pathStartsWith}" — this request's path was "${url.pathname}", which does not match`,
    };
  }

  const methodPinned = parsed.method !== undefined;
  const methodMatched =
    !methodPinned || parsed.method!.toUpperCase() === request.method.toUpperCase();
  if (methodPinned && methodMatched) matchedFields.push("cs-method");
  if (!methodMatched) {
    return {
      fired: false,
      matchedFields,
      reason: `rule requires method ${parsed.method} at this path — this request used ${request.method}`,
    };
  }

  const hasPayloadSelections = parsed.queryContains.length > 0 || parsed.bodyContains.length > 0;
  if (!hasPayloadSelections) {
    matchedFields.push("condition:selection_route");
    return {
      fired: true,
      matchedFields,
      reason: `route${methodPinned ? "+method" : ""} matched and this rule has no payload-marker condition (condition: "${parsed.condition}")`,
    };
  }

  // Decode percent-encoding before matching — a payload marker like `' OR '1'='1`
  // survives as literal characters in the log formats Sigma `cs-uri-query` rules
  // key on (and in `context.ts`'s own `URLSearchParams`-decoded marker diffing),
  // whereas the WHATWG `URL.search` getter re-encodes reserved characters. Falls
  // back to the raw (still-encoded) string on malformed encoding rather than
  // throwing.
  const rawQuery = url.search.replace(/^\?/, "");
  let queryString = rawQuery;
  try {
    queryString = decodeURIComponent(rawQuery);
  } catch {
    // malformed percent-encoding — match against the raw string instead.
  }
  const bodyString = request.bodySnippet ?? "";
  const queryHit = parsed.queryContains.find((m) => containsMarker(queryString, m));
  const bodyHit = parsed.bodyContains.find((m) => containsMarker(bodyString, m));

  if (queryHit) matchedFields.push("cs-uri-query");
  if (bodyHit) matchedFields.push("cs-body");

  if (queryHit || bodyHit) {
    return {
      fired: true,
      matchedFields,
      reason: `route${methodPinned ? "+method" : ""} matched, and payload marker "${
        queryHit ?? bodyHit
      }" was found in the ${queryHit ? "query string" : "request body"} (condition: "${parsed.condition}")`,
    };
  }

  const bodyGap =
    parsed.bodyContains.length > 0 && bodyString === ""
      ? " — note: this scenario runner never sends a request body (RedTeamStep carries no body field, and runScenario's transport.send call passes only method/url), so a body-only marker can never match today"
      : "";
  const allMarkers = [...parsed.queryContains, ...parsed.bodyContains];
  return {
    fired: false,
    matchedFields,
    reason: `route${methodPinned ? "+method" : ""} matched, but none of this rule's payload markers [${allMarkers.join(
      ", ",
    )}] were found in the query string or body${bodyGap} (condition: "${parsed.condition}")`,
  };
}

/* ============================ scenario-vs-rule ============================ */

export interface SigmaRuleEvaluation {
  rule: DetectionRule;
  fired: boolean;
  matchedFields: string[];
  /** The transcript exchange that fired (or came closest to firing). */
  matchedExchange?: HttpExchange;
  reason: string;
}

/**
 * Evaluate one `DetectionRule` against every exchange in a scenario's real
 * transcript. Fires if ANY exchange satisfies the rule's structural
 * condition; the reported evidence is the firing exchange, or — when nothing
 * fires — the exchange that matched the MOST selection fields (the most
 * informative near-miss), so "why undetected" is always concrete.
 */
export function evaluateDetectionRuleAgainstScenario(
  rule: DetectionRule,
  scenarioRun: Pick<ScenarioRunResult, "transcript" | "probed">,
): SigmaRuleEvaluation {
  if (rule.format !== "sigma") {
    return {
      rule,
      fired: false,
      matchedFields: [],
      reason: `this evaluator structurally assesses "sigma"-format rules only; rule ${rule.id} is format "${rule.format}"`,
    };
  }

  const parsed = parseSigmaRule(rule.content);

  if (scenarioRun.transcript.length === 0) {
    return {
      rule,
      fired: false,
      matchedFields: [],
      reason: scenarioRun.probed
        ? "scenario probed but produced no transcript entries"
        : "scenario ran in gate-only/authorize mode (no transport supplied) — no request was ever sent, so there is nothing to evaluate the rule against",
    };
  }

  let bestMiss: (SigmaEvalOutcome & { exchange: HttpExchange }) | undefined;
  for (const exchange of scenarioRun.transcript) {
    const outcome = evaluateSigmaRule(parsed, {
      method: exchange.request.method,
      url: exchange.request.url,
      bodySnippet: exchange.request.bodySnippet,
    });
    if (outcome.fired) {
      return {
        rule,
        fired: true,
        matchedFields: outcome.matchedFields,
        matchedExchange: exchange,
        reason: outcome.reason,
      };
    }
    if (!bestMiss || outcome.matchedFields.length > bestMiss.matchedFields.length) {
      bestMiss = { ...outcome, exchange };
    }
  }

  return {
    rule,
    fired: false,
    matchedFields: bestMiss?.matchedFields ?? [],
    matchedExchange: bestMiss?.exchange,
    reason: bestMiss?.reason ?? "no scenario request matched this rule's selection conditions",
  };
}

/* ============================ orchestration ============================ */

export interface RunPurpleTeamScenarioInput {
  scenario: RedTeamScenario;
  /** The confirmed finding this scenario is verifying detection coverage for. */
  finding: ConfirmedFinding;
  config: MontrConfig;
  /** ⛔ Approver authorization gate — forwarded verbatim to `runScenario`. */
  allowLive: boolean;
  targetOverride?: string;
}

export interface RunPurpleTeamScenarioDeps extends ScenarioRunDeps {
  /** Candidate detection rules for `finding` (e.g. from `store.detectionRules.listByFinding`). */
  detectionRules?: DetectionRule[];
  now?: () => string;
}

export interface PurpleTeamScenarioResult {
  scenarioRun: ScenarioRunResult;
  finding: Pick<ConfirmedFinding, "id" | "category" | "title" | "clientId" | "scanId">;
  ruleEvaluations: SigmaRuleEvaluation[];
  /** The DetectionCoverage-shaped verdict: fired = true iff ANY candidate rule fired. */
  overall: DetectionVerificationResult;
}

/**
 * ⛔ Run one red-team scenario through the EXISTING gated engine
 * (`runScenario` from ./scenarios.js — no new execution path, see module
 * header), then structurally evaluate every candidate Sigma detection rule
 * against the resulting transcript. Pure post-processing after the gated
 * call returns; throws exactly what `runScenario` throws (kill switch /
 * allowlist / production / authorization failures) — this function adds no
 * additional guard AND removes none of `runScenario`'s existing ones.
 */
export async function runPurpleTeamScenario(
  input: RunPurpleTeamScenarioInput,
  deps: RunPurpleTeamScenarioDeps = {},
): Promise<PurpleTeamScenarioResult> {
  const { detectionRules, now, ...scenarioDeps } = deps;
  const scenarioRun = await runScenario(
    {
      scenario: input.scenario,
      config: input.config,
      allowLive: input.allowLive,
      ...(input.targetOverride ? { targetOverride: input.targetOverride } : {}),
    },
    scenarioDeps,
  );

  const sigmaRules = (detectionRules ?? []).filter((r) => r.format === "sigma");
  const ruleEvaluations = sigmaRules.map((rule) =>
    evaluateDetectionRuleAgainstScenario(rule, scenarioRun),
  );

  const fired = ruleEvaluations.some((e) => e.fired);
  const clock = now ?? (() => new Date().toISOString());
  const firedEval = ruleEvaluations.find((e) => e.fired);
  const bestEval = firedEval ?? ruleEvaluations[0];

  const evidence =
    ruleEvaluations.length === 0
      ? "no sigma detection rule exists yet for this finding — nothing to verify (generate one via packages/report/src/detection-rules first)"
      : (bestEval?.reason ?? "");

  const overall: DetectionVerificationResult = {
    scenarioId: input.scenario.id,
    fired,
    verifiedAt: clock(),
    ...(evidence ? { evidence } : {}),
  };

  return {
    scenarioRun,
    finding: {
      id: input.finding.id,
      category: input.finding.category,
      title: input.finding.title,
      clientId: input.finding.clientId,
      scanId: input.finding.scanId,
    },
    ruleEvaluations,
    overall,
  };
}

/* ============================ persistence (B1 consumption) ============================ */

export interface FindOrCreateCoverageOptions {
  now?: () => string;
  idFactory?: () => string;
  detectionRuleId?: string;
}

/**
 * Find the most recent `DetectionCoverage` row for a finding, or create a
 * fresh `detected: "unknown"` placeholder row when none exists yet. Read-only
 * consumption of the B1 repository (`StateStore.detectionCoverage`) — no
 * changes to packages/state-store/src/blue-team.ts.
 */
export async function findOrCreateDetectionCoverage(
  store: StateStore,
  clientId: string,
  finding: Pick<ConfirmedFinding, "id" | "scanId">,
  opts: FindOrCreateCoverageOptions = {},
): Promise<DetectionCoverage> {
  const existing = await store.detectionCoverage.listByFinding(clientId, finding.id);
  if (existing[0]) return existing[0];

  const now = opts.now ?? (() => new Date().toISOString());
  const idFactory =
    opts.idFactory ?? (() => `dcov_${finding.id}_${Math.random().toString(36).slice(2, 10)}`);

  return store.detectionCoverage.create(clientId, {
    id: idFactory(),
    clientId,
    scanId: finding.scanId,
    findingId: finding.id,
    detected: "unknown",
    reasoning:
      "Coverage record created by the purple-team verification loop (B5) prior to any prior generated verdict; detected stays 'unknown' until a scenario run's evaluation completes and updates it.",
    ...(opts.detectionRuleId ? { detectionRuleId: opts.detectionRuleId } : {}),
    createdAt: now(),
  });
}

export interface VerifyScenarioDetectionResult {
  scenarioResult: PurpleTeamScenarioResult;
  coverage: DetectionCoverage;
}

/**
 * Full B5 loop for one (scenario, finding) pair: run the scenario through the
 * existing gate, evaluate candidate rules against the transcript, find-or-
 * create the finding's `DetectionCoverage` row, and persist the result via
 * `StateStore.detectionCoverage.updateVerification` (B1's real repository —
 * see packages/state-store/src/blue-team.ts). Standalone: NOT called from any
 * pipeline layer or report-assembly path (B10's job in a later wave).
 */
export async function verifyScenarioDetection(
  store: StateStore,
  clientId: string,
  input: RunPurpleTeamScenarioInput,
  deps: RunPurpleTeamScenarioDeps = {},
): Promise<VerifyScenarioDetectionResult> {
  const scenarioResult = await runPurpleTeamScenario(input, deps);
  const bestRule =
    scenarioResult.ruleEvaluations.find((e) => e.fired) ?? scenarioResult.ruleEvaluations[0];

  const coverage = await findOrCreateDetectionCoverage(store, clientId, input.finding, {
    ...(deps.now ? { now: deps.now } : {}),
    ...(bestRule ? { detectionRuleId: bestRule.rule.id } : {}),
  });

  const updated = await store.detectionCoverage.updateVerification(
    clientId,
    coverage.id,
    scenarioResult.overall,
  );

  return { scenarioResult, coverage: updated };
}

/* ============================ reporting summary ============================ */

export interface PurpleTeamScenarioSummaryEntry {
  scenarioId: string;
  scenarioName: string;
  findingId: string;
  findingCategory: Category;
  detectionRuleId?: string;
  detected: boolean;
  /** Why detected/undetected — always concrete, never a placeholder. */
  reason: string;
}

export interface PurpleTeamRunSummary {
  scanId: string;
  totalScenarios: number;
  detectedCount: number;
  undetectedCount: number;
  entries: PurpleTeamScenarioSummaryEntry[];
}

export interface PurpleTeamRunEntry {
  scenario: RedTeamScenario;
  finding: ConfirmedFinding;
  result: PurpleTeamScenarioResult;
}

/**
 * Pure, standalone summary builder — NOT wired into report-builder.ts (B10's
 * job). Reports detected/undetected per scenario, and for undetected ones
 * WHY: no rule exists for the finding, or a rule exists but its match
 * conditions genuinely don't cover this scenario's real request shape.
 */
export function summarizePurpleTeamRun(
  scanId: string,
  runs: readonly PurpleTeamRunEntry[],
): PurpleTeamRunSummary {
  const entries: PurpleTeamScenarioSummaryEntry[] = runs.map(({ scenario, finding, result }) => {
    const bestRule = result.ruleEvaluations.find((e) => e.fired) ?? result.ruleEvaluations[0];
    return {
      scenarioId: scenario.id,
      scenarioName: scenario.name,
      findingId: finding.id,
      findingCategory: finding.category,
      ...(bestRule ? { detectionRuleId: bestRule.rule.id } : {}),
      detected: result.overall.fired,
      reason: result.overall.evidence ?? "no evidence recorded",
    };
  });

  return {
    scanId,
    totalScenarios: entries.length,
    detectedCount: entries.filter((e) => e.detected).length,
    undetectedCount: entries.filter((e) => !e.detected).length,
    entries,
  };
}

/* ============================ scenario<->finding category hint ============================ */

/**
 * Informational mapping from the coarse `RedTeamCategory` (phase4.ts —
 * `access_control` | `injection` | `authentication` | `ssrf` | `xss` |
 * `business_logic` | `recon` | `other`) to the finer-grained finding
 * `Category` (compliance.ts) it plausibly targets. NOT used to auto-select a
 * finding for a scenario run (callers explicitly pass the `ConfirmedFinding`
 * to verify — see {@link RunPurpleTeamScenarioInput}); this exists purely as
 * a documented convenience for a caller (e.g. B10) deciding which finding a
 * given scenario is meant to verify detection for.
 */
export const REDTEAM_CATEGORY_TO_FINDING_CATEGORIES: Record<RedTeamCategory, readonly Category[]> =
  {
    access_control: ["broken_access_control", "idor", "mass_assignment", "csrf"],
    injection: [
      "sql_injection",
      "nosql_injection",
      "command_injection",
      "xxe",
      "insecure_deserialization",
    ],
    authentication: ["broken_authentication", "insecure_cookie", "weak_crypto"],
    ssrf: ["ssrf"],
    xss: ["xss"],
    business_logic: ["mass_assignment", "rate_limit_missing"],
    recon: ["vulnerable_dependency", "missing_security_headers", "sensitive_data_exposure"],
    other: [
      "other",
      "hardcoded_secret",
      "permissive_cors",
      "open_redirect",
      "insufficient_logging",
      "insecure_configuration",
    ],
  };
