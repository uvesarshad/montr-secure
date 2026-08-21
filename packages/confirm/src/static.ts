/**
 * Layer 3a — STATIC confirmation (default, works on any repo, no running target).
 *
 * Builds a deterministic source → transforms → sink data-flow proof, tracking the
 * AUTH STATE at each hop, and emits a proof-of-reachability argument. NO requests
 * are fired. The deterministic engine is authoritative for the confirm/deny
 * decision (golden rule #6); an optional confirmation-tier LLM may only enrich the
 * argument or VETO (demote) a finding — it can never promote one (golden rule #4).
 */
import {
  ConfirmedFindingSchema,
  UnconfirmedFindingSchema,
  complianceForCategory,
  type AppMap,
  type AuthState,
  type ConfirmedFinding,
  type DataFlowHop,
  type Exposure,
  type LLMRequest,
  type ProbableFinding,
  type Route,
  type StaticProof,
  type TaintSink,
  type TaintSource,
  type UnconfirmedFinding,
} from "@montr/contracts";
import {
  assessSink,
  deriveImpact,
  deriveSeverity,
  deriveTitle,
  extractParam,
  isDataFlowConfirmable,
  DATAFLOW_SINK_KINDS,
} from "./taxonomy.js";
import { resolveHeuristics } from "./heuristics/registry.js";
import type { ResolvedHeuristics } from "./heuristics/types.js";
import type { ConfirmDeps, ConfirmInput, StaticConfirmOutcome } from "./types.js";

const defaultNow = (): string => new Date().toISOString();
const defaultConfirmedId = (p: ProbableFinding, proofType: "static" | "live"): string =>
  `cf_${proofType}_${p.id}`;

interface DataFlowResult {
  reachable: boolean;
  hops: DataFlowHop[];
  sanitizersBypassed: string[];
  reason: string;
  exposure: Exposure;
  entryAuthState: AuthState;
  route?: Route;
  source?: TaintSource;
  sink?: TaintSink;
  param?: string;
}

function findRoute(appMap: AppMap, finding: ProbableFinding): Route | undefined {
  if (finding.routeId) {
    const byId = appMap.routes.find((r) => r.id === finding.routeId);
    if (byId) return byId;
  }
  return appMap.routes.find((r) => r.handler?.file === finding.location.file);
}

function findSink(appMap: AppMap, finding: ProbableFinding): TaintSink | undefined {
  const kinds = new Set(DATAFLOW_SINK_KINDS[finding.category]);
  const inFile = appMap.taintSinks.filter(
    (s) => kinds.has(s.kind) && s.location.file === finding.location.file,
  );
  if (inFile.length === 0) return undefined;
  const exact = inFile.find((s) => s.location.line === finding.location.line);
  if (exact) return exact;
  return [...inFile].sort(
    (a, b) =>
      Math.abs(a.location.line - finding.location.line) -
      Math.abs(b.location.line - finding.location.line),
  )[0];
}

function findSource(
  appMap: AppMap,
  finding: ProbableFinding,
  sink: TaintSink,
  route: Route | undefined,
): TaintSource | undefined {
  const routeId = route?.id ?? finding.routeId;
  if (routeId) {
    const byRoute = appMap.taintSources.find((s) => s.routeId === routeId);
    if (byRoute) return byRoute;
  }
  return (
    appMap.taintSources.find((s) => s.location.file === sink.location.file) ??
    appMap.taintSources.find((s) => s.location.file === finding.location.file)
  );
}

function describeRoute(route: Route | undefined, exposure: Exposure): string {
  if (route) {
    const auth =
      route.authState === "public"
        ? "public"
        : route.authState === "unknown"
          ? "unknown-auth"
          : route.authState.replace(/_/g, " ");
    return `the ${auth} route ${route.method} ${route.path}`;
  }
  return exposure === "public" ? "a public entry point" : "an authenticated entry point";
}

/** Build the source → sink data-flow, carrying auth state at each hop. */
function buildDataFlow(
  appMap: AppMap,
  finding: ProbableFinding,
  heuristics: ResolvedHeuristics,
): DataFlowResult {
  const category = finding.category;
  const route = findRoute(appMap, finding);
  const entryAuthState: AuthState = route?.authState ?? "unknown";
  const exposure = finding.exposure;
  const base = {
    hops: [] as DataFlowHop[],
    sanitizersBypassed: [] as string[],
    exposure,
    entryAuthState,
    route,
  };

  if (!isDataFlowConfirmable(category)) {
    return {
      ...base,
      reachable: false,
      reason: `${category} is a configuration/component-class finding with no tainted source→sink data-flow; static confirmation defers it to the appendix (live DAST or manual review required).`,
    };
  }

  const sink = findSink(appMap, finding);
  if (!sink) {
    return {
      ...base,
      reachable: false,
      reason: `no ${category} sink (${DATAFLOW_SINK_KINDS[category].join("/")}) found in ${finding.location.file}; reachability cannot be proven statically.`,
    };
  }

  const source = findSource(appMap, finding, sink, route);
  const param = extractParam(source?.description, heuristics);
  const assessment = assessSink(sink, heuristics);

  const hops: DataFlowHop[] = [];
  if (source) {
    hops.push({
      location: source.location,
      authState: entryAuthState,
      transform: `read ${source.kind}${param ? ` "${param}"` : ""}`,
      ...(source.description ? { note: source.description } : {}),
    });
  }
  hops.push({
    location: sink.location,
    authState: entryAuthState,
    transform: assessment.sanitizer ? `sanitizer: ${assessment.sanitizer}` : "no sanitizer on path",
    ...(sink.description ? { note: sink.description } : {}),
  });

  if (!assessment.dangerous) {
    return {
      ...base,
      hops,
      reachable: false,
      reason: `${assessment.reason}; tainted input does not reach an exploitable ${sink.kind} sink.`,
      source,
      sink,
      param,
    };
  }
  if (!source) {
    return {
      ...base,
      hops,
      reachable: false,
      reason: `the ${sink.kind} sink at ${sink.location.file}:${sink.location.line} is unsanitized, but no tainted source was proven to reach it; deferred (fail-safe).`,
      sink,
      param,
    };
  }

  return {
    ...base,
    hops,
    reachable: true,
    reason: `tainted ${source.kind} on ${describeRoute(route, exposure)} reaches the ${sink.kind} sink at ${sink.location.file}:${sink.location.line}; ${assessment.reason}.`,
    source,
    sink,
    param,
  };
}

function buildStaticArgument(df: DataFlowResult, finding: ProbableFinding): string {
  const sink = df.sink;
  const entry = df.source
    ? `${df.source.kind}${df.param ? ` "${df.param}"` : ""} enters at ${df.source.location.file}:${df.source.location.line}`
    : "tainted input enters";
  const flow = sink
    ? `It flows to the ${sink.kind} sink at ${sink.location.file}:${sink.location.line} with no interrupting sanitizer or validator.`
    : "";
  const reach =
    df.entryAuthState === "public"
      ? "an unauthenticated attacker"
      : "an authorized-but-malicious caller";
  return [
    "Static proof of reachability (no requests fired):",
    `The ${entry} on ${describeRoute(df.route, finding.exposure)}.`,
    flow,
    `Auth state is "${df.entryAuthState}" at every hop, so the sink is reachable by ${reach}.`,
    `Exploit hypothesis: ${finding.exploitHypothesis}`,
  ]
    .filter((s) => s.length > 0)
    .join(" ");
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

interface LlmReview {
  argument?: string;
  confirmed?: boolean;
}

/** Confirmation-tier LLM review: enrich the argument + provide a fail-safe veto. Metadata only. */
async function runLlmReview(
  deps: ConfirmDeps,
  input: ConfirmInput,
  df: DataFlowResult,
  finding: ProbableFinding,
): Promise<LlmReview | undefined> {
  const llm = deps.llm;
  if (!llm) return undefined;
  const payload = {
    task: 'Judge exploitability of this static data-flow. Respond ONLY as JSON {"confirmed": boolean, "argument": string}. When uncertain, set confirmed=false.',
    category: finding.category,
    exposure: finding.exposure,
    route: df.route
      ? { method: df.route.method, path: df.route.path, authState: df.route.authState }
      : null,
    source: df.source
      ? { kind: df.source.kind, file: df.source.location.file, line: df.source.location.line }
      : null,
    sink: df.sink
      ? {
          kind: df.sink.kind,
          file: df.sink.location.file,
          line: df.sink.location.line,
          note: (df.sink.description ?? "").slice(0, 200),
        }
      : null,
    hops: df.hops.map((h) => ({
      file: h.location.file,
      line: h.location.line,
      authState: h.authState,
      transform: h.transform,
    })),
  };
  // Prompt registry (§8.2, §15): resolve the DB-versioned template for this
  // prompt name when one is active; otherwise the hardcoded string below
  // (resolvePrompt's `fallback` arg) is used unchanged.
  const systemFallback =
    "You are a security exploit-confirmation reviewer. Judge exploitability conservatively from the static data-flow. When uncertain, set confirmed=false.";
  const request: LLMRequest = {
    tier: "confirmation",
    system:
      (await llm.resolvePrompt?.("confirm.static_review.system", systemFallback, {
        clientId: input.clientId,
      })) ?? systemFallback,
    messages: [{ role: "user", content: JSON.stringify(payload) }],
    maxTokens: 4096, // A8: raised from 1024 — output-token headroom to reason, not a cost cap.
    temperature: 0,
    responseFormat: "json",
    stream: false,
    metadata: {
      scanId: input.scanId,
      clientId: input.clientId,
      layer: "layer3",
      purpose: "confirmation",
    },
  };
  try {
    const resp = await llm.complete(request);
    const parsed = safeJson(resp.content);
    if (!parsed || typeof parsed !== "object") return {};
    const rec = parsed as Record<string, unknown>;
    const review: LlmReview = {};
    if (typeof rec.confirmed === "boolean") review.confirmed = rec.confirmed;
    if (typeof rec.argument === "string") review.argument = rec.argument;
    return review;
  } catch (err) {
    deps.logger?.warn?.("layer3: LLM confirmation review failed; keeping deterministic decision", {
      error: errMessage(err),
      probableId: finding.id,
    });
    return undefined;
  }
}

/** Assemble a validated ConfirmedFinding from a proof artifact (shared: static + live). */
export function assembleConfirmed(
  finding: ProbableFinding,
  route: Route | undefined,
  param: string | undefined,
  proof:
    | StaticProof
    | { kind: "live"; target: string; transcript: import("@montr/contracts").HttpExchange[] },
  proofType: "static" | "live",
  deps: ConfirmDeps,
): ConfirmedFinding {
  const category = finding.category;
  const compliance = complianceForCategory(category);
  return ConfirmedFindingSchema.parse({
    id: (deps.idFactory ?? defaultConfirmedId)(finding, proofType),
    scanId: finding.scanId,
    clientId: finding.clientId,
    probableId: finding.id,
    title: deriveTitle(category, route, finding.location.file, finding.location.line, param),
    category,
    cwe: compliance.cwe,
    owasp: compliance.owasp,
    severity: deriveSeverity(category, finding.exposure),
    exposure: finding.exposure,
    location: finding.location,
    impact: deriveImpact(category, finding.exploitHypothesis),
    proofType,
    proofArtifact: proof,
    createdAt: (deps.now ?? defaultNow)(),
  });
}

/** Build the appendix entry for a probable finding that failed confirmation (kept, not deleted). */
export function toUnconfirmed(finding: ProbableFinding, reason: string): UnconfirmedFinding {
  return UnconfirmedFindingSchema.parse({
    ...finding,
    status: "unconfirmed",
    unconfirmedReason: reason,
  });
}

/**
 * Attempt static confirmation of one probable finding. Returns a confirmed
 * finding with a static proof, or an unconfirmed outcome carrying the reason.
 */
export async function confirmStatic(
  finding: ProbableFinding,
  input: ConfirmInput,
  deps: ConfirmDeps,
): Promise<StaticConfirmOutcome> {
  // Per-language confirmation heuristics (extras appended to the stack-agnostic
  // base). Empty for Phase-1 TS/JS, so the assessment is unchanged there.
  const heuristics = resolveHeuristics(input.appMap);
  const df = buildDataFlow(input.appMap, finding, heuristics);
  if (!df.reachable) {
    return { kind: "unconfirmed", reason: df.reason, dataFlow: df.hops };
  }

  let argument = buildStaticArgument(df, finding);

  const review = await runLlmReview(deps, input, df, finding);
  if (review) {
    const crossCheck = deps.useLlmCrossCheck ?? Boolean(deps.llm);
    if (crossCheck && review.confirmed === false) {
      return {
        kind: "unconfirmed",
        reason: `${df.reason} However, the confirmation-tier model judged it NOT exploitable on review — demoted to the appendix (fail-safe, golden rule #4).`,
        dataFlow: df.hops,
      };
    }
    if (review.argument && review.argument.trim().length >= 8) {
      argument = `${argument}\n\nModel review: ${review.argument.trim()}`;
    }
  }

  const proof: StaticProof = {
    kind: "static",
    argument,
    dataFlow: df.hops,
    sanitizersBypassed: df.sanitizersBypassed,
  };
  const finding_ = assembleConfirmed(finding, df.route, df.param, proof, "static", deps);
  return { kind: "confirmed", finding: finding_, dataFlow: df.hops };
}
