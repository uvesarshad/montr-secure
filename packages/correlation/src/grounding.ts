/**
 * App Map grounding — THE MOAT. For each candidate we ask the deterministic
 * questions of PRD §7 Layer 2:
 *   - Is it on a route/entry point that actually EXISTS and is registered?
 *   - Is it public or behind auth, and which auth state gates it?
 *   - Does tainted input actually REACH the sink, or does a validator/sanitizer
 *     interrupt the path?
 * Everything here is deterministic and grounded in the App Map — the LLM only
 * refines the narrative + ranking later, never route existence or exposure.
 */
import type {
  AppMap,
  AuthState,
  CandidateFinding,
  Entrypoint,
  EnvSecretSurface,
  Exposure,
  Route,
  TaintFlowEdge,
  TaintSink,
  TaintSource,
} from "@montr/contracts";
import { classifyCategory, type FindingClass } from "./taxonomy.js";

/** Signals that a validator/sanitizer neutralizes tainted input before a sink. */
const SANITIZER_RE =
  /\b(validat|paramet|sanitiz|escap|encod|allowlist|whitelist|prepared|bind|zod|parseInt|number\()/i;

/**
 * How the taint reachability verdict was reached:
 *   - "cross-file-resolved": a real interprocedural flow (App Map's
 *     `taintFlows`, see `packages/appmap/src/languages/typescript/callgraph.ts`)
 *     named the actual function that carries the tainted value to the sink —
 *     structural proof, not a proximity guess. May or may not literally cross
 *     a file (see the flow's own `crossFile` flag), but is always resolved via
 *     the call graph rather than nearest-line distance.
 *   - "same-file-heuristic": the original nearest-line-in-the-same-file guess
 *     (paired with the text-based sanitizer regex) — kept as the fallback for
 *     everything the resolver above doesn't (yet) handle.
 *   - "none": no taint path was established either way.
 */
export type TaintFlowKind = "cross-file-resolved" | "same-file-heuristic" | "none";

/** The deterministic verdict for a single candidate, grounded in the App Map. */
export interface Grounding {
  klass: FindingClass;
  /** Registered route this finding sits on, if any. */
  route?: Route;
  routeId?: string;
  /** Route-level auth state ("unknown" when unmapped). */
  authState: AuthState;
  /** Coarse exposure enum (public only when a public route is confirmed). */
  exposure: Exposure;
  authGate?: string;
  matchedSink?: TaintSink;
  matchedSource?: TaintSource;
  matchedSecretSurface?: EnvSecretSurface;
  matchedEntrypoint?: Entrypoint;
  /** The resolved interprocedural flow this verdict is grounded in, if any. */
  matchedFlow?: TaintFlowEdge;
  /** Was the taint verdict a resolved call-graph flow, a same-file proximity guess, or neither? */
  taintFlowKind: TaintFlowKind;
  /** A validator/sanitizer interrupts the source→sink path (same-file heuristic only). */
  sanitizerInterrupts: boolean;
  /** Tainted input plausibly reaches the sink with no interrupt. */
  taintReaches: boolean;
  /** The App Map corroborates this finding as part of the real attack surface. */
  corroborated: boolean;
  corroborationBasis: string;
  /** Demote to the appendix (never delete) — uncorroborated or path-neutralized. */
  demote: boolean;
  demoteReason?: string;
}

/** Indexed view of an App Map for O(1)-ish lookups by file. */
export class AppMapIndex {
  private readonly routesByFile = new Map<string, Route[]>();
  private readonly sourcesByFile = new Map<string, TaintSource[]>();
  private readonly sinksByFile = new Map<string, TaintSink[]>();
  private readonly secretsByFile = new Map<string, EnvSecretSurface[]>();
  private readonly entrypointsByFile = new Map<string, Entrypoint[]>();
  private readonly routeById = new Map<string, Route>();
  /** Resolved taint flows, indexed by the FILE THE SINK SITS IN (a candidate's
   * own location is always the sink side, never the source side). */
  private readonly flowsBySinkFile = new Map<string, TaintFlowEdge[]>();

  constructor(readonly appMap: AppMap) {
    for (const route of appMap.routes) {
      if (route.handler?.file) push(this.routesByFile, route.handler.file, route);
      if (route.id) this.routeById.set(route.id, route);
    }
    for (const src of appMap.taintSources) push(this.sourcesByFile, src.location.file, src);
    for (const sink of appMap.taintSinks) push(this.sinksByFile, sink.location.file, sink);
    for (const s of appMap.envSecretSurfaces)
      if (s.location) push(this.secretsByFile, s.location.file, s);
    for (const e of appMap.entrypoints)
      if (e.location) push(this.entrypointsByFile, e.location.file, e);
    for (const flow of appMap.taintFlows ?? [])
      push(this.flowsBySinkFile, flow.sinkLocation.file, flow);
  }

  routesInFile(file: string): Route[] {
    return this.routesByFile.get(file) ?? [];
  }
  sourcesInFile(file: string): TaintSource[] {
    return this.sourcesByFile.get(file) ?? [];
  }
  sinksInFile(file: string): TaintSink[] {
    return this.sinksByFile.get(file) ?? [];
  }
  secretsInFile(file: string): EnvSecretSurface[] {
    return this.secretsByFile.get(file) ?? [];
  }
  entrypointsInFile(file: string): Entrypoint[] {
    return this.entrypointsByFile.get(file) ?? [];
  }
  /** Resolved taint flows whose SINK sits in `file`. */
  flowsInFile(file: string): TaintFlowEdge[] {
    return this.flowsBySinkFile.get(file) ?? [];
  }
  getRoute(id: string): Route | undefined {
    return this.routeById.get(id);
  }
}

function push<T>(map: Map<string, T[]>, key: string, value: T): void {
  const arr = map.get(key);
  if (arr) arr.push(value);
  else map.set(key, [value]);
}

/** Nearest route in a file to a target line, keyed on its handler location. */
function pickNearestRoute(routes: Route[], line: number): Route | undefined {
  let best: Route | undefined;
  let bestDist = Number.POSITIVE_INFINITY;
  for (const route of routes) {
    const handlerLine = route.handler?.line ?? line;
    const dist = Math.abs(handlerLine - line);
    if (dist < bestDist) {
      best = route;
      bestDist = dist;
    }
  }
  return best;
}

/** Nearest element in a file to a target line (by absolute distance). */
function nearestByLine<T extends { location?: { line: number } }>(
  items: T[],
  line: number,
): T | undefined {
  let best: T | undefined;
  let bestDist = Number.POSITIVE_INFINITY;
  for (const item of items) {
    if (!item.location) continue;
    const dist = Math.abs(item.location.line - line);
    if (dist < bestDist) {
      best = item;
      bestDist = dist;
    }
  }
  return best;
}

/** Nearest resolved taint-flow edge (by its sink line) to a target line. */
function nearestFlowByLine(flows: TaintFlowEdge[], line: number): TaintFlowEdge | undefined {
  let best: TaintFlowEdge | undefined;
  let bestDist = Number.POSITIVE_INFINITY;
  for (const flow of flows) {
    const dist = Math.abs(flow.sinkLocation.line - line);
    if (dist < bestDist) {
      best = flow;
      bestDist = dist;
    }
  }
  return best;
}

function exposureFromAuth(authState: AuthState, hasRoute: boolean): Exposure {
  // Only claim "public" when a public route is actually confirmed. Everything
  // else — authed, role-gated, unknown, or off-route (secret/dep) — is reported
  // conservatively as "authed" so we never overstate exposure.
  return hasRoute && authState === "public" ? "public" : "authed";
}

/** Extract a dependency package name from a candidate's metadata (no code egress). */
export function extractPackageName(cand: CandidateFinding): string | undefined {
  const hay = `${cand.evidenceSnippet} ${cand.title ?? ""}`;
  const m = hay.match(/([@a-z0-9/._-]+)@\d/i);
  return m?.[1];
}

/** Cross-reference one candidate against the App Map. */
export function groundCandidate(cand: CandidateFinding, index: AppMapIndex): Grounding {
  const klass = classifyCategory(cand.category);
  const file = cand.location.file;

  // --- Route / entry-point resolution (does the surface exist & is it registered?)
  const routesHere = index.routesInFile(file);
  const sourcesHere = index.sourcesInFile(file);
  const entrypointsHere = index.entrypointsInFile(file);

  // Routes are indexed by handler file, so every route here has a handler line.
  let route: Route | undefined = pickNearestRoute(routesHere, cand.location.line);

  // Fall back to a route referenced by a taint source in this file.
  if (!route) {
    const src = sourcesHere.find((s) => s.routeId !== undefined);
    if (src?.routeId) route = index.getRoute(src.routeId);
  }
  const matchedEntrypoint = entrypointsHere[0];

  const authState: AuthState = route?.authState ?? "unknown";
  const exposure = exposureFromAuth(authState, route !== undefined);
  const authGate = route?.authGate;

  // --- Taint path (does input actually reach a dangerous sink?)
  const matchedSink =
    klass === "injection" || klass === "other"
      ? nearestByLine(index.sinksInFile(file), cand.location.line)
      : undefined;
  const matchedSource =
    matchedSink !== undefined
      ? // Prefer a source on the same route, else any source in the file.
        ((route?.id ? sourcesHere.find((s) => s.routeId === route?.id) : undefined) ??
        sourcesHere[0])
      : undefined;

  // A resolved call-graph flow (see callgraph.ts) is structural proof the
  // source reaches this exact sink — prefer it over the same-file proximity
  // guess whenever the candidate's sink line has one. Only attempted for
  // "injection" candidates (matching the class the same-file heuristic below
  // has always applied its taintReaches/sanitizerInterrupts verdict to).
  const matchedFlow =
    klass === "injection"
      ? nearestFlowByLine(index.flowsInFile(file), cand.location.line)
      : undefined;

  const pathText = [
    matchedSource?.description ?? "",
    matchedSink?.description ?? "",
    cand.evidenceSnippet,
  ].join(" ");
  const heuristicSanitizerInterrupts = klass === "injection" && SANITIZER_RE.test(pathText);
  const heuristicTaintReaches =
    klass === "injection" &&
    matchedSink !== undefined &&
    matchedSource !== undefined &&
    !heuristicSanitizerInterrupts;

  let taintFlowKind: TaintFlowKind;
  let sanitizerInterrupts: boolean;
  let taintReaches: boolean;
  if (matchedFlow !== undefined) {
    // callgraph.ts only ever emits an edge when the tainted parameter reaches
    // the sink with nothing sanitizer-shaped called on it in between (see its
    // `isCleanParamUse` — a nested call anywhere on the path drops the edge
    // entirely) — so a resolved edge IS the proof the path is clean.
    taintFlowKind = "cross-file-resolved";
    sanitizerInterrupts = false;
    taintReaches = true;
  } else if (klass === "injection") {
    taintFlowKind = "same-file-heuristic";
    sanitizerInterrupts = heuristicSanitizerInterrupts;
    taintReaches = heuristicTaintReaches;
  } else {
    taintFlowKind = "none";
    sanitizerInterrupts = false;
    taintReaches = false;
  }

  // --- Secret / dependency corroboration.
  const matchedSecretSurface =
    klass === "secret" ? nearestByLine(index.secretsInFile(file), cand.location.line) : undefined;
  const pkg = klass === "dependency" ? extractPackageName(cand) : undefined;
  const depCorroborated =
    klass === "dependency" &&
    pkg !== undefined &&
    index.appMap.thirdPartyCalls.some(
      (tp) => tp.name.includes(pkg) || (tp.target?.includes(pkg) ?? false),
    );

  // --- Corroboration + demotion verdict.
  let corroborated: boolean;
  let corroborationBasis: string;
  switch (klass) {
    case "injection":
      corroborated = matchedSink !== undefined || matchedFlow !== undefined || route !== undefined;
      corroborationBasis = matchedFlow
        ? `resolved taint flow${matchedFlow.throughFunction ? ` via ${matchedFlow.throughFunction}` : ""} (${matchedFlow.sinkKind})`
        : matchedSink
          ? `taint sink (${matchedSink.kind}) on the App Map`
          : route
            ? `registered route ${route.path}`
            : "none";
      break;
    case "config":
    case "access":
      corroborated = route !== undefined || matchedEntrypoint !== undefined;
      corroborationBasis = route ? `registered route ${route.path}` : "registered entry point";
      break;
    case "secret":
      corroborated = matchedSecretSurface !== undefined || route !== undefined;
      corroborationBasis = matchedSecretSurface
        ? `secret surface ${matchedSecretSurface.name}`
        : "registered route";
      break;
    case "dependency":
      corroborated = depCorroborated;
      corroborationBasis = depCorroborated
        ? `imported/called dependency ${pkg}`
        : "no import-graph reachability";
      break;
    default:
      corroborated = route !== undefined || matchedSink !== undefined;
      corroborationBasis = route ? `registered route ${route.path}` : "App Map surface";
  }

  let demote = false;
  let demoteReason: string | undefined;
  if (!corroborated) {
    demote = true;
    demoteReason =
      klass === "dependency"
        ? "vulnerable dependency is not reachable via the App Map import/third-party graph"
        : "location is not on a registered route, taint sink, or secret surface in the App Map";
  } else if (klass === "injection" && sanitizerInterrupts) {
    demote = true;
    demoteReason = "a validator/sanitizer neutralizes the tainted input before it reaches the sink";
  }

  return {
    klass,
    route,
    routeId: route?.id,
    authState,
    exposure,
    authGate,
    matchedSink,
    matchedSource,
    matchedSecretSurface,
    matchedEntrypoint,
    matchedFlow,
    taintFlowKind,
    sanitizerInterrupts,
    taintReaches,
    corroborated,
    corroborationBasis,
    demote,
    demoteReason,
  };
}
