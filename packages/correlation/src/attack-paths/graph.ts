/**
 * Attack-path graph (B8) — chains `ConfirmedFinding[]` into realistic kill
 * chains via `./conditions.ts`'s three concrete, checkable structural
 * conditions, scores end-to-end feasibility (`./feasibility.ts`), and ranks
 * the result. See `./index.ts` for the module-level design rationale
 * (why `packages/correlation`, why not wired into `../correlate.ts`).
 */
import type {
  AppMap,
  AttackPath,
  AttackPathStep,
  ConfirmedFinding,
  Route,
  Severity,
} from "@montr/contracts";
import { fnv1a } from "../hash.js";
import { SEVERITY_WEIGHT } from "../taxonomy.js";
import { evaluateChainCondition, type ChainCondition } from "./conditions.js";
import { computeFeasibility } from "./feasibility.js";
import { buildNarrative } from "./narrative.js";
import { resolveRoutes } from "./route-match.js";

/** Hard bound on chain length — bounds DFS depth on a dense condition graph. */
const DEFAULT_MAX_CHAIN_LENGTH = 5;
/** Cap on emitted paths after ranking — the actionable signal is the top chains, not every combinatorial one. */
const DEFAULT_MAX_PATHS = 50;
/** Safety valve against pathological fan-out (e.g. many RCE findings on one scan). */
const MAX_RAW_PATHS = 5000;

export interface BuildAttackPathsInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  findings: readonly ConfirmedFinding[];
  /** ISO timestamp stamped on emitted paths (tests inject a fixed value; defaults to now). */
  now?: string;
  /** Max hops per chain (default 5). */
  maxChainLength?: number;
  /** Max paths returned after ranking (default 50). */
  maxPaths?: number;
}

/**
 * A discovered chain with its full structural evidence still attached — the
 * conditions that connect each hop, and the resolved `Route` per hop — for
 * callers (tests, a future report renderer) that need to introspect WHY a
 * chain was formed, not just the persisted `AttackPath` row. `attackPath` is
 * exactly what `discoverAndPersistAttackPaths` (`./persist.ts`) writes via
 * `StateStore.attackPaths`.
 */
export interface AttackPathCandidate {
  attackPath: AttackPath;
  findings: ConfirmedFinding[];
  routes: Array<Route | undefined>;
  /** `conditions[i]` connects `findings[i]` to `findings[i + 1]` (length `findings.length - 1`). */
  conditions: ChainCondition[];
}

interface Edge {
  to: number;
  condition: ChainCondition;
}

function severityRank(s: Severity): number {
  return SEVERITY_WEIGHT[s];
}

/** End-to-end severity: the max hop severity, force-bumped to "critical" once an RCE hop is present (A24/B8 rationale in ./conditions.ts). */
function pathSeverity(
  findings: readonly ConfirmedFinding[],
  conditions: readonly ChainCondition[],
): Severity {
  let best: Severity = "info";
  for (const f of findings) if (severityRank(f.severity) > severityRank(best)) best = f.severity;
  if (conditions.some((c) => c.kind === "rce-post-exploitation")) return "critical";
  return best;
}

function makePathId(scanId: string, findingIds: readonly string[]): string {
  return `ap_${fnv1a(`${scanId}|${findingIds.join(">")}`)}`;
}

function buildAdjacency(
  appMap: AppMap,
  findings: readonly ConfirmedFinding[],
  routeByFindingId: Map<string, Route | undefined>,
): Edge[][] {
  const adjacency: Edge[][] = findings.map(() => []);
  for (let i = 0; i < findings.length; i++) {
    for (let j = 0; j < findings.length; j++) {
      if (i === j) continue;
      const f1 = findings[i]!;
      const f2 = findings[j]!;
      const condition = evaluateChainCondition(
        appMap,
        f1,
        f2,
        routeByFindingId.get(f1.id),
        routeByFindingId.get(f2.id),
      );
      if (condition) adjacency[i]!.push({ to: j, condition });
    }
  }
  return adjacency;
}

/**
 * Enumerates every MAXIMAL simple path (no repeated node, and not itself a
 * prefix of a longer path reachable from the same start) reachable in
 * `adjacency`, length in [2, maxChainLength]. A path is recorded only once
 * DFS can no longer extend it — so a 2-hop chain that IS the start of a real
 * 4-hop kill chain never gets emitted as a separate, redundant "finding": the
 * exact "40 speculative 2-step chains burying the one real 4-step chain"
 * failure mode the ranking exists to avoid.
 */
function enumerateMaximalPaths(
  adjacency: Edge[][],
  maxChainLength: number,
): Array<{ path: number[]; conditions: ChainCondition[] }> {
  const out: Array<{ path: number[]; conditions: ChainCondition[] }> = [];

  function record(path: number[], conditions: ChainCondition[]): void {
    if (path.length >= 2 && out.length < MAX_RAW_PATHS) {
      out.push({ path: [...path], conditions: [...conditions] });
    }
  }

  function dfs(path: number[], conditions: ChainCondition[], visited: Set<number>): void {
    if (out.length >= MAX_RAW_PATHS) return;
    if (path.length >= maxChainLength) {
      record(path, conditions);
      return;
    }
    const last = path[path.length - 1]!;
    let extended = false;
    for (const edge of adjacency[last]!) {
      if (visited.has(edge.to)) continue;
      extended = true;
      visited.add(edge.to);
      path.push(edge.to);
      conditions.push(edge.condition);
      dfs(path, conditions, visited);
      conditions.pop();
      path.pop();
      visited.delete(edge.to);
    }
    if (!extended) record(path, conditions);
  }

  for (let start = 0; start < adjacency.length; start++) {
    dfs([start], [], new Set([start]));
  }
  return out;
}

/** The full, introspectable candidate list (`./index.ts` exports both this and the plain `AttackPath[]` convenience wrapper). */
export function buildAttackPathCandidates(input: BuildAttackPathsInput): AttackPathCandidate[] {
  const { clientId, scanId, appMap, findings } = input;
  if (findings.length < 2) return [];

  const maxChainLength = input.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH;
  const maxPaths = input.maxPaths ?? DEFAULT_MAX_PATHS;
  const now = input.now ?? new Date().toISOString();

  const routeByFindingId = resolveRoutes(appMap, findings);
  const adjacency = buildAdjacency(appMap, findings, routeByFindingId);
  const rawPaths = enumerateMaximalPaths(adjacency, maxChainLength);

  const candidates: AttackPathCandidate[] = rawPaths.map(({ path, conditions }) => {
    const pathFindings = path.map((idx) => findings[idx]!);
    const routes = path.map((idx) => routeByFindingId.get(findings[idx]!.id));
    const findingIds = pathFindings.map((f) => f.id);
    const steps: AttackPathStep[] = pathFindings.map((f, i) => ({
      findingId: f.id,
      note: conditions[i]?.note,
    }));
    return {
      attackPath: {
        id: makePathId(scanId, findingIds),
        clientId,
        scanId,
        steps,
        feasibilityScore: computeFeasibility(pathFindings, conditions),
        severity: pathSeverity(pathFindings, conditions),
        narrative: buildNarrative(pathFindings, routes, conditions),
        createdAt: now,
      },
      findings: pathFindings,
      routes,
      conditions,
    };
  });

  candidates.sort((a, b) => {
    if (b.attackPath.feasibilityScore !== a.attackPath.feasibilityScore) {
      return b.attackPath.feasibilityScore - a.attackPath.feasibilityScore;
    }
    return severityRank(b.attackPath.severity) - severityRank(a.attackPath.severity);
  });

  return candidates.slice(0, maxPaths);
}

/** Ranked `AttackPath[]` ready to persist via `StateStore.attackPaths` (`./persist.ts`). */
export function buildAttackPaths(input: BuildAttackPathsInput): AttackPath[] {
  return buildAttackPathCandidates(input).map((c) => c.attackPath);
}
