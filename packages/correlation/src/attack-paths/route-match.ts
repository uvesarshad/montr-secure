/**
 * Route resolution for attack-path chaining (B8). `ConfirmedFinding` carries
 * no `routeId` (only `ProbableFinding` does — see
 * `packages/contracts/src/findings.ts`), so this resolves a `ConfirmedFinding`
 * back to the `Route` whose handler lives in the same file, picking the route
 * whose handler line is nearest the finding's location when a file registers
 * more than one route. This mirrors the identical file+nearest-line
 * convention already implemented independently three times for the same
 * problem across `packages/confirm/src/{static,live,investigation-pipeline}.ts`
 * (`findRoute`/`routeFor`/`findRouteForInvestigation`) — kept as a small local
 * copy here rather than importing across the `packages/confirm` boundary
 * (out of scope for this task) or exporting a new symbol from
 * `../grounding.ts` (left untouched per the read-only constraint on
 * `packages/correlation`'s existing scoring/grounding logic).
 */
import type { AppMap, ConfirmedFinding, Route } from "@montr/contracts";

function indexRoutesByFile(appMap: AppMap): Map<string, Route[]> {
  const byFile = new Map<string, Route[]>();
  for (const route of appMap.routes) {
    if (!route.handler?.file) continue;
    const arr = byFile.get(route.handler.file);
    if (arr) arr.push(route);
    else byFile.set(route.handler.file, [route]);
  }
  return byFile;
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

/**
 * Resolves every confirmed finding to its `Route` (undefined when
 * unresolved — no route handler shares the finding's file), once, indexed by
 * finding id.
 */
export function resolveRoutes(
  appMap: AppMap,
  findings: readonly ConfirmedFinding[],
): Map<string, Route | undefined> {
  const byFile = indexRoutesByFile(appMap);
  const out = new Map<string, Route | undefined>();
  for (const f of findings) {
    const inFile = byFile.get(f.location.file) ?? [];
    out.set(f.id, pickNearestRoute(inFile, f.location.line));
  }
  return out;
}
