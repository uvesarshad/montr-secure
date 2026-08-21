/**
 * Kill-chain narratives (B8) — grounded in the ACTUAL routes/findings in the
 * scan (real route paths/methods and real finding titles), never a generic
 * template. Built from the resolved `Route` (when available, falling back to
 * the finding's file:line when a route didn't resolve — see `./route-match.ts`)
 * plus each hop's own `ChainCondition` (`./conditions.ts`), which already
 * carries the finding-specific "why this hop enables the next" reasoning.
 */
import type { ConfirmedFinding, Route } from "@montr/contracts";
import type { ChainCondition } from "./conditions.js";

function describeEntry(f: ConfirmedFinding, route: Route | undefined): string {
  if (route) {
    const who =
      route.authState === "public"
        ? "An unauthenticated attacker"
        : `An attacker with ${route.authState.replace(/_/g, " ")} access`;
    return `${who} can exploit ${f.title} at ${route.method} ${route.path}`;
  }
  return `An attacker can exploit ${f.title} at ${f.location.file}:${f.location.line}`;
}

function describeHop(f: ConfirmedFinding, route: Route | undefined): string {
  return route
    ? `${f.title} (${route.method} ${route.path})`
    : `${f.title} (${f.location.file}:${f.location.line})`;
}

function describeTransition(
  condition: ChainCondition | undefined,
  f: ConfirmedFinding,
  route: Route | undefined,
): string {
  switch (condition?.kind) {
    case "rce-post-exploitation":
      return `achieving arbitrary code execution, which then makes ${describeHop(f, route)} trivially reachable`;
    case "idor-credential-leak":
      return `leaking credentials that grant access to ${describeHop(f, route)}`;
    case "ssrf-internal-pivot":
      return `pivoting server-side to reach the internal-only surface at ${describeHop(f, route)}`;
    default:
      return `reaching ${describeHop(f, route)}`;
  }
}

/**
 * Builds the full narrative for one chain. `findings`/`routes` are the
 * ordered hops (index 0 = entry point); `conditions[i]` is the condition
 * connecting `findings[i]` to `findings[i + 1]` (length `findings.length - 1`).
 */
export function buildNarrative(
  findings: readonly ConfirmedFinding[],
  routes: readonly (Route | undefined)[],
  conditions: readonly ChainCondition[],
): string {
  const first = findings[0];
  if (!first) throw new Error("buildNarrative: empty chain");
  const parts: string[] = [describeEntry(first, routes[0])];
  for (let i = 1; i < findings.length; i++) {
    const f = findings[i];
    if (!f) continue;
    parts.push(describeTransition(conditions[i - 1], f, routes[i]));
  }
  return `${parts.join(", ")}.`;
}
