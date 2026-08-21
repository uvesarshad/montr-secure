/**
 * Chain-step conditions (B8). Two confirmed findings F1 -> F2 form a genuine
 * kill-chain step only when a CONCRETE, CHECKABLE structural condition holds
 * — never "any two findings on the same host" (that is combinatorial noise,
 * not a kill chain). Three conditions, in decreasing order of certainty
 * (reflected in `ChainCondition.strength`, consumed by `../feasibility.ts` —
 * actually `./feasibility.ts`):
 *
 *  1. `rce-post-exploitation` — F1 is RCE-class (command injection or
 *     insecure deserialization — `RCE_CATEGORIES`). Once an attacker has
 *     arbitrary code execution on the host, EVERY other confirmed finding on
 *     that same target (same `scanId` — a scan targets one repo/deployment,
 *     the closest proxy for "host" this schema exposes) becomes trivially
 *     reachable — the classic "game over" case. This is flagged with its own
 *     `kind` because its semantics genuinely differ from the other two: it is
 *     not "F1 unlocks specific access to F2", it is "F1 makes everything
 *     after it moot" (`../graph.ts` also force-bumps end-to-end severity to
 *     "critical" whenever this condition appears in a chain).
 *  2. `idor-credential-leak` — F1 is an access-control-class finding
 *     (`idor`/`broken_access_control`/`broken_authentication`/
 *     `mass_assignment` — `ACCESS_CATEGORIES`, `../taxonomy.ts`) whose route
 *     statically reads (A18 route -> ORM-model fan-out) a model containing a
 *     credential-shaped field (`./credentials.ts`), AND F2 sits on a
 *     DIFFERENT route that is not `public` — i.e. actually gated by
 *     something F1's leaked credential could plausibly satisfy.
 *  3. `ssrf-internal-pivot` — F1 is an `ssrf` finding, AND F2 sits on a
 *     DIFFERENT route whose resolved auth state is not `public` — the
 *     closest structural proxy this App Map exposes for "only reachable from
 *     internal network space" (there is no explicit internal/external
 *     network classification in the schema yet — see the AGENT NOTE in
 *     docs/modules/correlation.md). Deliberately the weakest condition: an
 *     SSRF finding proves a request can be redirected server-side, not that
 *     the specific internal target it lands on is this specific F2. When the
 *     App Map's own `taintSinks` corroborate an `http_client`-kind sink in
 *     F1's file (real outbound-request evidence, not just the category tag),
 *     the strength is nudged up — still capped well below the other two.
 */
import type { AppMap, ConfirmedFinding, Route } from "@montr/contracts";
import { ACCESS_CATEGORIES } from "../taxonomy.js";
import { routeLeaksCredentials } from "./credentials.js";

export const RCE_CATEGORIES: ReadonlySet<ConfirmedFinding["category"]> = new Set([
  "command_injection",
  "insecure_deserialization",
]);

export type ChainConditionKind =
  "rce-post-exploitation" | "idor-credential-leak" | "ssrf-internal-pivot";

export interface ChainCondition {
  kind: ChainConditionKind;
  /** [0,1] structural confidence this condition genuinely connects the two hops (`./feasibility.ts`). */
  strength: number;
  /** Human-readable, finding-specific reason this hop enables the next (feeds `AttackPathStep.note`/`./narrative.ts`). */
  note: string;
}

function isRceClass(f: ConfirmedFinding): boolean {
  return RCE_CATEGORIES.has(f.category);
}

/** Not "public" — either the resolved route says so, or (route unresolved) the finding's own coarse exposure does. */
function requiresMoreThanPublicAccess(
  route: Route | undefined,
  fallbackExposure: ConfirmedFinding["exposure"],
): boolean {
  if (route) return route.authState !== "public";
  return fallbackExposure !== "public";
}

/**
 * Same handler surface? Prefers real `Route` identity (id, else path+method);
 * falls back to same source file when neither finding's route resolved — the
 * closest proxy for "same handler" this schema offers, and the same file-based
 * identity `../grounding.ts`/`./route-match.ts` already use to resolve a route
 * in the first place.
 */
function sameRoute(
  f1: ConfirmedFinding,
  f2: ConfirmedFinding,
  r1: Route | undefined,
  r2: Route | undefined,
): boolean {
  if (r1 && r2) {
    if (r1.id && r2.id) return r1.id === r2.id;
    return r1.path === r2.path && r1.method === r2.method;
  }
  if (r1 || r2) return false; // one resolved, one didn't: treat as distinct surfaces
  return f1.location.file === f2.location.file;
}

/** Real outbound-request evidence (not just the `ssrf` category tag) at F1's location. */
function hasHttpClientSinkNearby(appMap: AppMap, f1: ConfirmedFinding): boolean {
  return appMap.taintSinks.some(
    (sink) => sink.kind === "http_client" && sink.location.file === f1.location.file,
  );
}

/**
 * Evaluates all three conditions for an ordered pair (f1 -> f2 as a chain
 * step) and returns the STRONGEST that applies, or `undefined` when none do.
 */
export function evaluateChainCondition(
  appMap: AppMap,
  f1: ConfirmedFinding,
  f2: ConfirmedFinding,
  route1: Route | undefined,
  route2: Route | undefined,
): ChainCondition | undefined {
  const candidates: ChainCondition[] = [];

  if (isRceClass(f1)) {
    candidates.push({
      kind: "rce-post-exploitation",
      strength: 0.95,
      note: `${f1.title} grants arbitrary code execution on the host — every other confirmed finding on this target, including "${f2.title}", is reachable post-exploitation.`,
    });
  }

  if (
    ACCESS_CATEGORIES.has(f1.category) &&
    !sameRoute(f1, f2, route1, route2) &&
    routeLeaksCredentials(appMap, route1) &&
    requiresMoreThanPublicAccess(route2, f2.exposure)
  ) {
    candidates.push({
      kind: "idor-credential-leak",
      strength: 0.6,
      note: `${f1.title} exposes a model with a credential-shaped field via its route -> ORM fan-out; the leaked credential can plausibly satisfy the auth gate on "${f2.title}"'s route.`,
    });
  }

  if (
    f1.category === "ssrf" &&
    !sameRoute(f1, f2, route1, route2) &&
    requiresMoreThanPublicAccess(route2, f2.exposure)
  ) {
    candidates.push({
      kind: "ssrf-internal-pivot",
      strength: hasHttpClientSinkNearby(appMap, f1) ? 0.55 : 0.45,
      note: `${f1.title} lets an attacker redirect server-side requests; "${f2.title}"'s route is not directly public, consistent with being reachable only from the internal network space the SSRF can pivot into.`,
    });
  }

  if (candidates.length === 0) return undefined;
  candidates.sort((a, b) => b.strength - a.strength);
  return candidates[0];
}
