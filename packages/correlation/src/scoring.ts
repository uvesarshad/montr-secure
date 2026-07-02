/**
 * Ranking scores. PRD §7 Layer 2: rank by reachability × exposure × impact, NOT
 * raw CVSS. Each score is in [0,1] and derived from the deterministic App Map
 * grounding; the combined product is what orders the report.
 */
import type { AuthState, CandidateFinding } from "@montr/contracts";
import type { Grounding } from "./grounding.js";
import { CATEGORY_IMPACT_BASE, SEVERITY_WEIGHT } from "./taxonomy.js";

export interface ScoreTriple {
  reachabilityScore: number;
  exposureScore: number;
  impactScore: number;
}

export function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(1, Math.max(0, n));
}

/** Round to 3 dp so persisted scores are stable and readable. */
export function round3(n: number): number {
  return Math.round(clamp01(n) * 1000) / 1000;
}

/** Exposure score is a pure function of the route's auth state (structural). */
export function exposureScoreFor(authState: AuthState, hasRoute: boolean): number {
  if (!hasRoute) return 0.4; // off-route (secret/dep): reachable via source/build access only
  switch (authState) {
    case "public":
      return 1;
    case "authenticated":
      return 0.5;
    case "role_gated":
      return 0.35;
    case "unknown":
      return 0.5; // fail-safe: unknown auth stays visible for human review
    default:
      return 0.5;
  }
}

export function reachabilityScoreFor(g: Grounding): number {
  switch (g.klass) {
    case "injection":
      if (g.taintReaches) {
        // Strongest when a mapped source on the SAME route reaches the sink.
        const sameRoute =
          g.matchedSource?.routeId !== undefined && g.matchedSource.routeId === g.routeId;
        return sameRoute ? 0.95 : 0.9;
      }
      if (g.matchedSink) return 0.35; // real sink, source not statically traced
      return 0.4;
    case "config":
      return g.route ? 0.5 : 0.25;
    case "secret":
      return g.matchedSecretSurface ? 0.6 : 0.45;
    case "dependency":
      return 0.6; // only promoted when import-graph corroborated
    case "access":
      return g.route ? 0.6 : 0.4;
    default:
      return g.route || g.matchedSink ? 0.5 : 0.3;
  }
}

export function impactScoreFor(cand: CandidateFinding, g: Grounding): number {
  const base = CATEGORY_IMPACT_BASE[cand.category];
  const sev = SEVERITY_WEIGHT[cand.rawSeverity];
  let impact = 0.6 * base + 0.4 * sev;

  // Context: wildcard CORS on a public, non-credentialed endpoint is low impact
  // (no cookies/credentials to steal cross-origin).
  if (cand.category === "permissive_cors" && g.exposure === "public") {
    impact *= 0.5;
  }
  // A hard-coded secret sitting on a mapped secret surface is materially worse.
  if (cand.category === "hardcoded_secret" && g.matchedSecretSurface) {
    impact = Math.max(impact, 0.8);
  }
  // Injection whose taint path is not fully traced keeps a discounted impact.
  if (g.klass === "injection" && !g.taintReaches) {
    impact *= 0.85;
  }
  return clamp01(impact);
}

/** Deterministic base scores for a grounded finding. */
export function scoreGrounding(cand: CandidateFinding, g: Grounding): ScoreTriple {
  return {
    reachabilityScore: reachabilityScoreFor(g),
    exposureScore: exposureScoreFor(g.authState, g.route !== undefined),
    impactScore: impactScoreFor(cand, g),
  };
}

/** Combined ranking key: reachability × exposure × impact. */
export function combinedScore(s: ScoreTriple): number {
  return s.reachabilityScore * s.exposureScore * s.impactScore;
}
