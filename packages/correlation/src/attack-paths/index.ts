/**
 * Attack-path graph (B8) — chains `ConfirmedFinding[]` into realistic kill
 * chains ("public route -> SSRF -> metadata endpoint -> credentials") across
 * three concrete, checkable structural conditions (`./conditions.ts`):
 * RCE-class findings make everything after them reachable, IDOR/broken-
 * access-control findings that leak a credential-shaped field unlock a
 * DIFFERENT, non-public route, and SSRF findings pivot into a DIFFERENT,
 * non-public route as the closest structural proxy this schema has for
 * "internal network space". Feasibility (`./feasibility.ts`) is the PRODUCT
 * of each hop's own confirmation confidence (live-DAST-proven vs.
 * static-proof-only) and each connecting condition's structural strength —
 * not an average, so one speculative hop can't hide behind strong ones.
 * Results are ranked by feasibility then severity and deliberately keep only
 * MAXIMAL chains (`./graph.ts`), so a real 4-hop kill chain is never buried
 * under its own redundant 2-hop prefixes.
 *
 * Landed inside `packages/correlation` rather than `packages/report`: its
 * core dependency — resolving a `ConfirmedFinding` back to the `Route`/
 * `OrmModel` structure that makes a chain condition CHECKABLE rather than a
 * hand-wave — is exactly the App Map grounding machinery this package
 * already owns (`../grounding.ts`'s file+nearest-line route convention,
 * mirrored locally in `./route-match.ts`; `../taxonomy.ts`'s category
 * classification, reused as-is). Existing correlation scoring/grounding
 * files (`../grounding.ts`, `../scoring.ts`, `../correlate.ts`) are untouched
 * — this only reads `clamp01`/`round3` and `SEVERITY_WEIGHT`/
 * `ACCESS_CATEGORIES` from them.
 *
 * NOT wired into `../correlate.ts` (Layer 2 runs on `CandidateFinding[]`,
 * before any finding is confirmed) and NOT wired into `packages/report`'s
 * report assembly yet (`../correlate.ts` runs at Layer 2; this module
 * operates on Layer 3's `ConfirmedFinding[]` output, once exploitability is
 * already proven — B10, a later wave, is what puts a report-facing blue-team
 * section on top of the `AttackPath` rows `./persist.ts` writes).
 */
export {
  buildAttackPaths,
  buildAttackPathCandidates,
  type AttackPathCandidate,
  type BuildAttackPathsInput,
} from "./graph.js";
export { discoverAndPersistAttackPaths } from "./persist.js";
export {
  evaluateChainCondition,
  RCE_CATEGORIES,
  type ChainCondition,
  type ChainConditionKind,
} from "./conditions.js";
export { computeFeasibility, findingConfidence } from "./feasibility.js";
export {
  CREDENTIAL_FIELD_PATTERN,
  modelHasCredentialField,
  routeLeaksCredentials,
} from "./credentials.js";
export { resolveRoutes } from "./route-match.js";
export { buildNarrative } from "./narrative.js";
