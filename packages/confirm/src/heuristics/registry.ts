/**
 * Confirmation-heuristics registry + resolver (Layer 3a).
 *
 * `static.ts` calls {@link resolveHeuristics} with the App Map to get the EXTRA,
 * language-specific lexical hints to append to the stack-agnostic base in
 * `taxonomy.ts`. Adding a stack = append its plugin to {@link HEURISTICS}; the
 * confirmation engine is untouched. ⛔ Extras only ADD precision — the
 * deterministic data-flow proof remains authoritative (golden rules #4, #6).
 */
import type { AppMap, Language, TaintSinkKind } from "@montr/contracts";
import { typescriptHeuristics } from "./typescript/index.js";
import { pythonHeuristics } from "./python/index.js";
import { javaHeuristics } from "./java/index.js";
import { EMPTY_HEURISTICS, type ConfirmationHeuristics, type ResolvedHeuristics } from "./types.js";

/**
 * Registered per-language heuristics, stable order. Phase 1 ships TypeScript;
 * Python + JVM are pre-registered stubs (build-plan §7 Wave 4) their stack
 * agents fill under `heuristics/<lang>/` WITHOUT editing this list.
 */
export const HEURISTICS: readonly ConfirmationHeuristics[] = [
  typescriptHeuristics,
  pythonHeuristics,
  javaHeuristics,
];

/** What the resolver needs from an App Map (its detected languages). */
type LanguagesLike = Pick<AppMap, "languages"> | { languages: readonly Language[] };

/**
 * Merge the EXTRA heuristics for an App Map's detected languages. When no plugin
 * contributes (the Phase-1 TS/JS path — its heuristics live in the base), this
 * returns {@link EMPTY_HEURISTICS}, so `assessSink`/`extractParam` behave exactly
 * as the base does.
 */
export function resolveHeuristics(
  app: LanguagesLike,
  plugins: readonly ConfirmationHeuristics[] = HEURISTICS,
): ResolvedHeuristics {
  const active = plugins.filter((p) => p.appliesTo(app.languages));
  if (active.length === 0) return EMPTY_HEURISTICS;

  const unsafeMarkers: string[] = [];
  const safeMarkers: string[] = [];
  const paramPatterns: RegExp[] = [];
  const rawSinkKinds: TaintSinkKind[] = [];
  for (const p of active) {
    if (p.unsafeMarkers) unsafeMarkers.push(...p.unsafeMarkers);
    if (p.safeMarkers) safeMarkers.push(...p.safeMarkers);
    if (p.paramPatterns) paramPatterns.push(...p.paramPatterns);
    if (p.rawSinkKinds) rawSinkKinds.push(...p.rawSinkKinds);
  }
  return { unsafeMarkers, safeMarkers, paramPatterns, rawSinkKinds };
}
