/**
 * Discovery ruleset registry + per-language selection (Layer 1).
 *
 * `runDiscovery` asks this registry which Semgrep rulesets, extra custom
 * detectors, and SCA ecosystems apply to a scanned app, based on the App Map's
 * detected languages. Adding a stack = append its ruleset to
 * {@link LANGUAGE_RULESETS}; the detectors and `runDiscovery` are untouched.
 */
import type { AppMap, Language } from "@montr/contracts";
import type { FileDetector } from "../detectors/secrets.js";
import type { LanguageRuleset } from "./types.js";
import { typescriptRuleset } from "./typescript/index.js";
import { pythonRuleset } from "./python/index.js";
import { javaRuleset } from "./java/index.js";

/**
 * Registered per-language rulesets, stable order. TypeScript, Python, and JVM
 * are all fully implemented (build-plan §7 Wave 4) under `rulesets/<lang>/` —
 * each declares real curated Semgrep rulesets, custom detectors, and SCA
 * ecosystems, not stubs. A future stack is added by appending its ruleset
 * here WITHOUT editing this list's callers.
 */
export const LANGUAGE_RULESETS: readonly LanguageRuleset[] = [
  typescriptRuleset,
  pythonRuleset,
  javaRuleset,
];

/** What an App Map exposes for ruleset selection (its detected languages). */
type LanguagesLike = Pick<AppMap, "languages"> | { languages: readonly Language[] };

/** Rulesets active for the app's detected languages. */
function activeRulesets(
  app: LanguagesLike,
  rulesets: readonly LanguageRuleset[],
): readonly LanguageRuleset[] {
  return rulesets.filter((r) => r.appliesTo(app.languages));
}

function dedupeStable(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

/**
 * Curated Semgrep rulesets for the scanned app (merged + deduped across active
 * languages). ⛔ Fail-safe: an app with no matching stack falls back to the host
 * (TypeScript) rulesets so discovery never silently runs zero rules — Phase-1
 * TS/JS apps therefore get exactly {@link DEFAULT_SEMGREP_RULESETS}.
 */
export function selectSemgrepRulesets(
  app: LanguagesLike,
  rulesets: readonly LanguageRuleset[] = LANGUAGE_RULESETS,
): string[] {
  const active = activeRulesets(app, rulesets);
  const source = active.length > 0 ? active : [typescriptRuleset];
  return dedupeStable(source.flatMap((r) => [...r.semgrepRulesets]));
}

/**
 * Language-specific EXTRA secrets/config detectors for the scanned app, run in
 * addition to the always-on base set. Empty for the Phase-1 TS/JS path (the base
 * detectors already cover it), so secrets behavior is unchanged.
 */
export function selectCustomDetectors(
  app: LanguagesLike,
  rulesets: readonly LanguageRuleset[] = LANGUAGE_RULESETS,
): FileDetector[] {
  return activeRulesets(app, rulesets).flatMap((r) => [...(r.customDetectors ?? [])]);
}

/** SCA advisory ecosystems the scanned app's stacks contribute (e.g. `"npm"`). */
export function selectScaEcosystems(
  app: LanguagesLike,
  rulesets: readonly LanguageRuleset[] = LANGUAGE_RULESETS,
): string[] {
  const active = activeRulesets(app, rulesets);
  const source = active.length > 0 ? active : [typescriptRuleset];
  return dedupeStable(source.flatMap((r) => [...(r.scaEcosystems ?? [])]));
}
