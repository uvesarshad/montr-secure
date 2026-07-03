/**
 * Per-language discovery ruleset contract (Layer 1 stack breadth).
 *
 * Layer 1 is deliberately over-inclusive; WHAT it runs per stack is the only
 * language-specific part. A {@link LanguageRuleset} bundles the three knobs that
 * vary by language — the curated Semgrep rulesets, extra secrets/config
 * detectors, and the SCA advisory ecosystems — behind one seam. Adding a stack =
 * drop a ruleset under `rulesets/<lang>/` and append it to the registry; the
 * detectors (`sast`/`secrets`/`sca`) and `runDiscovery` stay untouched.
 */
import type { Language } from "@montr/contracts";
import type { FileDetector } from "../detectors/secrets.js";

export interface LanguageRuleset {
  /** Primary language this ruleset owns (also its stable registry key). */
  readonly id: Language;
  /** True when this ruleset applies to the scanned app's detected languages. */
  appliesTo(languages: readonly Language[]): boolean;
  /**
   * Curated Semgrep rulesets for this stack (e.g. `p/typescript`, `p/django`,
   * `p/java`). Merged + deduped across every active language.
   */
  readonly semgrepRulesets: readonly string[];
  /**
   * Language-specific EXTRA secrets/config detectors, run IN ADDITION to the
   * always-on base set (secrets/CORS/crypto/cookies). Optional.
   */
  readonly customDetectors?: readonly FileDetector[];
  /**
   * SCA advisory ecosystems this stack contributes (e.g. `"npm"`, `"PyPI"`,
   * `"Maven"`). The Phase-1 SCA detector ships the offline npm mirror; the
   * Python/JVM agents add their ecosystem's lockfile parser + advisory source
   * behind this declaration. Optional.
   */
  readonly scaEcosystems?: readonly string[];
}
