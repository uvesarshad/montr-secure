/**
 * JVM (Spring / JPA) discovery ruleset (Layer 1 stack breadth).
 *
 * Registered in `../registry.ts`; the registry, the detectors, and `runDiscovery`
 * stay untouched — this file only declares the three per-language knobs:
 *   - `semgrepRulesets`: the curated JVM set ({@link DEFAULT_SEMGREP_RULESETS}),
 *     merged + deduped with any other active stack's rulesets by the registry.
 *   - `customDetectors`: offline Spring config + weak-crypto detectors
 *     ({@link JAVA_DETECTORS}), appended to the always-on base secrets/CORS/crypto/
 *     cookie set (hard-coded creds in `application.{properties,yml}`, wildcard
 *     actuator exposure, weak `MessageDigest`/`Cipher`, disabled CSRF).
 *   - `scaEcosystems`: `"Maven"` (Maven/Gradle advisory ecosystem).
 *
 * ⛔ A33 (P0, closes an audit finding from the OWASP-benchmark pass, E14): this
 * used to be `["p/java", "p/spring"]`. The `p/spring` Semgrep Registry pack no
 * longer resolves — verified directly against Semgrep's own raw config-fetch
 * endpoint (`curl -sI https://semgrep.dev/c/p/spring` -> `404`; `p/java` on the
 * same endpoint -> `200`) and against the Registry's `rulesets` listing API,
 * which has no `spring`/`spring-boot`/`spring-security`-named pack at all
 * today. Because Semgrep aborts its ENTIRE `--json` invocation when even ONE
 * `--config` target fails to resolve (not just the failing pack), shipping a
 * dead pack ID here silently zeroed EVERY JVM SAST finding for EVERY scan —
 * confirmed empirically: swapping to `p/java`-only raised a benchmark subset
 * from 0 to 5 confirmed findings. No current Registry pack is Spring-specific
 * (`p/findsecbugs`, `p/security-audit`, and `p/java` are the closest generic
 * JVM security packs, per the Registry's own `languages`/`tags` metadata), so
 * this now runs `p/java` alone rather than guessing at a replacement pack this
 * change can't verify covers the same rule set. Structural fix, applying to
 * every language's ruleset list (not just this one): `detectSast`
 * (`../../detectors/sast.ts`) now resolves each `--config` entry in ITS OWN
 * Semgrep invocation, so one dead/unresolvable pack can only take out its own
 * findings — see that file's module doc for the full mechanism.
 */
import type { Language } from "@montr/contracts";
import type { LanguageRuleset } from "../types.js";
import { JAVA_DETECTORS } from "./detectors.js";

export const javaRuleset: LanguageRuleset = {
  id: "java",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("java");
  },
  semgrepRulesets: ["p/java"],
  customDetectors: JAVA_DETECTORS,
  scaEcosystems: ["Maven"],
};
