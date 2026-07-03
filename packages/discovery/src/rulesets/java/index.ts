/**
 * JVM (Spring / JPA) discovery ruleset (Layer 1 stack breadth).
 *
 * Registered in `../registry.ts`; the registry, the detectors, and `runDiscovery`
 * stay untouched — this file only declares the three per-language knobs:
 *   - `semgrepRulesets`: the curated JVM set (`p/java`, `p/spring`), merged +
 *     deduped with any other active stack's rulesets by the registry.
 *   - `customDetectors`: offline Spring config + weak-crypto detectors
 *     ({@link JAVA_DETECTORS}), appended to the always-on base secrets/CORS/crypto/
 *     cookie set (hard-coded creds in `application.{properties,yml}`, wildcard
 *     actuator exposure, weak `MessageDigest`/`Cipher`, disabled CSRF).
 *   - `scaEcosystems`: `"Maven"` (Maven/Gradle advisory ecosystem).
 */
import type { Language } from "@montr/contracts";
import type { LanguageRuleset } from "../types.js";
import { JAVA_DETECTORS } from "./detectors.js";

export const javaRuleset: LanguageRuleset = {
  id: "java",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("java");
  },
  semgrepRulesets: ["p/java", "p/spring"],
  customDetectors: JAVA_DETECTORS,
  scaEcosystems: ["Maven"],
};
