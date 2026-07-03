/**
 * Python (Django / FastAPI / Flask) discovery ruleset (Layer 1 stack breadth).
 *
 * ⛔ SEAM FOR THE PYTHON STACK AGENT (build-plan §7 Wave 4, PRD §16 Phase 3).
 * Registered in `../registry.ts`; the registry, the detectors, and `runDiscovery`
 * stay untouched — this file only declares the three per-language knobs:
 *   - `semgrepRulesets`: the curated Python set (`p/python`, `p/django`, `p/flask`),
 *     merged + deduped with any other active stack's rulesets by the registry.
 *   - `customDetectors`: offline Django/Flask config detectors ({@link PYTHON_DETECTORS}),
 *     appended to the always-on base secrets/CORS/crypto/cookie set.
 *   - `scaEcosystems`: `"PyPI"` (pip/poetry advisory ecosystem).
 */
import type { Language } from "@montr/contracts";
import type { LanguageRuleset } from "../types.js";
import { PYTHON_DETECTORS } from "./detectors.js";

export const pythonRuleset: LanguageRuleset = {
  id: "python",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("python");
  },
  semgrepRulesets: ["p/python", "p/django", "p/flask"],
  customDetectors: PYTHON_DETECTORS,
  scaEcosystems: ["PyPI"],
};
