/**
 * TypeScript / JavaScript discovery ruleset (Phase-1 host stack).
 *
 * The curated Semgrep set is the canonical {@link DEFAULT_SEMGREP_RULESETS}; the
 * base secrets/config custom detectors (secrets, CORS, crypto, cookies,
 * NEXT_PUBLIC, next.config headers) already run for every scan, so this ruleset
 * adds no `customDetectors` on top. SCA ships the offline npm advisory mirror.
 */
import type { Language } from "@montr/contracts";
import { DEFAULT_SEMGREP_RULESETS } from "../../detectors/sast.js";
import type { LanguageRuleset } from "../types.js";

export const typescriptRuleset: LanguageRuleset = {
  id: "typescript",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("typescript") || languages.includes("javascript");
  },
  semgrepRulesets: DEFAULT_SEMGREP_RULESETS,
  // Base detectors already cover the TS/Next surface; no extras needed.
  customDetectors: [],
  scaEcosystems: ["npm"],
};
