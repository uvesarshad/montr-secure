/**
 * TypeScript / JavaScript confirmation heuristics (Phase-1 host stack).
 *
 * The Phase-1 static-confirmation markers (raw-query/`dangerouslySetInnerHTML`/
 * `child_process` unsafe hints, `parameterized`/`sanitiz`/`findMany` safe hints,
 * `.query`/`searchParams` param patterns) already live in the stack-agnostic
 * base in `taxonomy.ts`, so this plugin contributes NO extras today. It is the
 * seam the Python/JVM plugins mirror — TS-specific refinements are added here
 * (appended after the base), never in the shared confirmation engine.
 */
import type { Language } from "@montr/contracts";
import type { ConfirmationHeuristics } from "../types.js";

export const typescriptHeuristics: ConfirmationHeuristics = {
  id: "typescript",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("typescript") || languages.includes("javascript");
  },
  // Base (taxonomy.ts) already covers the TS/Node surface — no extras.
  unsafeMarkers: [],
  safeMarkers: [],
  paramPatterns: [],
  rawSinkKinds: [],
};
