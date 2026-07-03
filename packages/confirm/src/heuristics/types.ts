/**
 * Per-language confirmation heuristics (Layer 3a stack breadth).
 *
 * Static confirmation is STACK-AGNOSTIC: it proves reachability over the App
 * Map's taint source→sink graph (`static.ts` / `taxonomy.ts`), which carries no
 * language-specific fields. The only language-sensitive knobs are the lexical
 * hints used to judge whether a sink is sanitized and to name the request
 * parameter. A {@link ConfirmationHeuristics} plugin contributes EXTRA such
 * hints for its stack, ADDED on top of the stack-agnostic base — it can only
 * make confirmation more precise, never bypass the deterministic proof.
 *
 * Adding a stack = drop a plugin under `heuristics/<lang>/` and append it to the
 * registry; `static.ts`, `taxonomy.ts`, and every other layer stay untouched.
 */
import type { Language, TaintSinkKind } from "@montr/contracts";

export interface ConfirmationHeuristics {
  /** Primary language this plugin owns (also its stable registry key). */
  readonly id: Language;
  /** True when this plugin applies to the App Map's detected languages. */
  appliesTo(languages: readonly Language[]): boolean;
  /** Extra description substrings signalling an UNSANITIZED construct. */
  readonly unsafeMarkers?: readonly string[];
  /** Extra description substrings signalling a sanitizer/validator on the path. */
  readonly safeMarkers?: readonly string[];
  /** Extra regexes extracting the request-parameter name from a source description. */
  readonly paramPatterns?: readonly RegExp[];
  /** Extra sink kinds that are inherently raw/dangerous absent a sanitizer. */
  readonly rawSinkKinds?: readonly TaintSinkKind[];
}

/** The merged EXTRA heuristics for one App Map (base lives in `taxonomy.ts`). */
export interface ResolvedHeuristics {
  unsafeMarkers: readonly string[];
  safeMarkers: readonly string[];
  paramPatterns: readonly RegExp[];
  rawSinkKinds: readonly TaintSinkKind[];
}

/** Empty extras — the identity element for the merge + the TS/base default. */
export const EMPTY_HEURISTICS: ResolvedHeuristics = {
  unsafeMarkers: [],
  safeMarkers: [],
  paramPatterns: [],
  rawSinkKinds: [],
};
