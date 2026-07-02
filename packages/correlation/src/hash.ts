/**
 * Deterministic id helpers. Correlation must be reproducible (offline
 * golden-corpus tests) — no Date.now()/Math.random() anywhere here.
 */

/** FNV-1a (32-bit) hex hash. Stable across runs and platforms. */
export function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/** Stable root-cause id derived from (scan, category, dedup key). */
export function makeRootCauseId(scanId: string, category: string, key: string): string {
  return `rc_${category}_${fnv1a(`${scanId}|${category}|${key}`)}`;
}

/** Stable probable-finding id derived from (scan, root cause). */
export function makeProbableId(scanId: string, rootCauseId: string): string {
  return `prob_${fnv1a(`${scanId}|${rootCauseId}`)}`;
}
