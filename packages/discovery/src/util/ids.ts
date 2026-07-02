/**
 * Deterministic identity + text helpers. There is NO Date.now()/Math.random in
 * this package's identity path — a candidate id is a stable hash of the finding's
 * identity tuple, so re-runs are idempotent and cross-tool dedup (Layer 2) is
 * trivial. (§5.2)
 */

/** FNV-1a (32-bit) hex hash — same construction @montr/fixtures uses. */
export function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/** Stable candidate id from its identity tuple (source|ruleId|file|line[|extra]). */
export function candidateId(parts: {
  source: string;
  ruleId: string;
  file: string;
  line: number;
  extra?: string;
}): string {
  const key = [parts.source, parts.ruleId, parts.file, String(parts.line), parts.extra ?? ""].join(
    "|",
  );
  return `cand_${parts.source}_${fnv1a(key)}`;
}

/**
 * Clamp text to an in-perimeter, metadata-grade single-line excerpt. Candidate
 * `evidenceSnippet` is metadata — short by construction — and is only ever
 * egressed inside a call to the client's own LLM key (§11, golden rule #1).
 */
export function toSnippet(text: string | undefined, max = 200): string {
  if (!text) return "";
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}
