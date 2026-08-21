/**
 * Targeted line-range edit format for LLM-proposed fixes (audit finding A14).
 *
 * The OLD contract asked the model to return `{"fixedSource": "<the full fixed
 * file>"}` — the ENTIRE file, rewritten. Any file over roughly 1,500 lines
 * could not fit in the response: the output truncated mid-string, `JSON.parse`
 * failed, and the fix silently degraded to a mechanical strategy or an
 * advisory, with no error, no metric, no retry.
 *
 * This module replaces that with a small set of 1-based, inclusive LINE-RANGE
 * edits scoped to only the lines that actually change. A model editing a
 * 50-line vulnerable snippet inside a 3,000-line file now only has to emit
 * those ~50 lines (plus a short rationale) — not the other 2,950. The
 * reconstructed full source is fed into the EXISTING `buildUnifiedDiff` /
 * `validatePatch` pipeline (patch.ts) unchanged — there is no parallel
 * diff-apply mechanism; `generate.ts` still hands `patch.ts` a full
 * (original, fixed) source pair exactly as it always has.
 */

export interface LlmEdit {
  /** 1-based, inclusive start line in the ORIGINAL source. */
  startLine: number;
  /** 1-based, inclusive end line in the ORIGINAL source (>= startLine). */
  endLine: number;
  /** Replacement text for lines startLine..endLine, WITHOUT line-number prefixes. */
  replacement: string;
}

/**
 * Prefix every line with its 1-based line number (`"12: const x = 1;"`), so the
 * model can address exact, original-file line ranges in its edits. Only used to
 * build the prompt sent TO the model — replacements the model returns must NOT
 * carry this prefix (the system prompt says so explicitly).
 */
export function numberLines(source: string): string {
  return source
    .split("\n")
    .map((line, i) => `${i + 1}: ${line}`)
    .join("\n");
}

/**
 * Parse and structurally validate a raw `edits` value from a model response.
 * Returns `null` on ANY problem — not an array, empty, a malformed entry,
 * non-integer/out-of-range line numbers, or overlapping ranges — so the caller
 * can treat `null` exactly like the old "no usable proposal" case (fall
 * through to the deterministic strategy / advisory) while still recording
 * that a proposal came back that could not be used.
 *
 * On success, returns the edits sorted ascending by `startLine` (the order
 * {@link applyLineEdits} requires).
 */
export function parseLlmEdits(value: unknown, totalLines: number): LlmEdit[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;

  const edits: LlmEdit[] = [];
  for (const entry of value) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return null;
    const { startLine, endLine, replacement } = entry as Record<string, unknown>;
    if (
      typeof startLine !== "number" ||
      typeof endLine !== "number" ||
      typeof replacement !== "string" ||
      !Number.isInteger(startLine) ||
      !Number.isInteger(endLine) ||
      startLine < 1 ||
      endLine < startLine ||
      endLine > totalLines
    ) {
      return null;
    }
    edits.push({ startLine, endLine, replacement });
  }

  const sorted = [...edits].sort((a, b) => a.startLine - b.startLine);
  for (let i = 1; i < sorted.length; i++) {
    // Overlap (or duplicate) range — reject rather than guess a resolution order.
    if (sorted[i]!.startLine <= sorted[i - 1]!.endLine) return null;
  }
  return sorted;
}

/**
 * Apply validated, non-overlapping, ascending-sorted edits to `original`.
 * Splices from the LAST edit to the FIRST so an earlier edit's line numbers
 * never shift out from under a later one still to be applied. Returns the
 * fully reconstructed fixed source — the only output of this module; nothing
 * downstream needs to know edits were ever involved.
 */
export function applyLineEdits(original: string, edits: readonly LlmEdit[]): string {
  const lines = original.split("\n");
  for (let i = edits.length - 1; i >= 0; i--) {
    const edit = edits[i]!;
    const replacementLines = edit.replacement.split("\n");
    lines.splice(edit.startLine - 1, edit.endLine - edit.startLine + 1, ...replacementLines);
  }
  return lines.join("\n");
}
