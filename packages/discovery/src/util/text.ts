/** Small, dependency-free text/collection helpers used across the detectors. */

/** A single regex match with its 1-based line number and matched text. */
export interface LineMatch {
  line: number;
  text: string;
  index: number;
}

/**
 * Iterate every match of a GLOBAL regex over `content`, resolving each to a
 * 1-based line number. The regex MUST have the global flag; we reset lastIndex
 * defensively so callers can reuse a shared pattern.
 */
export function iterMatches(content: string, re: RegExp): LineMatch[] {
  const pattern = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  pattern.lastIndex = 0;
  const out: LineMatch[] = [];
  // Precompute line-start offsets for O(matches * log lines) resolution.
  const lineStarts = computeLineStarts(content);
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(content)) !== null) {
    const idx = m.index;
    out.push({ line: lineFromOffset(lineStarts, idx), text: m[0], index: idx });
    // Guard against zero-width matches looping forever.
    if (m.index === pattern.lastIndex) pattern.lastIndex++;
  }
  return out;
}

function computeLineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) starts.push(i + 1);
  }
  return starts;
}

function lineFromOffset(lineStarts: number[], offset: number): number {
  // Binary search for the greatest lineStart <= offset.
  let lo = 0;
  let hi = lineStarts.length - 1;
  let ans = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const start = lineStarts[mid] ?? 0;
    if (start <= offset) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return ans + 1;
}

/** 1-based line number of the first occurrence of `needle`, or 0 if absent. */
export function lineOfFirst(content: string, needle: string): number {
  const idx = content.indexOf(needle);
  if (idx < 0) return 0;
  let line = 1;
  for (let i = 0; i < idx; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/** Count occurrences of each key produced by `keyOf`. */
export function countBy<T>(
  items: readonly T[],
  keyOf: (item: T) => string,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = keyOf(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

/** Best-effort message from an unknown thrown value (never leaks a stack to callers). */
export function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

/** True if a thrown value looks like a missing-binary spawn error. */
export function isBinaryMissing(err: unknown): boolean {
  const code = (err as { code?: unknown } | null | undefined)?.code;
  return code === "ENOENT" || code === "EACCES";
}
