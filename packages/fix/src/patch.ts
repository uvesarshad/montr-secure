/**
 * Diff-ready patch construction + validation (PRD §7 L4). Patches are real
 * unified diffs (built with the `diff` library) that apply cleanly to the target
 * file; validation confirms the vulnerability is present pre-patch and gone
 * post-patch, which is exactly what makes the proof-of-fix test fail-before /
 * pass-after.
 */
import { applyPatch, createTwoFilesPatch, parsePatch } from "diff";

export interface PatchValidation {
  /** The patch applies cleanly to the original source. */
  applies: boolean;
  /** The result of applying the patch (null when it does not apply). */
  appliedSource: string | null;
  /** The vulnerable pattern is present in the ORIGINAL (⇒ proof test fails pre-patch). */
  failsPrePatch: boolean;
  /** The vulnerable pattern is gone AFTER the patch (⇒ proof test passes post-patch). */
  passesPostPatch: boolean;
  /** Number of +/- lines the patch changes. */
  changedLines: number;
}

/** Build a unified-diff patch for a single file (git-style a/ b/ headers). */
export function buildUnifiedDiff(filePath: string, original: string, fixed: string): string {
  return createTwoFilesPatch(
    `a/${filePath}`,
    `b/${filePath}`,
    original,
    fixed,
    undefined,
    undefined,
    { context: 3 },
  );
}

/** Count the added/removed lines across every hunk in a unified diff. */
export function countChangedLines(patch: string): number {
  if (patch.length === 0) return 0;
  let n = 0;
  for (const file of parsePatch(patch)) {
    for (const hunk of file.hunks) {
      for (const line of hunk.lines) {
        if (line.startsWith("+") || line.startsWith("-")) n++;
      }
    }
  }
  return n;
}

/**
 * Validate a patch against the original source and a vulnerability predicate.
 * `vulnerable(src) === true` means "the insecure pattern is still present".
 */
export function validatePatch(
  original: string,
  patch: string,
  vulnerable: (src: string) => boolean,
): PatchValidation {
  const applied = applyPatch(original, patch);
  const applies = applied !== false;
  const appliedSource = applies ? applied : null;
  const failsPrePatch = vulnerable(original);
  const passesPostPatch = appliedSource !== null && !vulnerable(appliedSource);
  return {
    applies,
    appliedSource,
    failsPrePatch,
    passesPostPatch,
    changedLines: countChangedLines(patch),
  };
}
