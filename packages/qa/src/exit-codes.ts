/**
 * Stable process exit codes for the QA / golden-corpus gate. CI keys off these
 * to decide whether a release is blocked (build-plan §4.7: "Provide clear exit
 * codes so CI can gate on it").
 */
export const QA_EXIT = {
  /** Scores meet the committed baseline — release may proceed. */
  OK: 0,
  /** A precision/recall/FP-rate threshold regressed — block the release. */
  REGRESSION: 1,
  /** Bad CLI usage (unknown flag, missing argument). */
  USAGE: 2,
  /** Corpus/baseline/findings could not be loaded or validated. */
  CORPUS_ERROR: 3,
  /** Unexpected runtime error. */
  RUNTIME_ERROR: 4,
} as const;

export type QaExitCode = (typeof QA_EXIT)[keyof typeof QA_EXIT];

/** Human-readable label for an exit code (used in CLI output). */
export function exitLabel(code: number): string {
  switch (code) {
    case QA_EXIT.OK:
      return "OK";
    case QA_EXIT.REGRESSION:
      return "REGRESSION";
    case QA_EXIT.USAGE:
      return "USAGE";
    case QA_EXIT.CORPUS_ERROR:
      return "CORPUS_ERROR";
    case QA_EXIT.RUNTIME_ERROR:
      return "RUNTIME_ERROR";
    default:
      return `UNKNOWN(${code})`;
  }
}
