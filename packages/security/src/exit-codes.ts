/**
 * Stable process exit codes for the @montr/security CLIs (audit hash-chain
 * verifier, self-scan). CI keys off these to gate a release (build-plan §4.8:
 * "Tamper-evident audit log verification tool (checks hash chain)").
 *
 * A non-zero exit on a broken chain is a HARD requirement — a tampered or
 * truncated audit log must fail the pipeline (golden rule #7).
 */
export const SEC_EXIT = {
  /** Chain intact / scan clean — proceed. */
  OK: 0,
  /** ⛔ Audit hash chain is broken (tamper/insert/delete/reorder) — block. */
  CHAIN_BROKEN: 1,
  /** Bad CLI usage (unknown flag, missing argument). */
  USAGE: 2,
  /** Input could not be read / parsed / schema-validated. */
  INPUT_ERROR: 3,
  /** Unexpected runtime error. */
  RUNTIME_ERROR: 4,
} as const;

export type SecExitCode = (typeof SEC_EXIT)[keyof typeof SEC_EXIT];

/** Human-readable label for an exit code (used in CLI output). */
export function secExitLabel(code: number): string {
  switch (code) {
    case SEC_EXIT.OK:
      return "OK";
    case SEC_EXIT.CHAIN_BROKEN:
      return "CHAIN_BROKEN";
    case SEC_EXIT.USAGE:
      return "USAGE";
    case SEC_EXIT.INPUT_ERROR:
      return "INPUT_ERROR";
    case SEC_EXIT.RUNTIME_ERROR:
      return "RUNTIME_ERROR";
    default:
      return `UNKNOWN(${code})`;
  }
}
