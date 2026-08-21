/**
 * Stable process exit codes for `montr scan` (A15). A CI job gates on these —
 * see the `--fail-on` severity threshold in ./cli.ts — mirroring the
 * `SEC_EXIT`/`QA_EXIT` convention already used by `@montr/security`'s
 * `montr-audit-verify` and `@montr/qa`'s `montr-qa` CLIs.
 */
export const CLI_EXIT = {
  /** Scan completed; no confirmed finding met/exceeded --fail-on. */
  OK: 0,
  /** ⛔ Scan completed with a confirmed finding at/above --fail-on — gate the build. */
  FINDINGS: 1,
  /** Bad CLI usage (unknown flag, missing argument, invalid value). */
  USAGE: 2,
  /** The API rejected the request (auth failure, validation, HTTP error). */
  API_ERROR: 3,
  /** The scan itself failed/was cancelled, or the CLI timed out waiting on it. */
  SCAN_FAILED: 4,
  /** Unexpected runtime error. */
  RUNTIME_ERROR: 5,
} as const;
export type CliExitCode = (typeof CLI_EXIT)[keyof typeof CLI_EXIT];

export function exitLabel(code: number): string {
  switch (code) {
    case CLI_EXIT.OK:
      return "OK";
    case CLI_EXIT.FINDINGS:
      return "FINDINGS";
    case CLI_EXIT.USAGE:
      return "USAGE";
    case CLI_EXIT.API_ERROR:
      return "API_ERROR";
    case CLI_EXIT.SCAN_FAILED:
      return "SCAN_FAILED";
    case CLI_EXIT.RUNTIME_ERROR:
      return "RUNTIME_ERROR";
    default:
      return `UNKNOWN(${code})`;
  }
}
