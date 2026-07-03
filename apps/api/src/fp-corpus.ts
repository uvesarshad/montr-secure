/**
 * §15 False-positive regression-corpus sink for the API.
 *
 * When an operator/approver marks a confirmed finding as a false positive, the
 * decision is (1) recorded in the append-only, hash-chained audit log (the
 * authoritative, tamper-evident record) and (2) written through this recorder
 * into the durable regression corpus that tunes correlation/confirmation and
 * feeds the precision / FP-rate metric.
 *
 * This interface is declared LOCALLY (structural typing) so the API does not take
 * a build-time dependency on the @montr/qa harness — exactly as `store.ts`
 * mirrors @montr/state-store. Production wires @montr/qa's
 * `corpusRecorder(new FileRegressionCorpus(path))` (or an audit-log projection)
 * here; both are structurally assignable to {@link RegressionCorpusRecorder}.
 *
 * ⛔ Metadata only — NEVER a proof artifact, code body, or secret (golden rule #1).
 */
import type {
  Category,
  CweId,
  Exposure,
  OwaspId,
  ProofType,
  Role,
  Severity,
} from "@montr/contracts";

/** The metadata an operator supplies to record a false positive (no code body). */
export interface FalsePositiveMarkInput {
  clientId: string;
  scanId: string;
  /** The confirmed finding being overturned. */
  findingId: string;
  category: Category;
  cwe?: CweId[];
  owasp?: OwaspId;
  /** Repo-relative file + line — metadata only. */
  file: string;
  line: number;
  severity?: Severity;
  exposure?: Exposure;
  proofType?: ProofType;
  /** Who overturned it (operator/approver). */
  operator: { id: string; role?: Role };
  /** The operator's free-text justification. */
  reason: string;
  /** ISO-8601 timestamp. */
  markedAt: string;
  ruleId?: string;
}

/** Durable regression-corpus sink. Satisfied by @montr/qa's `corpusRecorder(...)`. */
export interface RegressionCorpusRecorder {
  record(input: FalsePositiveMarkInput): Promise<unknown> | unknown;
}

/**
 * Fail-safe default. The audit log is authoritative and the corpus is rebuildable
 * from it (`regressionCorpusFromAuditEvents`), so an unconfigured corpus must
 * never break FP marking — it simply no-ops until a durable recorder is wired.
 */
export const noopRegressionCorpus: RegressionCorpusRecorder = {
  record() {
    /* no-op — see doc comment. */
  },
};
