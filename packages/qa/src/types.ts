import type { Category } from "@montr/contracts";

/**
 * QA-internal analytics shapes. NOTE: these are metrics/reporting types, NOT
 * pipeline finding tiers or layer boundaries — those always come verbatim from
 * @montr/contracts (golden rule #10). Ground-truth shapes are re-exported from
 * @montr/fixtures (the single source of truth for the corpus labels).
 */
export type { GroundTruthFinding, GroundTruthRepo, GroundTruthManifest } from "@montr/fixtures";

/** Raw confusion-matrix counts. */
export interface ConfusionCounts {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
}

/** Per-category precision/recall/FP-rate breakdown. */
export interface CategoryScore extends ConfusionCounts {
  category: Category;
  precision: number;
  recall: number;
  f1: number;
  /** falsePositives / (truePositives + falsePositives) — the headline metric, per category. */
  fpRate: number;
}

/** Classification of a single confirmed finding (or missed ground-truth finding). */
export interface MatchOutcome {
  kind: "true_positive" | "false_positive" | "false_negative";
  category: Category;
  /** Confirmed finding id (present for TP/FP). */
  confirmedId?: string;
  /** Ground-truth finding id (present for TP/FN, and FP when it over-confirmed a demoted case). */
  groundTruthId?: string;
  /** Repo-relative file + line — metadata only; never a code/secret body (golden rule #1). */
  file?: string;
  line?: number;
  note?: string;
}

/** Per-repo confusion result. */
export interface RepoScore extends ConfusionCounts {
  repo: string;
  kind: "vulnerable" | "clean";
  /** Confirmations that matched a ground-truth finding flagged non-exploitable (should have stayed demoted). */
  overConfirmed: number;
  outcomes: MatchOutcome[];
}

/** Aggregate score across the whole corpus. */
export interface CorpusScore extends ConfusionCounts {
  precision: number;
  recall: number;
  f1: number;
  /**
   * Headline metric (PRD §15/§19, target < 0.05):
   * falsePositives / (truePositives + falsePositives) == 1 - precision.
   */
  fpRate: number;
  perCategory: CategoryScore[];
  /** Total confirmations that over-confirmed a demoted (non-exploitable) ground-truth case. */
  overConfirmed: number;
  /** Number of manifest repos that were scored. */
  reposScored: number;
  /** Number of manifest repos that actually had scan results supplied. */
  reposWithResults: number;
  /** Result entries whose repo name was not in the manifest (could not be scored). */
  unknownRepoResults: number;
  perRepo: RepoScore[];
}

/**
 * A metadata-only marker for an operator-confirmed FALSE POSITIVE (§15 FP loop).
 * Derived from the regression corpus; matched against a confirmed finding on
 * category + file + line (within {@link ScoreOptions.lineTolerance}). Carries no
 * code/secret body (golden rule #1).
 */
export interface FalsePositiveMarker {
  category: Category;
  file: string;
  line: number;
}

/** Options controlling how confirmed findings are matched to ground truth. */
export interface ScoreOptions {
  /**
   * Max |confirmed.line - groundTruth.line| allowed for a location match.
   * Default {@link DEFAULT_LINE_TOLERANCE}. A confirmed finding must also match
   * on category and file.
   */
  lineTolerance?: number;
  /**
   * Operator-marked false positives from the regression corpus (§15). A confirmed
   * finding matching one of these is scored as a FALSE POSITIVE regardless of
   * ground truth (the human override authoritatively overturns the confirmation),
   * and the matching ground-truth case is not counted as a miss. Additive: omit
   * for pure ground-truth scoring.
   */
  falsePositives?: readonly FalsePositiveMarker[];
}

/** A scan's confirmed findings for one corpus repo. */
export interface RepoScanResult {
  /** Corpus repo name (must match a manifest repo). */
  repo: string;
  confirmed: import("@montr/contracts").ConfirmedFinding[];
}

export const DEFAULT_LINE_TOLERANCE = 3;
