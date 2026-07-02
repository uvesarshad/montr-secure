/**
 * @montr/report — shared input/option types for Layer 5 (report model + gated
 * auto-fix PR flow). The finding/fix/report/PR SHAPES themselves are the frozen
 * @montr/contracts types; this file only defines the assembly inputs and the
 * VCS-opener seam so the flow is testable OFFLINE (inject a fake opener).
 */
import type {
  ConfirmedFinding,
  CandidateFinding,
  CostRollup,
  Fix,
  GateState,
  PullRequest,
  Scan,
  UnconfirmedFinding,
  VcsProvider,
} from "@montr/contracts";
import type { AuditLogClient, Logger } from "@montr/telemetry";

/** Strategy for grouping auto-eligible fixes into PRs. */
export type PrStrategy = "per-fix" | "grouped";

/** Previous-scan context used to compute the posture delta (§12.1). */
export interface PreviousScanContext {
  scanId?: string;
  confirmed: ConfirmedFinding[];
}

/**
 * Everything Layer 5 needs to assemble the report and (optionally) open PRs.
 *
 * The first six fields match the Wave-0 stub signature exactly; the rest are
 * OPTIONAL additions (backward compatible). `buildReport` is PURE and offline
 * unless an `opener` is supplied — only then does it open PRs (auto-eligible +
 * gate-passed only).
 */
export interface BuildReportInput {
  scan: Scan;
  confirmed: ConfirmedFinding[];
  unconfirmed: UnconfirmedFinding[];
  fixes: Fix[];
  costRollup: CostRollup;
  /** When true, open PRs for auto-eligible fixes (still gated on scan state). */
  autoApply: boolean;

  /** Candidate pile — used only to DERIVE `toolsConsolidated` (never surfaced). */
  candidates?: CandidateFinding[];
  /** Explicit "point tools consolidated" list; overrides candidate derivation. */
  toolsConsolidated?: string[];
  /** Previous scan's confirmed findings, for the posture delta. */
  previous?: PreviousScanContext;

  /** Deterministic report id. Defaults to `report_${scanId}`. */
  reportId?: string;
  /** ISO-8601 generation time. Defaults to now (inject for deterministic tests). */
  generatedAt?: string;

  /**
   * VCS opener. When present AND `autoApply` AND the gate has passed, PRs are
   * opened for auto-eligible fixes. Omit for the pure/offline path.
   */
  opener?: PullRequestOpener;
  /** One PR per fix (default, each independently reviewable) or one grouped PR. */
  prStrategy?: PrStrategy;
  /** Base branch PRs target. Defaults to `scan.branch` then "main". */
  baseBranch?: string;

  /** Audit sink — every opened PR is recorded (`fix.pr_opened`). */
  audit?: AuditLogClient;
  /** Structured logger (scrubbing). Metadata only, never code bodies. */
  logger?: Logger;
}

/**
 * A planned PR for one or more auto-eligible fixes. Deterministic and pure — the
 * gate has ALREADY been checked before a plan is produced. `patch` is the
 * client's own diff bound for the client's own VCS (not an LLM egress path).
 */
export interface AutoFixPrPlan {
  scanId: string;
  clientId: string;
  provider: VcsProvider;
  branch: string;
  baseBranch: string;
  title: string;
  /** PR body: rationale + proof-of-fix test intent. NEVER audit-logged verbatim. */
  bodySummary: string;
  /** Confirmed-finding-derived fix ids this PR closes (>= 1). */
  fixIds: string[];
  /** Combined unified diff applied on `branch`. */
  patch: string;
  /** Deterministic id assigned to the resulting PullRequest. */
  prId: string;
}

/**
 * The VCS seam. Concrete GitHub/GitLab implementations live in `./vcs.ts` (lazy
 * Octokit / gitbeaker + simple-git). ⛔ An opener opens PRs ONLY — it must never
 * commit to the base branch (golden rule #5); implementations assert this.
 */
export interface PullRequestOpener {
  readonly provider: VcsProvider;
  open(plan: AutoFixPrPlan): Promise<PullRequest>;
}

/** Inputs to the standalone auto-fix PR flow (a subset of BuildReportInput). */
export interface AutoFixFlowInput {
  scan: Scan;
  confirmed: ConfirmedFinding[];
  fixes: Fix[];
  autoApply: boolean;
  opener?: PullRequestOpener;
  prStrategy?: PrStrategy;
  baseBranch?: string;
  provider?: VcsProvider;
  audit?: AuditLogClient;
  logger?: Logger;
}

/** Gate states in which code changes (PRs) may proceed (golden rule #5, §6.2). */
export const GATE_PASSED_STATES: readonly GateState[] = ["auto_approved", "approved"];
