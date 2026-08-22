/**
 * @montr/report — shared input/option types for Layer 5 (report model + gated
 * auto-fix PR flow). The finding/fix/report/PR SHAPES themselves are the frozen
 * @montr/contracts types; this file only defines the assembly inputs and the
 * VCS-opener seam so the flow is testable OFFLINE (inject a fake opener).
 */
import type {
  AppMap,
  ConfirmedFinding,
  CandidateFinding,
  CostRollup,
  Fix,
  GateState,
  HardeningRecommendation,
  PullRequest,
  PurpleTeamScenarioSummaryEntryShape,
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

  /**
   * B10 — blue-team report sections. Optional and additive: every section
   * degrades to an honest empty/absent state (never a guess) when its input
   * is omitted, so this stays backward compatible with existing callers
   * (e.g. `apps/worker/src/runners.ts`'s Layer 5 runner, which does not yet
   * pass these — see docs/modules/reporting-vcs.md).
   */

  /**
   * The scan's App Map. Drives THREE sections when present: B3/B4 detection-
   * rule route resolution for static-proof findings, B6 detection-coverage
   * gap analysis, B8 attack-path discovery, and B7's threat-model section
   * (via `appMap.threatModel`). All four degrade to an empty/absent section
   * (never fabricated) when omitted.
   */
  appMap?: AppMap;
  /**
   * B9's advisory hardening recommendations, precomputed by the caller
   * (`generateHardeningRecommendations` needs a `FileProvider` over the real
   * repo checkout — genuine I/O `buildReport` deliberately stays free of;
   * mirrors how `fixes`/`costRollup` above are already precomputed by
   * earlier layers rather than regenerated here).
   */
  hardeningRecommendations?: HardeningRecommendation[];
  /**
   * B5's purple-team "detected vs. undetected" scenario entries, precomputed
   * by the caller (e.g. via `@montr/confirm`'s `summarizePurpleTeamRun(...)
   * .entries` after running the purple-team loop). The clearly-named,
   * currently-empty-array-safe integration slot: omit (or pass `[]`) until a
   * purple-team run exists for this scan, and the report's `purpleTeam`
   * section reports zero scenarios rather than fabricating a verdict.
   */
  purpleTeamEntries?: PurpleTeamScenarioSummaryEntryShape[];
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
