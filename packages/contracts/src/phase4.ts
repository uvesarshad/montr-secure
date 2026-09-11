import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { LanguageSchema, ScanModeSchema, SeveritySchema, HttpMethodSchema } from "./enums.js";
// Reuse the canonical posture-delta shape from the report spec (§12) — do not
// invent a second one (golden rule #10).
import { PostureDeltaSchema } from "./report.js";

/**
 * Phase-4 (Wave 5) — Scale & Intelligence contracts (build-plan §8, PRD §16).
 *
 * STRICTLY ADDITIVE: appended to the frozen @montr/contracts spine. Everything
 * here is RBAC-scoped and per-client isolated in persistence (@montr/state-store).
 *
 * ⛔ SAFETY (golden rules, §11 — never weakened by these features):
 *   - Custom rules are VALIDATED before use and disabled by default.
 *   - Red-team scenarios are ALLOWLIST-GATED (`targetAllowlistRef`),
 *     approver-authorized, and disabled by default; running one is a live-DAST
 *     action routed via the @montr/security egress guard + kill switch.
 *   - Scheduled scans carry a hard `budgetCeiling` and still honor the human gate.
 *   - Posture aggregates count CONFIRMED findings only — never headline raw
 *     candidate piles (§12, golden rule "never headline raw counts").
 */

/* ============================== Custom rules ============================== */

/** Engine a client custom rule targets. */
export const RuleEngineSchema = z.enum(["semgrep", "secret"]);
export type RuleEngine = z.infer<typeof RuleEngineSchema>;

/**
 * A client-authored detection rule (custom Semgrep rule or secret detector).
 * `enabled` defaults OFF — a rule must be validated before it can be turned on
 * (golden rule: custom rules are validated before use). `body` is the rule
 * source (Semgrep YAML or a secret-detector definition), never a credential.
 */
export const CustomRuleSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  name: z.string().min(1).max(200),
  language: LanguageSchema,
  engine: RuleEngineSchema,
  /** Rule source (Semgrep YAML / secret-detector definition). Validated before use. */
  body: z.string().min(1),
  version: z.number().int().positive().default(1),
  enabled: z.boolean().default(false),
  createdBy: IdSchema,
  createdAt: IsoDateTimeSchema,
});
export type CustomRule = z.infer<typeof CustomRuleSchema>;

/** Outcome of validating a custom rule before it may be enabled. */
export const CustomRuleValidationSchema = z.object({
  valid: z.boolean(),
  /** Human-readable errors (empty when valid). */
  errors: z.array(z.string()).default([]),
  /** Non-fatal warnings. */
  warnings: z.array(z.string()).default([]),
});
export type CustomRuleValidation = z.infer<typeof CustomRuleValidationSchema>;

/* ========================== Red-team scenarios ========================== */

/** Coarse category for a reusable red-team / DAST scenario. */
export const RedTeamCategorySchema = z.enum([
  "access_control",
  "injection",
  "authentication",
  "ssrf",
  "xss",
  "business_logic",
  "recon",
  "other",
]);
export type RedTeamCategory = z.infer<typeof RedTeamCategorySchema>;

/** One step in a red-team scenario. Descriptive; execution is heavily gated (§11). */
export const RedTeamStepSchema = z.object({
  order: z.number().int().nonnegative(),
  /** Human-readable action, e.g. "POST login with SQLi payload in username". */
  action: z.string().min(1),
  method: HttpMethodSchema.optional(),
  /** Request path RELATIVE to the allowlisted target (never an absolute URL). */
  path: z.string().optional(),
  /**
   * Request body payload for this step, sent verbatim by `runScenario`
   * (packages/confirm/src/scenarios.ts) when a transport is supplied. Additive
   * and optional — a step without one behaves exactly as before (no body
   * sent). Needed for scenarios whose confirming payload is a POST/PUT body
   * rather than a query parameter (e.g. command_injection, ssrf,
   * insecure_deserialization in the OWASP starter catalogue).
   */
  body: z.string().optional(),
  /** What indicates the step succeeded (proof signal). */
  expectation: z.string().optional(),
});
export type RedTeamStep = z.infer<typeof RedTeamStepSchema>;

/**
 * A reusable, versioned red-team scenario (PRD §16 Phase-4).
 *
 * ⛔ `targetAllowlistRef` binds the scenario to an allowlisted DAST target/scope
 * — a scenario can NEVER be run against a target that is not on the allowlist,
 * and running is approver-authorized (§11). `enabled` defaults OFF.
 */
export const RedTeamScenarioSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  name: z.string().min(1).max(200),
  category: RedTeamCategorySchema,
  steps: z.array(RedTeamStepSchema).default([]),
  /** ⛔ Reference to the allowlisted DAST target/scope this scenario is bound to. */
  targetAllowlistRef: z.string().min(1),
  version: z.number().int().positive().default(1),
  enabled: z.boolean().default(false),
  createdBy: IdSchema,
  createdAt: IsoDateTimeSchema,
});
export type RedTeamScenario = z.infer<typeof RedTeamScenarioSchema>;

/* ============================ Scan schedules ============================ */

/**
 * A cron-scheduled scan (PRD §16 Phase-4).
 *
 * ⛔ `budgetCeiling` (USD) is a HARD per-run ceiling; scheduled runs still honor
 * the human gate (estimate acknowledgement + fix-gate approval). `enabled`
 * defaults OFF.
 */
export const ScanScheduleSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  repo: z.string().min(1),
  mode: ScanModeSchema.default("full"),
  /** Cron expression (5- or 6-field). Validated by the scheduler before enable. */
  cron: z.string().min(1),
  /** ⛔ Hard USD ceiling applied to each scheduled run (budget hard-halt, §8.4). */
  budgetCeiling: z.number().positive(),
  enabled: z.boolean().default(false),
  nextRunAt: IsoDateTimeSchema.optional(),
  createdBy: IdSchema,
  createdAt: IsoDateTimeSchema,
});
export type ScanSchedule = z.infer<typeof ScanScheduleSchema>;

/* ===================== Posture / trend intelligence ===================== */

/** Confirmed-finding counts keyed by severity (absent key ⇒ zero). */
export const SeverityCountsSchema = z
  .record(SeveritySchema, z.number().int().nonnegative())
  .default({});
export type SeverityCounts = z.infer<typeof SeverityCountsSchema>;

/**
 * One point on a repo's posture-over-time series. Derived from a completed scan's
 * CONFIRMED findings (never raw candidates). Persisted per client for fast trend
 * queries; equivalently derivable from Scan + finding history.
 */
export const PostureSnapshotSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  scanId: IdSchema,
  repo: z.string().min(1),
  at: IsoDateTimeSchema,
  /** CONFIRMED findings by severity at this scan (golden rule: never raw counts). */
  confirmedBySeverity: SeverityCountsSchema,
  /** Total confirmed findings (sum of the above). */
  total: z.number().int().nonnegative(),
  /** Posture change vs the previous snapshot for this repo, if any. */
  delta: PostureDeltaSchema.optional(),
});
export type PostureSnapshot = z.infer<typeof PostureSnapshotSchema>;

/** A repo's posture time-series (read model for the trend dashboard). */
export const PostureTrendSchema = z.object({
  clientId: IdSchema,
  repo: z.string().min(1),
  snapshots: z.array(PostureSnapshotSchema).default([]),
  latest: PostureSnapshotSchema.optional(),
});
export type PostureTrend = z.infer<typeof PostureTrendSchema>;

/** Per-repo row in the org-wide posture dashboard. */
export const RepoPostureSchema = z.object({
  repo: z.string().min(1),
  total: z.number().int().nonnegative(),
  confirmedBySeverity: SeverityCountsSchema,
  latestScanId: IdSchema.optional(),
  latestAt: IsoDateTimeSchema.optional(),
});
export type RepoPosture = z.infer<typeof RepoPostureSchema>;

/**
 * Org-wide posture aggregate across repos (RBAC-scoped read model, §16). Headlines
 * confirmed-by-severity totals — never raw candidate piles (golden rule, §12).
 */
export const OrgPostureSummarySchema = z.object({
  clientId: IdSchema,
  at: IsoDateTimeSchema,
  repos: z.array(RepoPostureSchema).default([]),
  totals: z.object({
    repoCount: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    confirmedBySeverity: SeverityCountsSchema,
  }),
});
export type OrgPostureSummary = z.infer<typeof OrgPostureSummarySchema>;
