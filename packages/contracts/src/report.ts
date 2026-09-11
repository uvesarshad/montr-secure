import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { SeveritySchema } from "./enums.js";
import { ConfirmedFindingSchema, UnconfirmedFindingSchema } from "./findings.js";
import { FixSchema, PullRequestSchema } from "./fix.js";
import { ComplianceMappingSchema } from "./compliance.js";
import { ScanScopeSchema } from "./scan.js";
import { CostRollupSchema } from "./cost.js";
import { DetectionRuleSchema, AttackPathSchema, DetectionCoverageSchema } from "./blue-team.js";
import { HardeningRecommendationSchema } from "./hardening.js";
import { ThreatModelSchema } from "./threat-model.js";

/**
 * Report specification (§12). The report is the hero product. Headline =
 * confirmed + prioritized findings; breadth lives in the appendix. NEVER
 * headline raw counts (golden rule / §12).
 */

/** Posture delta vs the previous scan. */
export const PostureDeltaSchema = z.object({
  previousScanId: IdSchema.optional(),
  newIssues: z.number().int().nonnegative(),
  resolvedIssues: z.number().int().nonnegative(),
  netDelta: z.number().int(),
});
export type PostureDelta = z.infer<typeof PostureDeltaSchema>;

export const ExecutiveSummarySchema = z.object({
  totalConfirmed: z.number().int().nonnegative(),
  confirmedBySeverity: z.record(SeveritySchema, z.number().int().nonnegative()),
  postureDelta: PostureDeltaSchema.optional(),
  /** Prior point tools consolidated into this scan (e.g. ["semgrep","gitleaks","osv"]). */
  toolsConsolidated: z.array(z.string()).default([]),
});
export type ExecutiveSummary = z.infer<typeof ExecutiveSummarySchema>;

/** A confirmed finding as rendered in the report, with its merge-ready fix. */
export const ReportFindingSchema = z.object({
  finding: ConfirmedFindingSchema,
  fix: FixSchema.optional(),
  compliance: ComplianceMappingSchema,
});
export type ReportFinding = z.infer<typeof ReportFindingSchema>;

/** Which fixes are auto-eligible (PRs) vs human-required (recommendations). */
export const FixStatusSummarySchema = z.object({
  autoEligibleFixIds: z.array(IdSchema).default([]),
  humanRequiredFixIds: z.array(IdSchema).default([]),
  pullRequests: z.array(PullRequestSchema).default([]),
});
export type FixStatusSummary = z.infer<typeof FixStatusSummarySchema>;

export const CostAndScopeSchema = z.object({
  scope: ScanScopeSchema,
  cost: CostRollupSchema,
});
export type CostAndScope = z.infer<typeof CostAndScopeSchema>;

/* ------------------------------------------------------------------ *
 * Blue-team report sections (B10). Wires B2 (MITRE ATT&CK), B3/B4
 * (detection-rule generation), B6 (detection-coverage gap analysis), B7
 * (threat-model report), B8 (attack-path graph), and B9 (hardening
 * recommendations) — all landed standalone earlier this session — into the
 * final assembled Report. Every leaf entity type (`DetectionRule`,
 * `AttackPath`, `DetectionCoverage`, `HardeningRecommendation`,
 * `ThreatModel`) already has a real, frozen zod schema elsewhere in this
 * package; this section only adds the thin wrapper shapes report-builder.ts
 * assembles them into, plus a small MITRE-technique-descriptor schema
 * (mirroring `./mitre.ts`'s plain-TS `MitreTechniqueDescriptor` interface —
 * kept local to avoid a contracts->report-shape coupling the other way).
 * Every field defaults so an existing `Report` fixture built without
 * `blueTeam` still parses (additive, backward-compatible).
 * ------------------------------------------------------------------ */

/** Mirrors `./mitre.ts`'s `MitreTechniqueDescriptor` (kept a separate zod
 * schema here rather than importing the plain interface, since it is only
 * embedded — never re-derived — in the report shape). */
export const MitreTechniqueDescriptorSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  tactic: z.string().min(1),
  framework: z.enum(["attack-enterprise", "atlas"]),
  url: z.string().min(1),
});
export type MitreTechniqueDescriptorShape = z.infer<typeof MitreTechniqueDescriptorSchema>;

/** One confirmed finding's MITRE ATT&CK/ATLAS technique mapping (B2). */
export const MitreFindingMappingSchema = z.object({
  findingId: IdSchema,
  title: z.string(),
  category: z.string(),
  severity: z.string(),
  techniques: z.array(MitreTechniqueDescriptorSchema).default([]),
});
export type MitreFindingMappingShape = z.infer<typeof MitreFindingMappingSchema>;

/** Per-technique coverage index: how many (and which) findings map to it. */
export const MitreTechniqueCoverageSchema = z.object({
  technique: MitreTechniqueDescriptorSchema,
  findingCount: z.number().int().nonnegative(),
  findingIds: z.array(IdSchema).default([]),
});
export type MitreTechniqueCoverageShape = z.infer<typeof MitreTechniqueCoverageSchema>;

export const MitreAttackSectionSchema = z.object({
  findings: z.array(MitreFindingMappingSchema).default([]),
  coverage: z.array(MitreTechniqueCoverageSchema).default([]),
});
export type MitreAttackSectionShape = z.infer<typeof MitreAttackSectionSchema>;

/** B3/B4 generated rules + B6 coverage verdicts, per confirmed finding. */
export const DetectionEngineeringSectionSchema = z.object({
  rules: z.array(DetectionRuleSchema).default([]),
  coverage: z.array(DetectionCoverageSchema).default([]),
});
export type DetectionEngineeringSection = z.infer<typeof DetectionEngineeringSectionSchema>;

/** B7's reviewable threat-model artifact (raw `ThreatModel` + rendered prose). */
export const ThreatModelSectionSchema = z.object({
  /** False when the scan's App Map carried no threat model to render. */
  present: z.boolean().default(false),
  summary: z.string().optional(),
  markdown: z.string().optional(),
  raw: ThreatModelSchema.optional(),
});
export type ThreatModelSection = z.infer<typeof ThreatModelSectionSchema>;

/**
 * B9's advisory config/infra guidance. `advisoryOnly` is a load-bearing
 * literal (always `true`) — a structural, always-present reminder that this
 * section carries no diff/patch and is never auto-applied, distinct from
 * `fixStatus`'s code fixes above (see `HardeningRecommendationSchema`'s own
 * doc comment in `./hardening.ts` for the full architectural boundary).
 */
export const HardeningSectionSchema = z.object({
  advisoryOnly: z.literal(true).default(true),
  recommendations: z.array(HardeningRecommendationSchema).default([]),
});
export type HardeningSection = z.infer<typeof HardeningSectionSchema>;

/**
 * One purple-team scenario verification entry — mirrors B5's
 * `PurpleTeamScenarioSummaryEntry` (`packages/confirm/src/purple-loop.ts`'s
 * `summarizePurpleTeamRun`, landed this same wave), field-for-field, so a
 * caller can pass B5's own `PurpleTeamRunSummary.entries` straight through
 * with no reshaping. `findingCategory` is `z.string()` (not `CategorySchema`)
 * to keep this contracts-internal schema decoupled from re-importing
 * `./compliance.ts` for a denormalized display field.
 */
export const PurpleTeamScenarioSummaryEntrySchema = z.object({
  scenarioId: IdSchema,
  scenarioName: z.string().min(1),
  findingId: IdSchema,
  findingCategory: z.string().min(1),
  detectionRuleId: IdSchema.optional(),
  detected: z.boolean(),
  /** Why detected/undetected — always concrete (B5), never a placeholder. */
  reason: z.string(),
});
export type PurpleTeamScenarioSummaryEntryShape = z.infer<
  typeof PurpleTeamScenarioSummaryEntrySchema
>;

/**
 * Detected-vs-undetected purple-team summary (B5, mirrors
 * `PurpleTeamRunSummary` minus the redundant `scanId`, already carried at
 * the top level of `Report`). B5 had not landed when B10 started this
 * change; it landed partway through this same wave, so this is real,
 * populated data when a caller supplies `purpleTeamEntries` to
 * `BuildReportInput` (`@montr/report`) — an empty array (all counts 0) when
 * no purple-team run has been executed for this scan yet.
 */
export const PurpleTeamSectionSchema = z.object({
  entries: z.array(PurpleTeamScenarioSummaryEntrySchema).default([]),
  totalScenarios: z.number().int().nonnegative().default(0),
  detectedCount: z.number().int().nonnegative().default(0),
  undetectedCount: z.number().int().nonnegative().default(0),
});
export type PurpleTeamSection = z.infer<typeof PurpleTeamSectionSchema>;

/**
 * A18 (2026-09-12 red/blue agentic-posture audit) — an OPTIONAL, LLM-generated
 * executive narrative layered ON TOP OF the deterministic report. `packages/
 * report` had zero LLM gateway calls; every executive summary, narrative, and
 * prioritization rationale was template-assembled from structured data
 * (defensible — deterministic reports are auditable and free — but it left
 * the one artifact the customer actually reads with no AI contribution).
 *
 * Owner decision: keep {@link ExecutiveSummarySchema} exactly as-is — the
 * audited, template-assembled artifact of record a compliance reviewer can
 * trust byte-for-byte — and add this as a SEPARATE, clearly-labelled section
 * a consumer can never mistake for it: different top-level key
 * (`Report.generatedExecutiveSummary`, not a field ON `executiveSummary`),
 * its own fixed `disclaimer` literal (so a UI/export that renders this
 * section can never accidentally drop the "generated, not authoritative"
 * framing), and its own provenance (`model`/`provider`/`generatedAt`).
 *
 * ABSENT (not an empty object) whenever `reporting.executiveSummary.enabled`
 * is false (the default — see `packages/config/src/schema.ts`'s
 * `ReportingConfigSchema`), no gateway is available, or generation fails for
 * any reason — see `packages/report/src/executive-summary.ts`'s
 * `generateExecutiveSummary` and `apps/worker/src/runners.ts`'s Layer 5
 * runner, which is the only caller. Never generated by `buildReport` itself
 * (pure/offline) — this is deliberately a second, separate step the caller
 * runs AFTER `buildReport` completes, then attaches to the finished report.
 */
export const GeneratedExecutiveSummarySchema = z.object({
  /** Fixed framing string — always present, never suppressed by a renderer. */
  disclaimer: z
    .literal("AI-generated narrative — not the audited report artifact.")
    .default("AI-generated narrative — not the audited report artifact."),
  /** The generated prose narrative. Never re-derives/overrides confirmed counts. */
  narrative: z.string().min(1),
  /** Short, model-proposed focus areas — advisory framing only, never new findings. */
  topPriorities: z.array(z.string()).default([]),
  generatedAt: IsoDateTimeSchema,
  /** Resolved model id / provider that produced this narrative (provenance). */
  model: z.string().min(1),
  provider: z.string().min(1),
});
export type GeneratedExecutiveSummary = z.infer<typeof GeneratedExecutiveSummarySchema>;

export const BlueTeamReportSchema = z.object({
  mitreAttack: MitreAttackSectionSchema.default({ findings: [], coverage: [] }),
  detectionEngineering: DetectionEngineeringSectionSchema.default({ rules: [], coverage: [] }),
  /** B8, ranked by feasibility (then severity) — see `buildAttackPaths`. */
  attackPaths: z.array(AttackPathSchema).default([]),
  threatModel: ThreatModelSectionSchema.default({ present: false }),
  hardening: HardeningSectionSchema.default({ advisoryOnly: true, recommendations: [] }),
  purpleTeam: PurpleTeamSectionSchema.default({
    entries: [],
    totalScenarios: 0,
    detectedCount: 0,
    undetectedCount: 0,
  }),
});
export type BlueTeamReport = z.infer<typeof BlueTeamReportSchema>;

/** The full report model (§12 structure). */
export const ReportSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  clientId: IdSchema,
  generatedAt: IsoDateTimeSchema,
  executiveSummary: ExecutiveSummarySchema,
  confirmedFindings: z.array(ReportFindingSchema).default([]),
  fixStatus: FixStatusSummarySchema,
  /** Demoted / unconfirmed candidates, clearly separated (§12.4). */
  unconfirmedAppendix: z.array(UnconfirmedFindingSchema).default([]),
  complianceMapping: z.array(ComplianceMappingSchema).default([]),
  costAndScope: CostAndScopeSchema,
  /** Blue-team sections (B10) — see {@link BlueTeamReportSchema}. */
  blueTeam: BlueTeamReportSchema.default({}),
  /**
   * A18 — optional AI-generated narrative on top of the deterministic
   * report. See {@link GeneratedExecutiveSummarySchema}'s doc comment for
   * the full rationale. Absent (not merely empty) unless
   * `reporting.executiveSummary.enabled` is true AND a gateway generated it
   * successfully.
   */
  generatedExecutiveSummary: GeneratedExecutiveSummarySchema.optional(),
});
export type Report = z.infer<typeof ReportSchema>;

/* ------------------------------------------------------------------ *
 * A5 (red/blue agentic-posture audit) — cross-scan blue-team aggregate.
 * Backs GET /analytics/blue-team (apps/api/src/routes/analytics.ts): an
 * org-wide, real-data rollup over every one of a client's scans, built from
 * the SAME per-scan sources the B11 scan-level Blue Team tab already renders
 * — `Report.blueTeam.mitreAttack` for ATT&CK coverage, and the real,
 * persisted (A7) `DetectionRule`/`DetectionCoverage` repositories
 * (packages/state-store/src/blue-team.ts) for the rule inventory and the
 * coverage trend. This is a READ-ONLY rollup layer — no new persistence.
 * ------------------------------------------------------------------ */

/** One point in the org-wide ATT&CK coverage timeline — one per scan that
 * has a generated report, chronological by `Scan.finishedAt` (falling back
 * to `createdAt` for a scan still in flight). */
export const BlueTeamAttackCoveragePointSchema = z.object({
  scanId: IdSchema,
  repo: z.string(),
  at: IsoDateTimeSchema,
  /** Distinct MITRE techniques covered by confirmed findings in this scan alone. */
  techniqueCount: z.number().int().nonnegative(),
  /** Distinct techniques covered cumulatively up to and including this scan. */
  cumulativeTechniqueCount: z.number().int().nonnegative(),
});
export type BlueTeamAttackCoveragePoint = z.infer<typeof BlueTeamAttackCoveragePointSchema>;

/** One point in the org-wide detection-coverage trend — one per scan with
 * persisted `DetectionCoverage` rows (A7), chronological. Real
 * detected/undetected/unknown tri-state counts, never mock data. */
export const BlueTeamCoverageTrendPointSchema = z.object({
  scanId: IdSchema,
  repo: z.string(),
  at: IsoDateTimeSchema,
  detected: z.number().int().nonnegative(),
  undetected: z.number().int().nonnegative(),
  unknown: z.number().int().nonnegative(),
});
export type BlueTeamCoverageTrendPoint = z.infer<typeof BlueTeamCoverageTrendPointSchema>;

/** A generated detection rule, deduped across scans by (format, content) —
 * the same rule text generated repeatedly for a recurring vulnerability
 * pattern collapses to one inventory entry; `scanIds`/`findingIds` record
 * every occurrence it was generated for. */
export const DedupedDetectionRuleSchema = z.object({
  /** The most-recently-generated occurrence, used as the representative row. */
  rule: DetectionRuleSchema,
  occurrences: z.number().int().positive(),
  scanIds: z.array(IdSchema).default([]),
  findingIds: z.array(IdSchema).default([]),
});
export type DedupedDetectionRule = z.infer<typeof DedupedDetectionRuleSchema>;

export const BlueTeamOrgSummarySchema = z.object({
  clientId: IdSchema,
  at: IsoDateTimeSchema,
  /** Number of the client's scans that had a generated report to aggregate. */
  scansConsidered: z.number().int().nonnegative(),
  attackCoverage: z.object({
    /** Aggregated across every scan's `blueTeam.mitreAttack.coverage` — the
     * SAME shape `AttackHeatMap` (apps/web/src/components/attack-heatmap.tsx)
     * already renders per-scan, reused as-is for the org-wide view. */
    coverage: z.array(MitreTechniqueCoverageSchema).default([]),
    overTime: z.array(BlueTeamAttackCoveragePointSchema).default([]),
  }),
  detectionRules: z.object({
    rules: z.array(DedupedDetectionRuleSchema).default([]),
    /** Total rows generated before dedup (>= `rules.length`). */
    totalGenerated: z.number().int().nonnegative(),
  }),
  detectionCoverageTrend: z.object({
    points: z.array(BlueTeamCoverageTrendPointSchema).default([]),
    totals: z.object({
      detected: z.number().int().nonnegative(),
      undetected: z.number().int().nonnegative(),
      unknown: z.number().int().nonnegative(),
    }),
  }),
});
export type BlueTeamOrgSummary = z.infer<typeof BlueTeamOrgSummarySchema>;

/* ------------------------------------------------------------------ *
 * Export descriptors (§13, DECIDE-5 order: SARIF + OWASP, then SOC2, then ISO)
 * ------------------------------------------------------------------ */

export const ExportFormatSchema = z.enum([
  "sarif",
  "owasp-json",
  "soc2-evidence",
  "iso27001",
  "csv",
  "pdf",
  "html",
  "json",
  // E16: CycloneDX SBOM. Unlike the other formats, its content is NOT derived
  // from confirmedFindings — see packages/report/src/exports/cyclonedx.ts's
  // module doc comment for how it plugs into the registry via
  // GenerateExportOptions.dependencyInventory.
  "cyclonedx",
]);
export type ExportFormat = z.infer<typeof ExportFormatSchema>;

export const ExportRequestSchema = z.object({
  scanId: IdSchema,
  format: ExportFormatSchema,
});
export type ExportRequest = z.infer<typeof ExportRequestSchema>;

/** Descriptor for a generated export artifact. */
export const ExportArtifactSchema = z.object({
  scanId: IdSchema,
  format: ExportFormatSchema,
  filename: z.string(),
  contentType: z.string(),
  sizeBytes: z.number().int().nonnegative().optional(),
  uri: z.string().optional(),
  generatedAt: IsoDateTimeSchema,
});
export type ExportArtifact = z.infer<typeof ExportArtifactSchema>;

/** Minimal SARIF 2.1.0 log shape (target for the SARIF exporter). */
export const SarifResultSchema = z.object({
  ruleId: z.string(),
  level: z.enum(["none", "note", "warning", "error"]).default("warning"),
  message: z.object({ text: z.string() }),
  locations: z
    .array(
      z.object({
        physicalLocation: z.object({
          artifactLocation: z.object({ uri: z.string() }),
          region: z.object({ startLine: z.number().int().positive() }).optional(),
        }),
      }),
    )
    .default([]),
});
export type SarifResult = z.infer<typeof SarifResultSchema>;

export const SarifLogSchema = z.object({
  version: z.literal("2.1.0"),
  $schema: z.string().optional(),
  runs: z.array(
    z.object({
      tool: z.object({
        driver: z.object({
          name: z.string(),
          informationUri: z.string().optional(),
          rules: z.array(z.object({ id: z.string() })).default([]),
        }),
      }),
      results: z.array(SarifResultSchema).default([]),
    }),
  ),
});
export type SarifLog = z.infer<typeof SarifLogSchema>;
