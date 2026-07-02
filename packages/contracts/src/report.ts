import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { SeveritySchema } from "./enums.js";
import { ConfirmedFindingSchema, UnconfirmedFindingSchema } from "./findings.js";
import { FixSchema, PullRequestSchema } from "./fix.js";
import { ComplianceMappingSchema } from "./compliance.js";
import { ScanScopeSchema } from "./scan.js";
import { CostRollupSchema } from "./cost.js";

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
});
export type Report = z.infer<typeof ReportSchema>;

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
