import { z } from "zod";
import { IdSchema, IsoDateTimeSchema, Score01Schema } from "./primitives.js";
import { ProofTypeSchema, SeveritySchema } from "./enums.js";

/**
 * Blue-team / purple-team entities (B1). Three genuinely new, first-class
 * persisted entities that build on top of the existing finding tiers
 * (`ConfirmedFinding`, see ./findings.ts) and `ThreatModelSchema` (see
 * ./threat-model.ts, reused as-is — NOT redefined here):
 *
 *   - {@link DetectionRuleSchema} — a generated detection rule (Sigma/OTel/SIEM)
 *     for a confirmed finding (B3 authors the actual rule content).
 *   - {@link AttackPathSchema} — a chained kill-chain across multiple confirmed
 *     findings (a later wave builds the graph algorithm).
 *   - {@link DetectionCoverageSchema} — whether existing telemetry would catch a
 *     confirmed finding if exploited, with a purple-team-verifiable result
 *     (B5's purple-team loop populates `verification`).
 *
 * This module is data-model ONLY — no generation/mapping/graph logic lives
 * here (that is B2/B3/B4/B5's job in a later wave). `findingId` fields below
 * are deliberately PLAIN string references, not Prisma relations at the
 * persistence layer — mirrors `ConfirmedFinding.probableId`'s existing loose-
 * reference precedent across finding tiers (packages/state-store/prisma/schema.prisma).
 */

/**
 * Rule output format. A plain string-backed enum (Zod owns the vocabulary,
 * mirrors `RedTeamScenario.category`/`CustomRule.language`'s precedent) rather
 * than a closed Prisma enum, because B3 is expected to grow this set (e.g.
 * additional SIEM query dialects) without a schema migration per new format.
 */
export const DetectionRuleFormatSchema = z.enum(["sigma", "otel", "siem_query"]);
export type DetectionRuleFormat = z.infer<typeof DetectionRuleFormatSchema>;

/**
 * B4 — human-readable "what this looks like in your logs" narrative attached
 * to a generated {@link DetectionRuleSchema} rule (packages/report/src/detection-rules
 * builds these, alongside the rule `content` itself — see that module's header
 * for the generation logic). `fields`/`pattern` are the concrete, finding-
 * specific signature an operator would alert on; `falseAlarmSources` is the
 * differentiated part — known, finding-specific sources of expected false
 * alarms (e.g. "a legitimate admin bulk-export tool hitting this same route"),
 * never a generic "may have false positives" placeholder.
 */
export const DetectionLogSignatureSchema = z.object({
  /** Concrete log field names to alert on (e.g. "http.request.path", "cs-uri-query"). */
  fields: z.array(z.string().min(1)).min(1),
  /** The exact, finding-specific log pattern an operator would grep/query for. */
  pattern: z.string().min(1),
  /** Finding-specific expected false-alarm sources (never generic boilerplate). */
  falseAlarmSources: z.array(z.string().min(1)).default([]),
});
export type DetectionLogSignature = z.infer<typeof DetectionLogSignatureSchema>;

/**
 * A generated detection rule for one confirmed finding. `provenance` reuses
 * {@link ProofTypeSchema} ("static" | "live") — the same discriminant
 * `ConfirmedFinding.proofType`/`proofArtifact.kind` already use — to record
 * whether the rule was derived from a live-DAST transcript or a static
 * data-flow path, without duplicating `ProofArtifactSchema`'s shape.
 * `mitreTechniques` holds raw ATT&CK technique ids (e.g. "T1190"); the
 * mapping table that populates this field is B2's job, not this schema's.
 * `logSignature` (B4) is optional/additive — absent for rows written before
 * B4 landed, or for a caller that only wants the raw rule `content`.
 */
export const DetectionRuleSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  scanId: IdSchema,
  /** `ConfirmedFinding.id` this rule was generated to detect. */
  findingId: IdSchema,
  format: DetectionRuleFormatSchema,
  /** The actual rule text: Sigma YAML, an OTel query, or a SIEM query string. */
  content: z.string().min(1),
  /** MITRE ATT&CK technique ids this rule detects (B2 populates the mapping). */
  mitreTechniques: z.array(z.string().min(1)).default([]),
  /** Derived from a live-DAST transcript ("live") or a static data-flow path ("static"). */
  provenance: ProofTypeSchema,
  /** B4 — "what this looks like in your logs" narrative (see doc comment above). */
  logSignature: DetectionLogSignatureSchema.optional(),
  createdAt: IsoDateTimeSchema,
});
export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

/** One hop in an attack-path chain — a confirmed finding plus why it leads to the next hop. */
export const AttackPathStepSchema = z.object({
  /** `ConfirmedFinding.id` of this hop. */
  findingId: IdSchema,
  /** How this hop connects to the next (e.g. "SSRF response leaks the metadata endpoint URL"). */
  note: z.string().optional(),
});
export type AttackPathStep = z.infer<typeof AttackPathStepSchema>;

/**
 * A chained kill-chain across >= 2 confirmed findings (e.g. "public route ->
 * SSRF -> metadata endpoint -> credentials"). `steps` is ordered: index 0 is
 * the entry point, the last index is the terminal impact. `.min(2)` enforces
 * this is a genuine chain, not a single finding wearing an AttackPath wrapper.
 */
export const AttackPathSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  scanId: IdSchema,
  steps: z.array(AttackPathStepSchema).min(2),
  /** End-to-end path feasibility, normalized [0, 1] (mirrors reachability/exposure/impact scores). */
  feasibilityScore: Score01Schema,
  /** End-to-end path severity (typically >= the severity of any single hop). */
  severity: SeveritySchema,
  /** Human-readable kill-chain narrative/summary. */
  narrative: z.string().min(1),
  createdAt: IsoDateTimeSchema,
});
export type AttackPath = z.infer<typeof AttackPathSchema>;

/**
 * Tri-state detection verdict: `true` (would be detected), `false` (would
 * NOT be detected), or `"unknown"` (not enough telemetry-surface info to
 * say). Deliberately not a plain boolean — collapsing "no" and "we don't
 * know" would overstate confidence in either direction.
 */
export const DetectionStatusSchema = z.union([z.boolean(), z.literal("unknown")]);
export type DetectionStatus = z.infer<typeof DetectionStatusSchema>;

/**
 * The result of actually running a scenario against the target and checking
 * whether the expected detection fired — B5's purple-team loop is the sole
 * writer of this shape (this schema only defines it; B5 builds the runner).
 */
export const DetectionVerificationResultSchema = z.object({
  /** The `RedTeamScenario.id` (if any) that was executed to produce this result. */
  scenarioId: IdSchema.optional(),
  /** Whether the expected alert/detection actually fired when the scenario ran. */
  fired: z.boolean(),
  verifiedAt: IsoDateTimeSchema,
  /** Reference to the concrete evidence (e.g. a SIEM alert id, a log excerpt pointer). */
  evidence: z.string().optional(),
});
export type DetectionVerificationResult = z.infer<typeof DetectionVerificationResultSchema>;

/**
 * Whether a target's existing telemetry would catch a confirmed finding if
 * exploited. `detectionRuleId`, like `findingId`, is a plain reference (a
 * `DetectionRule.id`) — optional because a finding can lack any generated
 * rule and still get a coverage verdict (e.g. "unknown, no relevant rule
 * exists yet"). `verification` starts absent and is populated once B5's
 * purple-team loop actually runs a scenario and observes whether it fired.
 */
export const DetectionCoverageSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  scanId: IdSchema,
  /** `ConfirmedFinding.id` this coverage verdict is about. */
  findingId: IdSchema,
  detected: DetectionStatusSchema,
  /** Reasoning/evidence behind the verdict (never a bare score with no justification). */
  reasoning: z.string().min(1),
  /** `DetectionRule.id` covering this finding, if one exists. */
  detectionRuleId: IdSchema.optional(),
  /** Populated by B5's purple-team loop; absent until a scenario has actually been run. */
  verification: DetectionVerificationResultSchema.optional(),
  createdAt: IsoDateTimeSchema,
});
export type DetectionCoverage = z.infer<typeof DetectionCoverageSchema>;
