import { z } from "zod";
import { IdSchema, IsoDateTimeSchema, SourceLocationSchema, Score01Schema } from "./primitives.js";
import { SeveritySchema, ExposureSchema, ProofTypeSchema, AuthStateSchema } from "./enums.js";
import { ToolSourceSchema } from "./enums.js";
import { CategorySchema, CweIdSchema, OwaspIdSchema } from "./compliance.js";

/**
 * PRD §9 — the three finding tiers. Findings only ever move DOWN a tier via an
 * appendix (never deleted, golden rule / §7 L2). Report headlines confirmed
 * findings; Layer-1 candidates are never surfaced to the user directly.
 */

/**
 * Layer 1 output. Deliberately over-inclusive, tagged with the producing tool.
 * `evidenceSnippet` is a short in-perimeter excerpt for triage — it is metadata,
 * never egressed outside a call to the client's own LLM key (§11, golden rule #1).
 */
export const CandidateFindingSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  clientId: IdSchema,
  source: ToolSourceSchema,
  ruleId: z.string().min(1),
  category: CategorySchema,
  cwe: z.array(CweIdSchema).default([]),
  location: SourceLocationSchema,
  rawSeverity: SeveritySchema,
  evidenceSnippet: z.string().default(""),
  title: z.string().optional(),
  status: z.literal("candidate").default("candidate"),
  createdAt: IsoDateTimeSchema,
  metadata: z.record(z.string(), z.unknown()).optional(),
});
export type CandidateFinding = z.infer<typeof CandidateFindingSchema>;

/**
 * Layer 2 output. Candidates corroborated against the App Map, deduped into one
 * root cause, and ranked by reachability × exposure × impact (not raw CVSS).
 */
export const ProbableFindingSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  clientId: IdSchema,
  rootCauseId: IdSchema,
  category: CategorySchema,
  /** Candidate ids merged into this single issue. */
  mergedCandidateIds: z.array(IdSchema).default([]),
  reachabilityHypothesis: z.string(),
  exploitHypothesis: z.string(),
  exposure: ExposureSchema,
  authGate: z.string().optional(),
  routeId: IdSchema.optional(),
  location: SourceLocationSchema,
  reachabilityScore: Score01Schema,
  exposureScore: Score01Schema,
  impactScore: Score01Schema,
  /** Final ordering rank (1 = highest). Derived from the three scores. */
  rank: z.number().int().positive(),
  status: z.literal("probable").default("probable"),
  createdAt: IsoDateTimeSchema,
});
export type ProbableFinding = z.infer<typeof ProbableFindingSchema>;

/** A single hop in a static data-flow proof, with the auth state at that hop. */
export const DataFlowHopSchema = z.object({
  location: SourceLocationSchema,
  authState: AuthStateSchema,
  transform: z.string().optional(),
  note: z.string().optional(),
});
export type DataFlowHop = z.infer<typeof DataFlowHopSchema>;

/** Static proof-of-reachability (no requests fired). */
export const StaticProofSchema = z.object({
  kind: z.literal("static"),
  argument: z.string(),
  dataFlow: z.array(DataFlowHopSchema).default([]),
  sanitizersBypassed: z.array(z.string()).default([]),
});
export type StaticProof = z.infer<typeof StaticProofSchema>;

/** A single request/response pair captured during live DAST. */
export const HttpExchangeSchema = z.object({
  request: z.object({
    method: z.string(),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
    bodySnippet: z.string().optional(),
  }),
  response: z.object({
    status: z.number().int(),
    headers: z.record(z.string(), z.string()).optional(),
    bodySnippet: z.string().optional(),
  }),
  note: z.string().optional(),
});
export type HttpExchange = z.infer<typeof HttpExchangeSchema>;

/** Live proof — a full request/response transcript against an allowlisted staging target. */
export const LiveProofSchema = z.object({
  kind: z.literal("live"),
  target: z.string(),
  transcript: z.array(HttpExchangeSchema).default([]),
});
export type LiveProof = z.infer<typeof LiveProofSchema>;

export const ProofArtifactSchema = z.discriminatedUnion("kind", [
  StaticProofSchema,
  LiveProofSchema,
]);
export type ProofArtifact = z.infer<typeof ProofArtifactSchema>;

/**
 * Layer 3 output. A probable finding proven exploitable. `proofType` and
 * `proofArtifact.kind` must agree.
 */
export const ConfirmedFindingSchema = z
  .object({
    id: IdSchema,
    scanId: IdSchema,
    clientId: IdSchema,
    probableId: IdSchema.optional(),
    title: z.string().min(1),
    category: CategorySchema,
    cwe: z.array(CweIdSchema).default([]),
    owasp: OwaspIdSchema.optional(),
    severity: SeveritySchema,
    exposure: ExposureSchema,
    location: SourceLocationSchema,
    impact: z.string(),
    proofType: ProofTypeSchema,
    proofArtifact: ProofArtifactSchema,
    status: z.literal("confirmed").default("confirmed"),
    createdAt: IsoDateTimeSchema,
  })
  .superRefine((val, ctx) => {
    if (val.proofType !== val.proofArtifact.kind) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `proofType "${val.proofType}" must match proofArtifact.kind "${val.proofArtifact.kind}"`,
        path: ["proofArtifact"],
      });
    }
  });
export type ConfirmedFinding = z.infer<typeof ConfirmedFindingSchema>;

/**
 * Probable findings that failed confirmation. Kept in a clearly-separated
 * appendix (§7 L3) — never deleted.
 */
export const UnconfirmedFindingSchema = ProbableFindingSchema.omit({ status: true }).extend({
  status: z.literal("unconfirmed").default("unconfirmed"),
  unconfirmedReason: z.string(),
});
export type UnconfirmedFinding = z.infer<typeof UnconfirmedFindingSchema>;
