import { z } from "zod";
import { IdSchema, IsoDateTimeSchema, UrlSchema } from "./primitives.js";
import { RiskClassSchema, FixStatusSchema } from "./enums.js";

/**
 * PRD §9 — Fix. For each CONFIRMED finding: a diff-ready patch, a plain-English
 * rationale, and a proof-of-fix test that fails pre-patch and passes post-patch.
 */

/** The proof-of-fix test. Must fail before the patch and pass after it (§7 L4). */
export const ProofOfFixTestSchema = z.object({
  filePath: z.string().optional(),
  framework: z.string().optional(),
  code: z.string(),
  failsPrePatch: z.boolean(),
  passesPostPatch: z.boolean(),
});
export type ProofOfFixTest = z.infer<typeof ProofOfFixTestSchema>;

export const FixSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  clientId: IdSchema,
  confirmedFindingId: IdSchema,
  /** Unified-diff patch (applies cleanly to the target repo). */
  patch: z.string(),
  rationale: z.string(),
  proofOfFixTest: ProofOfFixTestSchema,
  riskClass: RiskClassSchema,
  /**
   * Why the risk classifier chose this class. REQUIRED for auditability —
   * auth/session/crypto/access-control ⇒ human-required is a hard rule (§11).
   */
  riskClassRationale: z.string(),
  status: FixStatusSchema.default("proposed"),
  pullRequestId: IdSchema.optional(),
  createdAt: IsoDateTimeSchema,
  updatedAt: IsoDateTimeSchema.optional(),
});
export type Fix = z.infer<typeof FixSchema>;

/** Version-control host for the gated auto-fix PR flow. */
export const VcsProviderSchema = z.enum(["github", "gitlab"]);
export type VcsProvider = z.infer<typeof VcsProviderSchema>;

export const PullRequestStatusSchema = z.enum(["draft", "open", "merged", "closed"]);
export type PullRequestStatus = z.infer<typeof PullRequestStatusSchema>;

/**
 * A pull request opened for auto-eligible fixes ONLY (never a direct commit;
 * golden rule #5, §7 L5). Each PR is independently reviewable.
 */
export const PullRequestSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  clientId: IdSchema,
  provider: VcsProviderSchema,
  url: UrlSchema.optional(),
  number: z.number().int().positive().optional(),
  branch: z.string().min(1),
  baseBranch: z.string().min(1).default("main"),
  title: z.string().min(1),
  bodySummary: z.string(),
  fixIds: z.array(IdSchema).min(1),
  status: PullRequestStatusSchema.default("open"),
  createdAt: IsoDateTimeSchema,
});
export type PullRequest = z.infer<typeof PullRequestSchema>;
