import { z } from "zod";
import { IdSchema, IsoDateTimeSchema, UrlSchema } from "./primitives.js";
import { RiskClassSchema, FixStatusSchema } from "./enums.js";
import { HttpExchangeSchema } from "./findings.js";

/**
 * PRD §9 — Fix. For each CONFIRMED finding: a diff-ready patch, a plain-English
 * rationale, and a proof-of-fix test that fails pre-patch and passes post-patch.
 */

/**
 * E13 — evidence from a genuine ephemeral-container replay of a CONFIRMED
 * finding's live-DAST exploit transcript, ONLY present when
 * `packages/fix/src/generate.ts`'s opt-in `containerProof` was enabled AND the
 * finding carried a real live-DAST proof artifact to replay (see
 * `packages/fix/src/container-validate.ts`). Reuses `HttpExchangeSchema` — the
 * same shape `ConfirmedFinding.proofArtifact`'s live-DAST transcript already
 * uses — since this is the same kind of evidence (a real request/response
 * pair), just captured against a throwaway container instead of the original
 * staging target. `failsPrePatch`/`passesPostPatch` above are still the
 * authoritative pass/fail verdict either way (vitest-subprocess OR container
 * replay); this field is the additional, strictly-additive evidence artifact.
 */
export const ContainerReplayEvidenceSchema = z.object({
  attempted: z.boolean(),
  replayed: z.boolean(),
  category: z.string().optional(),
  harness: z.enum(["dockerfile", "synthesized-node"]).optional(),
  probeReplayed: z.object({ method: z.string(), url: z.string() }).optional(),
  prePatch: z.object({ exploitSucceeded: z.boolean(), exchange: HttpExchangeSchema }).optional(),
  postPatch: z.object({ exploitSucceeded: z.boolean(), exchange: HttpExchangeSchema }).optional(),
  /** Why this validation fell back to the vitest-subprocess mechanism instead
   * of replaying (no live evidence, no target checkout, empty transcript, …). */
  reason: z.string().optional(),
  /** Set on a genuine container-infra failure (build/start/timeout), distinct from `reason`. */
  error: z.string().optional(),
});
export type ContainerReplayEvidence = z.infer<typeof ContainerReplayEvidenceSchema>;

/** The proof-of-fix test. Must fail before the patch and pass after it (§7 L4). */
export const ProofOfFixTestSchema = z.object({
  filePath: z.string().optional(),
  framework: z.string().optional(),
  code: z.string(),
  failsPrePatch: z.boolean(),
  passesPostPatch: z.boolean(),
  /** E13: real ephemeral-container exploit-replay evidence, when attempted. */
  containerReplay: ContainerReplayEvidenceSchema.optional(),
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
