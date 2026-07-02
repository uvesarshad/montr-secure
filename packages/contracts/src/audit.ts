import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { RoleSchema } from "./enums.js";

/**
 * Audit contracts (§8.5). The audit log is append-only and hash-chained
 * (tamper-evident): every agent action, every LLM call (metadata only, never
 * code bodies), every code modification, and every human approval is recorded.
 * The hashing helper lives in @montr/state-store (needs node:crypto); this file
 * defines only the shape.
 */

export const ActorTypeSchema = z.enum(["user", "agent", "system"]);
export type ActorType = z.infer<typeof ActorTypeSchema>;

export const AuditActorSchema = z.object({
  type: ActorTypeSchema,
  id: IdSchema,
  /** Present for user actors. */
  role: RoleSchema.optional(),
});
export type AuditActor = z.infer<typeof AuditActorSchema>;

/** Every audited action type. Bind every mutating action to one of these. */
export const AuditActionSchema = z.enum([
  "scan.created",
  "scan.started",
  "scan.paused",
  "scan.resumed",
  "scan.cancelled",
  "scan.completed",
  "scan.failed",
  "gate.estimate_presented",
  "gate.estimate_approved",
  "gate.fix_approved",
  "gate.rejected",
  "llm.call",
  "appmap.built",
  "appmap.invalidated",
  "finding.candidate_created",
  "finding.promoted_probable",
  "finding.confirmed",
  "finding.demoted",
  "finding.marked_false_positive",
  "fix.generated",
  "fix.pr_opened",
  "fix.merged",
  "fix.rejected",
  "dast.authorized",
  "dast.probe",
  "dast.kill_switch",
  "budget.warning",
  "budget.exceeded",
  "config.changed",
  "auth.login",
  "auth.role_changed",
  "export.generated",
]);
export type AuditAction = z.infer<typeof AuditActionSchema>;

/**
 * One append-only audit record.
 * `hash = sha256(prevHash + canonicalJson({ ...event, hash: undefined }))`.
 * `prevHash` of the first record per client is the empty string.
 * `metadata` MUST be scrubbed of code/secret bodies before writing.
 */
export const AuditEventSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  /** Monotonic per-client sequence number (1-based). */
  sequence: z.number().int().positive(),
  scanId: IdSchema.optional(),
  actor: AuditActorSchema,
  action: AuditActionSchema,
  targetType: z.string().optional(),
  targetId: IdSchema.optional(),
  summary: z.string(),
  metadata: z.record(z.string(), z.unknown()).default({}),
  prevHash: z.string(),
  hash: z.string(),
  at: IsoDateTimeSchema,
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

/** Input to append an event (hash/sequence/prevHash are computed by the store). */
export const AuditEventInputSchema = AuditEventSchema.omit({
  id: true,
  sequence: true,
  prevHash: true,
  hash: true,
  at: true,
});
export type AuditEventInput = z.infer<typeof AuditEventInputSchema>;
