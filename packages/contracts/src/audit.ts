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
  "auth.logout",
  "auth.role_changed",
  "export.generated",
  // Phase-4 (Wave 5) — scale & intelligence. Every mutation is audited (§8.5).
  "rule.created",
  "rule.updated",
  "rule.deleted",
  "scenario.created",
  "scenario.updated",
  "scenario.deleted",
  "scenario.run", // ⛔ approver-authorized, allowlist-gated live-DAST run
  // A1 (2026-09-12 red/blue agentic-posture audit) — genuine worker-side live
  // execution, gated behind explicit written authorization (beyond RBAC).
  "scenario.authorized", // ⛔ an approver recorded a written authorization reference
  "scenario.live_run_enqueued", // ⛔ a real worker execution job was queued
  "scenario.live_run_rejected", // ⛔ execution refused (missing/stale authorization, etc.)
  "scenario.live_run_executed", // ⛔ apps/worker actually probed the target
  "schedule.created",
  "schedule.updated",
  "schedule.deleted",
  "schedule.triggered",
  "posture.snapshot",
  // E8 — cross-scan memory: an operator or the pipeline recorded a durable,
  // per-repo learned fact (see @montr/state-store's LearnedFactRepository).
  "learned_fact.recorded",
  // Suggested enhancement (2026-09-12 red/blue agentic-posture audit) — real
  // push integration for generated detection rules (packages/report/src/
  // detection-rules/push). "config" actions mirror `dast.authorized`'s
  // approver-only sensitivity (an outbound credential is stored); "pushed"/
  // "push_failed" audit every actual delivery attempt, success or failure —
  // a push failure is NEVER silently swallowed (apps/api/src/routes/
  // detection-rules.ts).
  "detection_rule.push_target_configured",
  "detection_rule.push_target_deleted",
  "detection_rule.pushed",
  "detection_rule.push_failed",
]);
export type AuditAction = z.infer<typeof AuditActionSchema>;

/**
 * One append-only audit record.
 * `hash = sha256(prevHash + canonicalJson({ ...event, hash: undefined }))`.
 * `prevHash` of the first record per client is the empty string.
 * `metadata` and `summary` MUST be scrubbed of code/secret bodies before
 * writing. A Zod type cannot express that constraint (it requires runtime
 * content inspection, not a shape check), so `z.record(z.string(),
 * z.unknown())` below stays deliberately permissive — the constraint is
 * enforced for real, unconditionally, at the single write chokepoint instead:
 * `PrismaAuditLogClient.append` in `@montr/state-store/src/audit.ts`, via
 * `@montr/security`'s `redactSensitive` + `findLogViolations` (audit finding
 * A24). Every caller of `append()` gets this for free; nothing upstream needs
 * to remember to scrub.
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
