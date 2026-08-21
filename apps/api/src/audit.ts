/**
 * Audit binding (§8.5, golden rule #7). EVERY mutating action calls `recordAudit`
 * with the actor (id + role) and a typed AuditAction. Metadata is pre-scrubbed
 * here via @montr/telemetry's scrubber as defense in depth, but this is NOT the
 * enforcement point (golden rule #1 — never store code or secret bodies): the
 * real, unconditional gate is `PrismaAuditLogClient.append` in
 * `@montr/state-store/src/audit.ts`, which scrubs metadata AND summary with
 * `@montr/security`'s stronger redactor regardless of what any caller —
 * including this one — already did (audit finding A24).
 */
import type { AuditAction, AuditActor, AuditEvent } from "@montr/contracts";
import { scrubFields } from "@montr/telemetry";
import type { AuthenticatedUser } from "./types.js";
import type { ApiStore } from "./store.js";

export function actorFromUser(user: AuthenticatedUser): AuditActor {
  return { type: "user", id: user.id, role: user.role };
}

export const SYSTEM_ACTOR: AuditActor = { type: "system", id: "system" };

export interface AuditInput {
  clientId: string;
  actor: AuditActor;
  action: AuditAction;
  summary: string;
  scanId?: string;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

/** Append one audit event, scrubbing metadata first. Returns the persisted event. */
export function recordAudit(store: ApiStore, input: AuditInput): Promise<AuditEvent> {
  return store.audit.append({
    clientId: input.clientId,
    ...(input.scanId ? { scanId: input.scanId } : {}),
    actor: input.actor,
    action: input.action,
    ...(input.targetType ? { targetType: input.targetType } : {}),
    ...(input.targetId ? { targetId: input.targetId } : {}),
    summary: input.summary,
    metadata: scrubFields(input.metadata) as Record<string, unknown>,
  });
}
