/**
 * Audit helpers (§8.5, golden rule #7). Every live-DAST action and every
 * confirmation is bound to an append-only, hash-chained audit event via the
 * injected {@link AuditSink}. Metadata is safe-by-construction (hosts, paths,
 * status codes, categories) — never request/response bodies or code (golden rule #1).
 */
import type { AuditEventInput } from "@montr/contracts";
import type { ConfirmDeps, ConfirmInput } from "./types.js";

export function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function agentAudit(
  input: ConfirmInput,
  action: AuditEventInput["action"],
  summary: string,
  metadata: Record<string, unknown>,
  targetId?: string,
): AuditEventInput {
  return {
    clientId: input.clientId,
    scanId: input.scanId,
    actor: { type: "agent", id: "layer3-confirm" },
    action,
    targetType: targetId ? "probable_finding" : "scan",
    ...(targetId ? { targetId } : {}),
    summary,
    metadata,
  };
}

export async function safeAppend(deps: ConfirmDeps, ev: AuditEventInput): Promise<void> {
  if (!deps.audit) return;
  try {
    await deps.audit.append(ev);
  } catch (err) {
    deps.logger?.warn?.("layer3: audit append failed", { action: ev.action, error: msg(err) });
  }
}
