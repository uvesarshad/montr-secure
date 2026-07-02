/**
 * Persist Layer-1 candidates to the state store and AUDIT the write (§5.2, §8.5,
 * golden rule #7: every persisted mutation is audit-logged). Typed against
 * NARROW structural interfaces so both the real @montr/state-store `StateStore`
 * (whose `candidates` repo and `audit` client satisfy these) and a tiny fake
 * (tests) work with no Prisma/DB.
 *
 * ⛔ The audit metadata is COUNTS + enum breakdowns only — never a snippet, never
 * a code body, never a secret value (golden rule #1). A single bulk write is one
 * mutation → one audit event.
 */
import type { AuditActor, AuditEvent, AuditEventInput, CandidateFinding } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";
import { countBy } from "./util/text.js";

/**
 * The slice of `StateStore.candidates` this module needs. The real
 * @montr/state-store `FindingRepository<CandidateFinding>` satisfies this
 * structurally (its `bulkCreate(clientId, findings)` has the identical shape),
 * so `runDiscoveryToStore({ store: store.candidates, audit: store.audit })`
 * type-checks against the live store — while a tiny fake works for offline tests.
 */
export interface CandidatePersister {
  bulkCreate(clientId: string, findings: CandidateFinding[]): Promise<CandidateFinding[]>;
}

/**
 * The slice of `StateStore.audit` / `AuditLogClient` this module needs — the real
 * `AuditLogClient.append(input)` satisfies it structurally.
 */
export interface AuditAppender {
  append(input: AuditEventInput): Promise<AuditEvent>;
}

export interface PersistCandidatesInput {
  clientId: string;
  scanId: string;
  candidates: CandidateFinding[];
  store: CandidatePersister;
  audit?: AuditAppender;
  actor?: AuditActor;
  logger?: Logger;
}

const DEFAULT_ACTOR: AuditActor = { type: "agent", id: "discovery" };

/**
 * Bulk-persist candidates, then append one `finding.candidate_created` audit
 * event summarizing the batch. Returns the persisted rows. A no-op on empty.
 */
export async function persistCandidates(
  input: PersistCandidatesInput,
): Promise<CandidateFinding[]> {
  const { clientId, scanId, candidates, store, audit } = input;
  if (candidates.length === 0) return [];

  const persisted = await store.bulkCreate(clientId, candidates);

  if (audit) {
    await audit.append({
      clientId,
      scanId,
      actor: input.actor ?? DEFAULT_ACTOR,
      action: "finding.candidate_created",
      targetType: "CandidateFinding",
      summary: `Layer 1 discovery persisted ${candidates.length} candidate finding(s).`,
      // Metadata-only: counts + enum breakdowns. NO snippets / code / secrets.
      metadata: {
        count: candidates.length,
        bySource: countBy(candidates, (c) => c.source),
        byCategory: countBy(candidates, (c) => c.category),
      },
    });
  }

  input.logger?.info("discovery.persist", { scanId, count: persisted.length });
  return persisted;
}
