/**
 * Canonical audit hash-chain helpers (§8.5, §14) — node:crypto only.
 *
 * This MIRRORS `@montr/state-store`'s `hash-chain.ts` byte-for-byte in algorithm
 * so the verifier reproduces exactly how events were hashed on append:
 *
 *   hash = sha256(prevHash + canonicalJson({ ...event, hash: undefined }))
 *
 * It is re-implemented here (rather than imported) so `@montr/security` stays a
 * leaf package depending only on `@montr/contracts` — a security/audit tool must
 * not pull the Prisma runtime just to check hashes. Equivalence with the
 * state-store implementation is guaranteed by a CONFORMANCE TEST
 * (`tests/security.audit-verify.test.ts`) that cross-checks both on shared
 * fixtures; if state-store ever changes the canonical form, that test fails.
 *
 * The FIRST event per client uses prevHash = "" (empty string).
 */
import { createHash } from "node:crypto";
import type { AuditEvent } from "@montr/contracts";

/** Stable, key-sorted JSON — the canonical form hashed for the audit chain. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      const v = obj[key];
      if (v !== undefined) out[key] = sortDeep(v);
    }
    return out;
  }
  return value;
}

/** Compute the next audit-chain hash: sha256(prevHash + canonicalJson(event\hash)). */
export function computeAuditHash(prevHash: string, eventWithoutHash: unknown): string {
  return createHash("sha256")
    .update(prevHash + canonicalJson(eventWithoutHash))
    .digest("hex");
}

/** The exact object hashed for an event: the full AuditEvent minus its own `hash`. */
export function auditHashPayload(event: AuditEvent): Record<string, unknown> {
  const { hash: _hash, ...rest } = event;
  return rest;
}

/** Recompute an event's hash from its fields + the given previous hash. */
export function hashAuditEvent(event: AuditEvent, prevHash: string): string {
  return computeAuditHash(prevHash, auditHashPayload(event));
}

export interface ChainVerification {
  ok: boolean;
  /** 1-based index of the first broken record, if any. */
  brokenAt?: number;
  reason?: string;
}

/**
 * Verify a per-client audit chain. `events` MUST be ordered by ascending
 * sequence. Checks: monotonic 1-based sequence, prevHash linkage, and that each
 * stored hash matches a recomputation.
 */
export function verifyChainRecords(events: readonly AuditEvent[]): ChainVerification {
  let prevHash = "";
  let expectedSequence = 1;
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event) continue;
    if (event.sequence !== expectedSequence) {
      return {
        ok: false,
        brokenAt: i + 1,
        reason: `sequence gap: expected ${expectedSequence}, got ${event.sequence}`,
      };
    }
    if (event.prevHash !== prevHash) {
      return { ok: false, brokenAt: i + 1, reason: "prevHash does not match prior hash" };
    }
    const recomputed = hashAuditEvent(event, prevHash);
    if (recomputed !== event.hash) {
      return { ok: false, brokenAt: i + 1, reason: "hash mismatch (record altered)" };
    }
    prevHash = event.hash;
    expectedSequence += 1;
  }
  return { ok: true };
}
