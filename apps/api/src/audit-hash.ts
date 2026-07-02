/**
 * Canonical-JSON + audit hash-chain helpers.
 *
 * These mirror the tamper-evident chain defined by @montr/contracts' AuditEvent
 * (`hash = sha256(prevHash + canonicalJson(eventWithoutHash))`). They are
 * reimplemented locally (identical algorithm) so the API's in-memory audit
 * client does not take a build-time dependency on @montr/state-store while that
 * package is in flight. The Postgres-backed client (WS-C) uses the same formula.
 */
import { createHash } from "node:crypto";

/** Stable, key-sorted JSON — the canonical form that is hashed. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) out[key] = sortDeep(obj[key]);
    return out;
  }
  return value;
}

/** `hash = sha256(prevHash + canonicalJson(eventWithoutHash))`. */
export function computeAuditHash(prevHash: string, eventWithoutHash: unknown): string {
  return createHash("sha256")
    .update(prevHash + canonicalJson(eventWithoutHash))
    .digest("hex");
}
