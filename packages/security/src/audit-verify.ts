/**
 * AUDIT HASH-CHAIN VERIFIER (build-plan §4.8, §8.5, golden rule #7).
 *
 * Recomputes and validates the append-only, hash-chained audit log and detects
 * tampering (insert / delete / reorder / field edit / truncation). It validates
 * each record against `AuditEventSchema` from `@montr/contracts` and re-derives
 * hashes with the canonical helpers in `./hash-chain` — which mirror, and are
 * conformance-tested against, `@montr/state-store` — so the verifier can never
 * drift from how events were hashed on append.
 *
 * Input is a per-client audit export (as produced by the state-store audit
 * export: `{ ..., events: AuditEvent[] }`) or a bare `AuditEvent[]`. A full,
 * intact chain starts at sequence 1 with prevHash "" — so a truncated head is
 * correctly reported as a break.
 */
import { AuditEventSchema, type AuditEvent } from "@montr/contracts";
import { verifyChainRecords } from "./hash-chain.js";

/** Thrown when the input cannot be parsed or fails schema validation. */
export class AuditInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditInputError";
    Object.setPrototypeOf(this, AuditInputError.prototype);
  }
}

export interface ClientChainResult {
  readonly clientId: string;
  readonly count: number;
  readonly ok: boolean;
  /** 1-based index of the first broken record, if any. */
  readonly brokenAt?: number;
  readonly reason?: string;
  readonly firstSequence?: number;
  readonly lastSequence?: number;
}

export interface AuditVerifyReport {
  readonly ok: boolean;
  readonly totalEvents: number;
  readonly clients: readonly ClientChainResult[];
}

/**
 * Parse an audit export (envelope `{ events: [...] }` or bare array) and validate
 * every record against the contract schema. Throws {@link AuditInputError} on
 * malformed input.
 */
export function parseAuditExport(text: string): AuditEvent[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (e) {
    throw new AuditInputError(`invalid JSON: ${(e as Error).message}`);
  }
  let raw: unknown;
  if (Array.isArray(json)) {
    raw = json;
  } else if (json && typeof json === "object" && "events" in json) {
    raw = (json as { events: unknown }).events;
  } else {
    throw new AuditInputError(
      "expected an array of audit events or an object with an 'events' array",
    );
  }
  // `.array()` avoids importing zod directly; validates each record's fields.
  const result = AuditEventSchema.array().safeParse(raw);
  if (!result.success) {
    throw new AuditInputError(
      `audit records failed contract validation (${result.error.issues.length} issue(s)): ${result.error.issues[0]?.message ?? "unknown"}`,
    );
  }
  return result.data;
}

/**
 * Verify the hash chain for the given events, grouped per client. Each group is
 * ordered by ascending sequence and validated with the canonical
 * `verifyChainRecords`. When `clientId` is given, only that client is verified
 * (and its absence is reported as a failure).
 */
export function verifyAuditEvents(
  events: readonly AuditEvent[],
  opts: { readonly clientId?: string } = {},
): AuditVerifyReport {
  const groups = new Map<string, AuditEvent[]>();
  for (const e of events) {
    if (opts.clientId && e.clientId !== opts.clientId) continue;
    let arr = groups.get(e.clientId);
    if (!arr) {
      arr = [];
      groups.set(e.clientId, arr);
    }
    arr.push(e);
  }

  const clients: ClientChainResult[] = [];
  let ok = true;
  let total = 0;
  for (const [clientId, evs] of groups) {
    const sorted = [...evs].sort((a, b) => a.sequence - b.sequence);
    const res = verifyChainRecords(sorted);
    total += sorted.length;
    if (!res.ok) ok = false;
    clients.push({
      clientId,
      count: sorted.length,
      ok: res.ok,
      ...(res.brokenAt !== undefined ? { brokenAt: res.brokenAt } : {}),
      ...(res.reason !== undefined ? { reason: res.reason } : {}),
      ...(sorted[0] ? { firstSequence: sorted[0].sequence } : {}),
      ...(sorted.length > 0 ? { lastSequence: sorted[sorted.length - 1]!.sequence } : {}),
    });
  }

  if (opts.clientId && !groups.has(opts.clientId)) {
    ok = false;
    clients.push({ clientId: opts.clientId, count: 0, ok: false, reason: "no events for client" });
  }

  clients.sort((a, b) => a.clientId.localeCompare(b.clientId));
  return { ok, totalEvents: total, clients };
}

/** Parse an export string and verify it in one step. */
export function verifyAuditExport(
  text: string,
  opts: { readonly clientId?: string } = {},
): AuditVerifyReport {
  return verifyAuditEvents(parseAuditExport(text), opts);
}
