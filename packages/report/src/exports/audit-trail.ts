/**
 * Third-party-auditor AUDIT-TRAIL surfacing through the report layer (§13, §14).
 *
 * The tamper-evident, hash-chained audit log itself lives in @montr/state-store
 * (it needs Prisma + node:crypto). This module (1) re-exports the store's
 * `exportAuditLog` so the report/API layer has a single import surface, (2) wraps
 * it to also attach a SHA-256 content digest + chain-verification flag, and (3)
 * builds a compact {@link AuditTrailLink} that the SOC 2 / ISO 27001 evidence
 * packages embed so an auditor can pivot from a finding to the immutable trail.
 *
 * Everything here is offline-testable: the audit accessor is an injected
 * structural interface (satisfied by the store's `PrismaAuditLogClient` /
 * `AuditLog`), never a live DB.
 */
import { createHash } from "node:crypto";

/**
 * The minimal audit surface the report layer needs. Structurally satisfied by
 * @montr/state-store's `AuditLog` / `PrismaAuditLogClient`. Kept minimal so tests
 * can inject a tiny fake with no Prisma.
 */
export interface AuditTrailAccess {
  exportJson(clientId: string): Promise<string>;
  exportCsv(clientId: string): Promise<string>;
  /** Tamper-evident chain check (§14). */
  verifyChain(clientId: string): Promise<boolean>;
}

export type AuditTrailFormat = "json" | "csv";

/** A produced audit-trail export (content + integrity metadata). */
export interface AuditTrailExport {
  clientId: string;
  format: AuditTrailFormat;
  content: string;
  contentType: string;
  filename: string;
  /** ⛔ Tamper-evident: false means the hash chain did not verify. */
  chainVerified: boolean;
  /** SHA-256 of `content` — lets an evidence package bind to an exact trail. */
  sha256: string;
  sizeBytes: number;
}

/** Compact reference embedded in evidence packages (no bulk content). */
export interface AuditTrailLink {
  clientId: string;
  /** True when a live audit accessor was supplied and produced a trail. */
  available: boolean;
  format: AuditTrailFormat;
  /** Suggested filename of the companion audit export an auditor pulls. */
  filename: string;
  chainVerified?: boolean;
  sha256?: string;
  sizeBytes?: number;
  note?: string;
}

function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function auditFilename(clientId: string, format: AuditTrailFormat): string {
  return `audit-${clientId}.${format}`;
}

/**
 * Produce a third-party-auditor audit-trail export through the report layer.
 * Adds a SHA-256 digest + chain-verification flag on top of the raw store export.
 */
export async function exportAuditTrail(
  audit: AuditTrailAccess,
  clientId: string,
  format: AuditTrailFormat = "json",
): Promise<AuditTrailExport> {
  const content =
    format === "csv" ? await audit.exportCsv(clientId) : await audit.exportJson(clientId);
  const chainVerified = await audit.verifyChain(clientId);
  return {
    clientId,
    format,
    content,
    contentType: format === "csv" ? "text/csv" : "application/json",
    filename: auditFilename(clientId, format),
    chainVerified,
    sha256: sha256Hex(content),
    sizeBytes: Buffer.byteLength(content, "utf8"),
  };
}

/**
 * Build the compact {@link AuditTrailLink} embedded in an evidence package. When
 * no accessor is supplied, returns an `available: false` reference (fail-safe —
 * the evidence package is still valid and clearly notes the trail is fetched
 * separately from the state store).
 */
export async function buildAuditTrailLink(
  clientId: string,
  audit?: AuditTrailAccess,
  format: AuditTrailFormat = "json",
): Promise<AuditTrailLink> {
  if (!audit) {
    return {
      clientId,
      available: false,
      format,
      filename: auditFilename(clientId, format),
      note: "Tamper-evident audit trail available on request via @montr/state-store exportAuditLog; not embedded in this package.",
    };
  }
  const exported = await exportAuditTrail(audit, clientId, format);
  return {
    clientId,
    available: true,
    format,
    filename: exported.filename,
    chainVerified: exported.chainVerified,
    sha256: exported.sha256,
    sizeBytes: exported.sizeBytes,
    note: exported.chainVerified
      ? "Hash chain verified intact at export time."
      : "WARNING: hash chain did not verify — trail may be tampered.",
  };
}
