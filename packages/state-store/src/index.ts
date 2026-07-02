/**
 * @montr/state-store — Prisma client wrapper, typed per-client repositories,
 * field-level encryption, resumable pipeline state, and the tamper-evident
 * audit log (§8.3, §8.5, DECIDE-2).
 *
 * Wave 0: canonical-JSON + hash-chain helpers are REAL (needed by the audit log
 * and deterministic). Repositories are typed stubs whose signatures match the
 * frozen contracts; the Prisma wiring lands in WS-C. Every method is scoped by
 * `clientId` — per-client data is NEVER shared.
 */
import { createHash } from "node:crypto";
import {
  NotImplementedError,
  type AppMap,
  type CandidateFinding,
  type ConfirmedFinding,
  type Fix,
  type ProbableFinding,
  type ResumeToken,
  type Scan,
  type UnconfirmedFinding,
} from "@montr/contracts";
import type { AuditLogClient } from "@montr/telemetry";

/** Stable, key-sorted JSON — the canonical form hashed for the audit chain. */
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

/**
 * Compute the next audit-chain hash.
 * `hash = sha256(prevHash + canonicalJson(eventWithoutHash))`.
 */
export function computeAuditHash(prevHash: string, eventWithoutHash: unknown): string {
  return createHash("sha256")
    .update(prevHash + canonicalJson(eventWithoutHash))
    .digest("hex");
}

/** Common repository shape — all reads/writes are scoped by clientId. */
export interface Repository<T> {
  create(clientId: string, entity: T): Promise<T>;
  get(clientId: string, id: string): Promise<T | null>;
  list(clientId: string, filter?: Record<string, unknown>): Promise<T[]>;
}

export interface ScanRepository extends Repository<Scan> {
  update(clientId: string, scan: Scan): Promise<Scan>;
}

export interface AppMapRepository extends Repository<AppMap> {
  /** Latest persisted map for a repo/commit (DECIDE-2 stale check). */
  latestForCommit(clientId: string, repo: string, commitSha: string): Promise<AppMap | null>;
  markStale(clientId: string, appMapId: string): Promise<void>;
}

export interface FindingRepository<T> extends Repository<T> {
  bulkCreate(clientId: string, findings: T[]): Promise<T[]>;
  listByScan(clientId: string, scanId: string): Promise<T[]>;
}

export interface FixRepository extends Repository<Fix> {
  update(clientId: string, fix: Fix): Promise<Fix>;
  listByScan(clientId: string, scanId: string): Promise<Fix[]>;
}

/** Resumable pipeline state (§8.1): a failed Layer-3 must not re-run Layer 0–2. */
export interface ResumeRepository {
  save(clientId: string, token: ResumeToken): Promise<ResumeToken>;
  get(clientId: string, scanId: string): Promise<ResumeToken | null>;
}

/** The aggregate persistence surface handed to the orchestrator and layers. */
export interface StateStore {
  scans: ScanRepository;
  appMaps: AppMapRepository;
  candidates: FindingRepository<CandidateFinding>;
  probable: FindingRepository<ProbableFinding>;
  confirmed: FindingRepository<ConfirmedFinding>;
  unconfirmed: FindingRepository<UnconfirmedFinding>;
  fixes: FixRepository;
  resume: ResumeRepository;
  audit: AuditLogClient;
  disconnect(): Promise<void>;
}

export interface CreateStateStoreOptions {
  /** Postgres connection string (DATABASE_URL). */
  databaseUrl: string;
  /** AES-256-GCM field-encryption key material (from KMS/Vault/k8s secret). */
  fieldEncryptionKey?: string;
}

export function createStateStore(_opts: CreateStateStoreOptions): StateStore {
  throw new NotImplementedError("createStateStore — WS-C");
}
