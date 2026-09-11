/**
 * The persistence surface the HTTP API needs.
 *
 * Scan / finding / audit repository shapes MIRROR the @montr/state-store (WS-C)
 * contracts but are declared locally (structural typing) so the API build is not
 * coupled to that package while it is in flight. Users and DAST targets are not
 * on the shared StateStore, so the API owns those interfaces and queries the
 * already-migrated Prisma tables directly (see prisma-store.ts). Reports DO have
 * a real @montr/state-store repository (`ReportRepository`) — `ReportStore` here
 * is only a structural-shape mirror, bridged to it in production by
 * `ReportRepositoryAdapter` (prisma-store.ts). `apiStoreFromStateStore` documents
 * the integration path — the real StateStore is structurally assignable to
 * `StateStoreLike`.
 */
import {
  AuditEventSchema,
  type AppMap,
  type AuditEvent,
  type AuditEventInput,
  type ConfirmedFinding,
  type CustomRule,
  type DetectionCoverage,
  type DetectionRule,
  type PostureSnapshot,
  type PullRequest,
  type RedTeamScenario,
  type Report,
  type Scan,
  type ScanSchedule,
  type UnconfirmedFinding,
} from "@montr/contracts";
import type { AuditListOptions, AuditLogClient } from "@montr/telemetry";
import { computeAuditHash } from "./audit-hash.js";
import { InMemoryUserStore, type UserRecord, type UserStore } from "./auth/users.js";

/** Mirrors @montr/state-store's `ScanRepository` (client-scoped). */
export interface ScanRepository {
  create(clientId: string, entity: Scan): Promise<Scan>;
  get(clientId: string, id: string): Promise<Scan | null>;
  list(clientId: string, filter?: Record<string, unknown>): Promise<Scan[]>;
  update(clientId: string, scan: Scan): Promise<Scan>;
}

/** Mirrors @montr/state-store's `FindingRepository<T>` (client-scoped). */
export interface FindingRepository<T> {
  create(clientId: string, entity: T): Promise<T>;
  get(clientId: string, id: string): Promise<T | null>;
  list(clientId: string, filter?: Record<string, unknown>): Promise<T[]>;
  bulkCreate(clientId: string, findings: T[]): Promise<T[]>;
  listByScan(clientId: string, scanId: string): Promise<T[]>;
}

/**
 * Mirrors @montr/state-store's `AppMapRepository` — only the read path the API
 * needs (A5): a scan's `appMapId` points at a row here, and `GET /scans/:id/appmap`
 * fetches it by id. The real repository also has `create`/`list`/`latestForRepo`/
 * etc; those extra methods don't break structural assignment.
 */
export interface AppMapRepository {
  create(clientId: string, entity: AppMap): Promise<AppMap>;
  get(clientId: string, id: string): Promise<AppMap | null>;
}

/**
 * Mirrors @montr/state-store's `PullRequestRepository` — the read path A5's
 * cross-scan `GET /pull-requests` aggregate needs. The real repository also has
 * `create`/`get`/`update`/`listByScan`; not needed here.
 */
export interface PullRequestRepository {
  create(clientId: string, entity: PullRequest): Promise<PullRequest>;
  list(clientId: string, filter?: Record<string, unknown>): Promise<PullRequest[]>;
}

/** The subset of @montr/state-store's `StateStore` the API composes from. */
export interface StateStoreLike {
  scans: ScanRepository;
  appMaps: AppMapRepository;
  pullRequests: PullRequestRepository;
  confirmed: FindingRepository<ConfirmedFinding>;
  unconfirmed: FindingRepository<UnconfirmedFinding>;
  audit: AuditLogClient;
  // Phase-4 (Wave 5). The real StateStore repos are structurally assignable
  // (they carry the same client-scoped signatures plus a few extra methods).
  customRules: CustomRuleStore;
  redTeamScenarios: RedTeamScenarioStore;
  scanSchedules: ScanScheduleStore;
  posture: PostureStore;
  // §15 cross-scan memory (E8). Real StateStore's `LearnedFactRepository` is
  // structurally assignable to `LearnedFactStore` below.
  learnedFacts: LearnedFactStore;
  // A5 — cross-scan blue-team aggregate reads (see DetectionRuleStore doc comment).
  detectionRules: DetectionRuleStore;
  detectionCoverage: DetectionCoverageStore;
  // Suggested enhancement — real StateStore's `DetectionRulePushTargetRepository`
  // is structurally assignable to `DetectionRulePushTargetStore` below.
  detectionRulePushTargets: DetectionRulePushTargetStore;
}

/** A client-authorized live-DAST target (mirrors the Prisma `DastTarget` model). */
export interface DastTarget {
  id: string;
  clientId: string;
  url: string;
  enabled: boolean;
  scopeContract: Record<string, unknown>;
  approvedById?: string;
  approvedAt?: string;
  createdAt: string;
}

export interface DastTargetStore {
  create(target: DastTarget): Promise<DastTarget>;
  get(clientId: string, id: string): Promise<DastTarget | null>;
  findByUrl(clientId: string, url: string): Promise<DastTarget | null>;
  list(clientId: string): Promise<DastTarget[]>;
  update(clientId: string, target: DastTarget): Promise<DastTarget>;
}

/** Report retrieval (report generation lives in WS-J/@montr/report). */
export interface ReportStore {
  getByScan(clientId: string, scanId: string): Promise<Report | null>;
  save(report: Report): Promise<Report>;
}

/* --------------------------------------------------------------------------- *
 * Detection-rule push target (suggested enhancement, 2026-09-12 red/blue
 * agentic-posture audit — "ship detection rules as a real push integration
 * rather than only a download"; see packages/report/src/detection-rules/push
 * for the Splunk HEC adapter this config/credential feeds). Declared locally
 * here — mirroring this file's `LearnedFact*` precedent above it — rather
 * than importing @montr/state-store's structurally-identical
 * `DetectionRulePushTarget*` types, so the API build stays decoupled the same
 * way. The real @montr/state-store `DetectionRulePushTargetRepository` is
 * structurally assignable to the `DetectionRulePushTargetStore` interface
 * below (see `apiStoreFromStateStore`).
 * --------------------------------------------------------------------------- */

/** One client's configured push target. Mirrors LlmCredential's clientId-unique, one-per-client shape. */
export interface DetectionRulePushTargetInput {
  type: string;
  endpointUrl: string;
  /** Plaintext on the way in; the real repository stores it AES-256-GCM encrypted. */
  hecToken: string;
  index?: string;
  sourcetype?: string;
}

/** A decrypted push target. `hecToken` is plaintext — NEVER log this object. */
export interface DetectionRulePushTargetRecord {
  clientId: string;
  type: string;
  endpointUrl: string;
  hecToken: string;
  index?: string;
  sourcetype?: string;
  createdAt: string;
  updatedAt: string;
}

export interface DetectionRulePushTargetStore {
  upsert(
    clientId: string,
    target: DetectionRulePushTargetInput,
  ): Promise<DetectionRulePushTargetRecord>;
  /** Returns the DECRYPTED target (secret in plaintext) or null. */
  get(clientId: string): Promise<DetectionRulePushTargetRecord | null>;
  /** Metadata only — never the secret. */
  getMetadata(
    clientId: string,
  ): Promise<Omit<DetectionRulePushTargetRecord, "hecToken" | "clientId"> | null>;
  delete(clientId: string): Promise<void>;
}

/* --------------------------------------------------------------------------- *
 * Phase-4 (Wave 5) stores — scale & intelligence (§16). Client-scoped; mirror
 * the @montr/state-store repositories (the real StateStore is structurally
 * assignable). Every mutation the routes perform is bound to an audit event.
 * --------------------------------------------------------------------------- */

/** Client custom detection rules (validated before enable). */
export interface CustomRuleStore {
  create(clientId: string, rule: CustomRule): Promise<CustomRule>;
  get(clientId: string, id: string): Promise<CustomRule | null>;
  list(clientId: string): Promise<CustomRule[]>;
  update(clientId: string, rule: CustomRule): Promise<CustomRule>;
  delete(clientId: string, id: string): Promise<void>;
}

/** ⛔ Red-team scenarios — allowlist-gated, approver-authorized to run (§11). */
export interface RedTeamScenarioStore {
  create(clientId: string, scenario: RedTeamScenario): Promise<RedTeamScenario>;
  get(clientId: string, id: string): Promise<RedTeamScenario | null>;
  list(clientId: string): Promise<RedTeamScenario[]>;
  update(clientId: string, scenario: RedTeamScenario): Promise<RedTeamScenario>;
  delete(clientId: string, id: string): Promise<void>;
}

/** Cron-scheduled scans (budget-ceiling + human-gate honoring). */
export interface ScanScheduleStore {
  create(clientId: string, schedule: ScanSchedule): Promise<ScanSchedule>;
  get(clientId: string, id: string): Promise<ScanSchedule | null>;
  list(clientId: string): Promise<ScanSchedule[]>;
  update(clientId: string, schedule: ScanSchedule): Promise<ScanSchedule>;
  delete(clientId: string, id: string): Promise<void>;
}

/** Posture-over-time snapshots (trend / regression intelligence). */
export interface PostureStore {
  record(clientId: string, snapshot: PostureSnapshot): Promise<PostureSnapshot>;
  list(clientId: string): Promise<PostureSnapshot[]>;
  listByRepo(clientId: string, repo: string): Promise<PostureSnapshot[]>;
  latestForRepo(clientId: string, repo: string): Promise<PostureSnapshot | null>;
}

/**
 * A5 (red/blue agentic-posture audit) — cross-scan blue-team aggregate reads.
 * Mirrors @montr/state-store's `DetectionRuleRepository`/`DetectionCoverageRepository`
 * (packages/state-store/src/blue-team.ts), scoped to only the `list` read path the
 * org-wide aggregate route (apps/api/src/routes/analytics.ts, GET /analytics/blue-team)
 * needs — the real repositories also have `create`/`get`/`listByFinding`/
 * `updateVerification`; those extra methods don't break structural assignment.
 * These rows are real and persisted per-scan by `persistDetectionCoverageForScan`
 * (packages/appmap/src/coverage-analysis.ts, called from Layer 3) — never mock data.
 */
export interface DetectionRuleStore {
  list(clientId: string, filter?: Record<string, unknown>): Promise<DetectionRule[]>;
}

/** See {@link DetectionRuleStore} doc comment. */
export interface DetectionCoverageStore {
  list(clientId: string, filter?: Record<string, unknown>): Promise<DetectionCoverage[]>;
}

/* --------------------------------------------------------------------------- *
 * §15 cross-scan memory (E8). Mirrors @montr/state-store's `LearnedFact` /
 * `LearnedFactInput` / `LearnedFactRepository` (declared locally per this
 * file's own decoupling convention — see the file header). Lets an operator
 * explicitly record a durable, per-repo fact (a custom sanitizer name, a
 * framework idiom, an explicit decision) that later scans of the SAME
 * `(clientId, repo)` inject as additive LLM prompt context — see
 * apps/worker/src/runners.ts's `loadLearnedFactsContext`.
 * `confirmed_false_positive` facts are NOT recorded through this surface —
 * they already have their own route, `POST /findings/:id/false-positive`
 * (findings.ts), and are merged in at read time instead (see
 * LearnedFactType's schema.prisma doc comment).
 * --------------------------------------------------------------------------- */

/**
 * `confirmed_exploit_shape` is a SYSTEM-recorded-only member (added
 * migration `14_learned_fact_confirmed_exploit_shape`) — deliberately NOT
 * part of `RecordLearnedFactBodySchema`'s operator-writable enum below, so
 * only `apps/worker/src/runners.ts`'s `recordConfirmedExploitShapes` (real,
 * gate-passed Layer 3 confirmations only) can ever write one.
 */
export type LearnedFactType =
  "custom_sanitizer" | "framework_idiom" | "operator_decision" | "confirmed_exploit_shape";

export interface LearnedFactProvenance {
  source: "operator" | "scan_derived";
  scanId?: string;
  operatorId?: string;
  at: string;
}

export interface LearnedFactRecord {
  id: string;
  clientId: string;
  repo: string;
  type: LearnedFactType;
  content: Record<string, unknown>;
  provenance: LearnedFactProvenance;
  createdAt: string;
}

export interface LearnedFactInput {
  clientId: string;
  repo: string;
  type: LearnedFactType;
  content: Record<string, unknown>;
  provenance: LearnedFactProvenance;
}

export interface LearnedFactStore {
  record(input: LearnedFactInput): Promise<LearnedFactRecord>;
  listByRepo(clientId: string, repo: string, limit?: number): Promise<LearnedFactRecord[]>;
}

/** Everything the API routes read/write. */
export interface ApiStore {
  users: UserStore;
  scans: ScanRepository;
  appMaps: AppMapRepository;
  pullRequests: PullRequestRepository;
  confirmed: FindingRepository<ConfirmedFinding>;
  unconfirmed: FindingRepository<UnconfirmedFinding>;
  reports: ReportStore;
  dastTargets: DastTargetStore;
  audit: AuditLogClient;
  // Phase-4 (Wave 5) — scale & intelligence.
  customRules: CustomRuleStore;
  redTeamScenarios: RedTeamScenarioStore;
  scanSchedules: ScanScheduleStore;
  posture: PostureStore;
  /** §15 cross-scan memory (E8) — durable per-repo learned facts. */
  learnedFacts: LearnedFactStore;
  // A5 — cross-scan blue-team aggregate reads (see DetectionRuleStore doc comment).
  detectionRules: DetectionRuleStore;
  detectionCoverage: DetectionCoverageStore;
  // Suggested enhancement (2026-09-12 red/blue agentic-posture audit) —
  // detection-rule push target config + encrypted credential.
  detectionRulePushTargets: DetectionRulePushTargetStore;
}

export interface Clock {
  now(): Date;
}

export type IdGen = (prefix?: string) => string;

/* --------------------------------------------------------------------------- *
 * In-memory implementations (dev + unit tests). Never for production use.
 * --------------------------------------------------------------------------- */

class InMemoryScanRepo implements ScanRepository {
  private readonly rows = new Map<string, Scan>();
  private key(clientId: string, id: string) {
    return `${clientId}:${id}`;
  }
  async create(clientId: string, entity: Scan): Promise<Scan> {
    this.rows.set(this.key(clientId, entity.id), { ...entity });
    return { ...entity };
  }
  async get(clientId: string, id: string): Promise<Scan | null> {
    const r = this.rows.get(this.key(clientId, id));
    return r ? { ...r } : null;
  }
  async list(clientId: string): Promise<Scan[]> {
    const out: Scan[] = [];
    for (const r of this.rows.values()) if (r.clientId === clientId) out.push({ ...r });
    return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  async update(clientId: string, scan: Scan): Promise<Scan> {
    this.rows.set(this.key(clientId, scan.id), { ...scan });
    return { ...scan };
  }
}

class InMemoryFindingRepo<
  T extends { id: string; clientId: string; scanId: string },
> implements FindingRepository<T> {
  private readonly rows = new Map<string, T>();
  private key(clientId: string, id: string) {
    return `${clientId}:${id}`;
  }
  async create(clientId: string, entity: T): Promise<T> {
    this.rows.set(this.key(clientId, entity.id), { ...entity });
    return { ...entity };
  }
  async get(clientId: string, id: string): Promise<T | null> {
    const r = this.rows.get(this.key(clientId, id));
    return r ? { ...r } : null;
  }
  async list(clientId: string): Promise<T[]> {
    const out: T[] = [];
    for (const r of this.rows.values()) if (r.clientId === clientId) out.push({ ...r });
    return out;
  }
  async bulkCreate(clientId: string, findings: T[]): Promise<T[]> {
    return Promise.all(findings.map((f) => this.create(clientId, f)));
  }
  async listByScan(clientId: string, scanId: string): Promise<T[]> {
    return (await this.list(clientId)).filter((f) => f.scanId === scanId);
  }
}

class InMemoryReportStore implements ReportStore {
  private readonly rows = new Map<string, Report>();
  private key(clientId: string, scanId: string) {
    return `${clientId}:${scanId}`;
  }
  async getByScan(clientId: string, scanId: string): Promise<Report | null> {
    const r = this.rows.get(this.key(clientId, scanId));
    return r ? { ...r } : null;
  }
  async save(report: Report): Promise<Report> {
    this.rows.set(this.key(report.clientId, report.scanId), { ...report });
    return { ...report };
  }
}

class InMemoryAppMapRepo implements AppMapRepository {
  private readonly rows = new Map<string, AppMap>();
  private key(clientId: string, id: string) {
    return `${clientId}:${id}`;
  }
  async create(clientId: string, entity: AppMap): Promise<AppMap> {
    this.rows.set(this.key(clientId, entity.id), { ...entity });
    return { ...entity };
  }
  async get(clientId: string, id: string): Promise<AppMap | null> {
    const r = this.rows.get(this.key(clientId, id));
    return r ? { ...r } : null;
  }
}

class InMemoryPullRequestRepo implements PullRequestRepository {
  private readonly rows = new Map<string, PullRequest>();
  private key(clientId: string, id: string) {
    return `${clientId}:${id}`;
  }
  async create(clientId: string, entity: PullRequest): Promise<PullRequest> {
    this.rows.set(this.key(clientId, entity.id), { ...entity });
    return { ...entity };
  }
  async list(clientId: string): Promise<PullRequest[]> {
    const out: PullRequest[] = [];
    for (const r of this.rows.values()) if (r.clientId === clientId) out.push({ ...r });
    return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
}

class InMemoryDastTargetStore implements DastTargetStore {
  private readonly rows = new Map<string, DastTarget>();
  private key(clientId: string, id: string) {
    return `${clientId}:${id}`;
  }
  async create(target: DastTarget): Promise<DastTarget> {
    this.rows.set(this.key(target.clientId, target.id), { ...target });
    return { ...target };
  }
  async get(clientId: string, id: string): Promise<DastTarget | null> {
    const r = this.rows.get(this.key(clientId, id));
    return r ? { ...r } : null;
  }
  async findByUrl(clientId: string, url: string): Promise<DastTarget | null> {
    for (const r of this.rows.values()) {
      if (r.clientId === clientId && r.url === url) return { ...r };
    }
    return null;
  }
  async list(clientId: string): Promise<DastTarget[]> {
    const out: DastTarget[] = [];
    for (const r of this.rows.values()) if (r.clientId === clientId) out.push({ ...r });
    return out;
  }
  async update(clientId: string, target: DastTarget): Promise<DastTarget> {
    this.rows.set(this.key(clientId, target.id), { ...target });
    return { ...target };
  }
}

/**
 * In-memory `DetectionRulePushTargetStore` for local dev and tests. Does NOT
 * exercise real AES-256-GCM encryption (that lives entirely in the real
 * `DetectionRulePushTargetRepositoryImpl`, packages/state-store/src/
 * detection-rule-push-target.ts, tested directly there) — mirrors this file's
 * existing precedent of a plain in-memory fake for the interface shape only.
 */
class InMemoryDetectionRulePushTargetStore implements DetectionRulePushTargetStore {
  private readonly rows = new Map<string, DetectionRulePushTargetRecord>();

  async upsert(
    clientId: string,
    target: DetectionRulePushTargetInput,
  ): Promise<DetectionRulePushTargetRecord> {
    const now = new Date().toISOString();
    const existing = this.rows.get(clientId);
    const record: DetectionRulePushTargetRecord = {
      clientId,
      type: target.type,
      endpointUrl: target.endpointUrl,
      hecToken: target.hecToken,
      ...(target.index !== undefined ? { index: target.index } : {}),
      ...(target.sourcetype !== undefined ? { sourcetype: target.sourcetype } : {}),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    this.rows.set(clientId, record);
    return { ...record };
  }

  async get(clientId: string): Promise<DetectionRulePushTargetRecord | null> {
    const r = this.rows.get(clientId);
    return r ? { ...r } : null;
  }

  async getMetadata(
    clientId: string,
  ): Promise<Omit<DetectionRulePushTargetRecord, "hecToken" | "clientId"> | null> {
    const r = this.rows.get(clientId);
    if (!r) return null;
    const { hecToken: _hecToken, clientId: _clientId, ...meta } = r;
    return meta;
  }

  async delete(clientId: string): Promise<void> {
    this.rows.delete(clientId);
  }
}

/** Generic client-scoped in-memory CRUD store for the Phase-4 entities. */
class InMemoryCrudStore<T extends { id: string; clientId: string; createdAt?: string }> {
  private readonly rows = new Map<string, T>();
  private key(clientId: string, id: string) {
    return `${clientId}:${id}`;
  }
  async create(clientId: string, entity: T): Promise<T> {
    this.rows.set(this.key(clientId, entity.id), { ...entity });
    return { ...entity };
  }
  async get(clientId: string, id: string): Promise<T | null> {
    const r = this.rows.get(this.key(clientId, id));
    return r ? { ...r } : null;
  }
  async list(clientId: string): Promise<T[]> {
    const out: T[] = [];
    for (const r of this.rows.values()) if (r.clientId === clientId) out.push({ ...r });
    return out.sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""));
  }
  async update(clientId: string, entity: T): Promise<T> {
    this.rows.set(this.key(clientId, entity.id), { ...entity });
    return { ...entity };
  }
  async delete(clientId: string, id: string): Promise<void> {
    this.rows.delete(this.key(clientId, id));
  }
}

/** In-memory posture-snapshot store (trend queries). */
class InMemoryPostureStore implements PostureStore {
  private readonly rows: PostureSnapshot[] = [];
  async record(clientId: string, snapshot: PostureSnapshot): Promise<PostureSnapshot> {
    const saved = { ...snapshot, clientId };
    this.rows.push(saved);
    return { ...saved };
  }
  async list(clientId: string): Promise<PostureSnapshot[]> {
    return this.rows.filter((r) => r.clientId === clientId).map((r) => ({ ...r }));
  }
  async listByRepo(clientId: string, repo: string): Promise<PostureSnapshot[]> {
    return this.rows
      .filter((r) => r.clientId === clientId && r.repo === repo)
      .sort((a, b) => a.at.localeCompare(b.at))
      .map((r) => ({ ...r }));
  }
  async latestForRepo(clientId: string, repo: string): Promise<PostureSnapshot | null> {
    const series = await this.listByRepo(clientId, repo);
    return series.length > 0 ? (series[series.length - 1] as PostureSnapshot) : null;
  }
}

/** In-memory learned-fact store (§15 cross-scan memory, E8), dev/tests only. */
class InMemoryLearnedFactStore implements LearnedFactStore {
  private readonly rows: LearnedFactRecord[] = [];
  private seq = 0;

  async record(input: LearnedFactInput): Promise<LearnedFactRecord> {
    const row: LearnedFactRecord = {
      ...input,
      id: `lf_${++this.seq}`,
      createdAt: input.provenance.at,
    };
    this.rows.push(row);
    return { ...row };
  }

  async listByRepo(clientId: string, repo: string, limit = 25): Promise<LearnedFactRecord[]> {
    return this.rows
      .filter((r) => r.clientId === clientId && r.repo === repo)
      .slice()
      .reverse()
      .slice(0, limit)
      .map((r) => ({ ...r }));
  }
}

/**
 * Append-only, hash-chained audit log kept in memory for dev/tests. Reuses the
 * REAL `computeAuditHash` from @montr/state-store so the chain is genuinely
 * tamper-evident (§8.5) even without Postgres.
 */
export class InMemoryAuditLogClient implements AuditLogClient {
  private readonly byClient = new Map<string, AuditEvent[]>();

  constructor(
    private readonly clock: Clock,
    private readonly idgen: IdGen,
  ) {}

  async append(input: AuditEventInput): Promise<AuditEvent> {
    const list = this.byClient.get(input.clientId) ?? [];
    const prevHash = list.length > 0 ? (list[list.length - 1] as AuditEvent).hash : "";
    const sequence = list.length + 1;
    const withoutHash = {
      id: this.idgen("audit"),
      clientId: input.clientId,
      sequence,
      ...(input.scanId ? { scanId: input.scanId } : {}),
      actor: input.actor,
      action: input.action,
      ...(input.targetType ? { targetType: input.targetType } : {}),
      ...(input.targetId ? { targetId: input.targetId } : {}),
      summary: input.summary,
      metadata: input.metadata ?? {},
      prevHash,
      at: this.clock.now().toISOString(),
    };
    const hash = computeAuditHash(prevHash, withoutHash);
    const event = AuditEventSchema.parse({ ...withoutHash, hash });
    list.push(event);
    this.byClient.set(input.clientId, list);
    return event;
  }

  async list(clientId: string, opts?: AuditListOptions): Promise<AuditEvent[]> {
    let list = [...(this.byClient.get(clientId) ?? [])];
    if (opts?.scanId) list = list.filter((e) => e.scanId === opts.scanId);
    if (opts?.fromSequence !== undefined) {
      list = list.filter((e) => e.sequence >= (opts.fromSequence as number));
    }
    if (opts?.limit !== undefined) list = list.slice(0, opts.limit);
    return list;
  }

  async verifyChain(clientId: string): Promise<boolean> {
    let prev = "";
    for (const e of this.byClient.get(clientId) ?? []) {
      if (e.prevHash !== prev) return false;
      const { hash, ...rest } = e;
      if (computeAuditHash(prev, rest) !== hash) return false;
      prev = hash;
    }
    return true;
  }
}

export interface InMemoryApiStoreOptions {
  clock?: Clock;
  idgen?: IdGen;
}

/** Fully in-memory ApiStore for local dev and unit tests. */
export function createInMemoryApiStore(opts: InMemoryApiStoreOptions = {}): ApiStore {
  const clock: Clock = opts.clock ?? { now: () => new Date() };
  const idgen: IdGen = opts.idgen ?? ((prefix = "id") => `${prefix}_${crypto.randomUUID()}`);
  return {
    users: new InMemoryUserStore(),
    scans: new InMemoryScanRepo(),
    appMaps: new InMemoryAppMapRepo(),
    pullRequests: new InMemoryPullRequestRepo(),
    confirmed: new InMemoryFindingRepo<ConfirmedFinding>(),
    unconfirmed: new InMemoryFindingRepo<UnconfirmedFinding>(),
    reports: new InMemoryReportStore(),
    dastTargets: new InMemoryDastTargetStore(),
    audit: new InMemoryAuditLogClient(clock, idgen),
    customRules: new InMemoryCrudStore<CustomRule>(),
    redTeamScenarios: new InMemoryCrudStore<RedTeamScenario>(),
    scanSchedules: new InMemoryCrudStore<ScanSchedule>(),
    posture: new InMemoryPostureStore(),
    learnedFacts: new InMemoryLearnedFactStore(),
    // A5 — both `DetectionRule` and `DetectionCoverage` already have
    // `id`/`clientId`/`createdAt`, so the same generic CRUD fake used for
    // customRules/redTeamScenarios/scanSchedules above applies unchanged.
    detectionRules: new InMemoryCrudStore<DetectionRule>(),
    detectionCoverage: new InMemoryCrudStore<DetectionCoverage>(),
    detectionRulePushTargets: new InMemoryDetectionRulePushTargetStore(),
  };
}

/**
 * Compose a production ApiStore from the shared StateStore (scans/findings/audit)
 * plus the API-owned stores for users/DAST targets (Prisma-direct) and reports
 * (adapted from the real @montr/state-store `ReportRepository`). Called from
 * production-deps.ts's real production bootstrap, not just at test integration.
 */
export function apiStoreFromStateStore(
  state: StateStoreLike,
  extras: { users: UserStore; reports: ReportStore; dastTargets: DastTargetStore },
): ApiStore {
  return {
    users: extras.users,
    scans: state.scans,
    appMaps: state.appMaps,
    pullRequests: state.pullRequests,
    confirmed: state.confirmed,
    unconfirmed: state.unconfirmed,
    reports: extras.reports,
    dastTargets: extras.dastTargets,
    audit: state.audit,
    // Phase-4 (Wave 5) — sourced from the shared StateStore.
    customRules: state.customRules,
    redTeamScenarios: state.redTeamScenarios,
    scanSchedules: state.scanSchedules,
    posture: state.posture,
    learnedFacts: state.learnedFacts,
    // A5 — sourced from the shared StateStore's real, persisted (A7) repos.
    detectionRules: state.detectionRules,
    detectionCoverage: state.detectionCoverage,
    // Suggested enhancement — real, encrypted push-target config/credential.
    detectionRulePushTargets: state.detectionRulePushTargets,
  };
}

export type { UserRecord };
