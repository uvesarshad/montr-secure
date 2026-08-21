/**
 * Repository interfaces (§8.3). EVERY method is scoped by `clientId` — per-client
 * data is never shared (row-scoped multitenancy enforced at this layer). The
 * shapes crossing these boundaries are the frozen @montr/contracts types.
 */
import type {
  AppMap,
  CandidateFinding,
  Category,
  ConfirmedFinding,
  CustomRule,
  Fix,
  KeyTier,
  LayerId,
  PostureSnapshot,
  ProbableFinding,
  Provider,
  PullRequest,
  RedTeamScenario,
  Report,
  ResumeToken,
  Scan,
  ScanSchedule,
  ScanStatus,
  UnconfirmedFinding,
} from "@montr/contracts";
import type { AuditLogClient } from "@montr/telemetry";
import type { ChainVerification } from "./hash-chain.js";
import type { RetentionEnforcer } from "./retention.js";

/**
 * The store's audit surface: the frozen {@link AuditLogClient} contract plus the
 * tamper-check + export helpers auditors need (§13, §14).
 */
export interface AuditLog extends AuditLogClient {
  verifyChainDetailed(clientId: string): Promise<ChainVerification>;
  exportJson(clientId: string): Promise<string>;
  exportCsv(clientId: string): Promise<string>;
}

/** Common repository shape — all reads/writes are scoped by clientId. */
export interface Repository<T> {
  create(clientId: string, entity: T): Promise<T>;
  get(clientId: string, id: string): Promise<T | null>;
  list(clientId: string, filter?: Record<string, unknown>): Promise<T[]>;
}

export interface ScanRepository extends Repository<Scan> {
  update(clientId: string, scan: Scan): Promise<Scan>;
  /**
   * Scans currently in `status` (most recently started first). Backs apps/worker's
   * boot-time reconciliation (A3, §8.1): a worker crash mid-layer parks a scan as
   * `running` forever unless something finds it and calls `resume()`.
   */
  listByStatus(clientId: string, status: ScanStatus): Promise<Scan[]>;
}

export interface AppMapRepository extends Repository<AppMap> {
  /** Persisted map for an exact repo/commit (DECIDE-2 stale check). */
  latestForCommit(clientId: string, repo: string, commitSha: string): Promise<AppMap | null>;
  /** Most-recent persisted map for a repo, any commit. */
  latestForRepo(clientId: string, repo: string): Promise<AppMap | null>;
  markStale(clientId: string, appMapId: string): Promise<void>;
  /**
   * DECIDE-2 stale-commit invalidation: mark stale every persisted map for
   * `repo` whose commit differs from `currentCommitSha`. Returns the count
   * invalidated. Never deletes — a stale map can still seed an incremental diff.
   */
  invalidateStaleForCommit(
    clientId: string,
    repo: string,
    currentCommitSha: string,
  ): Promise<number>;
}

export interface FindingRepository<T> extends Repository<T> {
  bulkCreate(clientId: string, findings: T[]): Promise<T[]>;
  listByScan(clientId: string, scanId: string): Promise<T[]>;
}

export interface FixRepository extends Repository<Fix> {
  update(clientId: string, fix: Fix): Promise<Fix>;
  listByScan(clientId: string, scanId: string): Promise<Fix[]>;
}

export interface PullRequestRepository extends Repository<PullRequest> {
  update(clientId: string, pr: PullRequest): Promise<PullRequest>;
  listByScan(clientId: string, scanId: string): Promise<PullRequest[]>;
}

export interface ReportRepository {
  upsert(clientId: string, report: Report): Promise<Report>;
  getByScan(clientId: string, scanId: string): Promise<Report | null>;
}

/** Per-layer state for diagnostics / resume detail. */
export interface ScanLayerState {
  scanId: string;
  layer: LayerId;
  status: ScanStatus;
  completedLayers: LayerId[];
  updatedAt: string;
}

/** Resumable pipeline state (§8.1): a failed Layer-3 must not re-run Layer 0–2. */
export interface ResumeRepository {
  save(clientId: string, token: ResumeToken): Promise<ResumeToken>;
  get(clientId: string, scanId: string): Promise<ResumeToken | null>;
  /** Mark a layer complete and advance the resume checkpoint atomically. */
  markLayerCompleted(
    clientId: string,
    scanId: string,
    layer: LayerId,
    checkpointRef?: string,
  ): Promise<ResumeToken>;
  /** Per-layer state rows for a scan. */
  listStates(clientId: string, scanId: string): Promise<ScanLayerState[]>;
}

/** BYO-key LLM credential (§11) — secrets are field-encrypted at rest. */
export interface LlmCredentialInput {
  provider: Provider;
  endpoint?: string;
  /** Plaintext on the way in; stored AES-256-GCM encrypted. */
  apiKey: string;
  /** Plaintext on the way in; stored encrypted. */
  refreshToken?: string;
  keyTier?: KeyTier | string;
}

/** A decrypted credential. The `apiKey` is plaintext — NEVER log this object. */
export interface LlmCredentialRecord {
  clientId: string;
  provider: Provider;
  endpoint?: string;
  apiKey: string;
  refreshToken?: string;
  keyTier: string;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialRepository {
  upsert(clientId: string, cred: LlmCredentialInput): Promise<LlmCredentialRecord>;
  /** Returns the DECRYPTED credential (secrets in plaintext) or null. */
  get(clientId: string): Promise<LlmCredentialRecord | null>;
  /** Metadata only (provider/endpoint/keyTier) — never touches the secret. */
  getMetadata(
    clientId: string,
  ): Promise<Pick<LlmCredentialRecord, "provider" | "endpoint" | "keyTier"> | null>;
  delete(clientId: string): Promise<void>;
}

/* --------------------------------------------------------------------------- *
 * Phase-4 (Wave 5) repositories — scale & intelligence (§16). Per-client scoped.
 * --------------------------------------------------------------------------- */

/** Client-authored custom detection rules (validated before enable). */
export interface CustomRuleRepository extends Repository<CustomRule> {
  update(clientId: string, rule: CustomRule): Promise<CustomRule>;
  delete(clientId: string, id: string): Promise<void>;
}

/**
 * Reusable, versioned red-team scenarios. ⛔ `steps` is encrypted at rest, so
 * these methods require a field cipher (like {@link CredentialRepository}).
 */
export interface RedTeamScenarioRepository extends Repository<RedTeamScenario> {
  update(clientId: string, scenario: RedTeamScenario): Promise<RedTeamScenario>;
  delete(clientId: string, id: string): Promise<void>;
}

/** Cron-scheduled scans (budget-ceiling + human-gate honoring). */
export interface ScanScheduleRepository extends Repository<ScanSchedule> {
  update(clientId: string, schedule: ScanSchedule): Promise<ScanSchedule>;
  delete(clientId: string, id: string): Promise<void>;
  /** Enabled schedules only (scheduler dispatch loop). */
  listEnabled(clientId: string): Promise<ScanSchedule[]>;
}

/** Posture-over-time snapshots (trend / regression intelligence). */
export interface PostureRepository {
  record(clientId: string, snapshot: PostureSnapshot): Promise<PostureSnapshot>;
  /** All snapshots for the client (chronological). */
  list(clientId: string): Promise<PostureSnapshot[]>;
  /** One repo's snapshots (chronological) — the trend series. */
  listByRepo(clientId: string, repo: string): Promise<PostureSnapshot[]>;
  latestForRepo(clientId: string, repo: string): Promise<PostureSnapshot | null>;
}

/* --------------------------------------------------------------------------- *
 * Versioned LLM prompt templates (§8.2, §15 regression-tuning loop).
 * --------------------------------------------------------------------------- */

/** Input to create a new (inactive) prompt version. */
export interface PromptVersionInput {
  /** The prompt's stable key, e.g. "correlation.system" or "fix.system". */
  name: string;
  template: string;
  layer?: LayerId;
  /** Per-client override/tuning candidate; omit for a global (shared) version. */
  clientId?: string | null;
}

/** A stored prompt version. */
export interface PromptVersionRecord {
  id: string;
  /** `null` for a global (shared) version. */
  clientId: string | null;
  name: string;
  version: number;
  layer: LayerId | null;
  template: string;
  isActive: boolean;
  createdAt: string;
}

/**
 * Versioned prompt templates. `clientId: null` denotes a global/shared
 * version; `version` is a monotonic counter per `name` across ALL clients
 * (see the schema doc comment). Not part of {@link Repository} because the
 * model can be intentionally cross-tenant (a global prompt has no owning
 * client) — every method takes its scope explicitly instead.
 */
export interface PromptVersionRepository {
  /** Create the next version for `name`, inactive until {@link markActive}. */
  createVersion(input: PromptVersionInput): Promise<PromptVersionRecord>;
  /**
   * Versions for `name`, newest first. When `clientId` is given, includes
   * that client's versions plus the global (`clientId: null`) versions.
   */
  listVersions(name: string, clientId?: string | null): Promise<PromptVersionRecord[]>;
  /**
   * The active version for `name`: a `clientId`-scoped active row wins over
   * the global active row; `null` when neither exists.
   */
  getActive(name: string, clientId?: string | null): Promise<PromptVersionRecord | null>;
  /** Promote `id` to active, deactivating any other active row in its scope. */
  markActive(id: string): Promise<PromptVersionRecord>;
}

/* --------------------------------------------------------------------------- *
 * §15 false-positive feedback tuning (A10). Prior operator false-positive
 * marks, sourced from the audit log's `finding.marked_false_positive` events
 * (apps/api/src/routes/findings.ts), so a future scan's correlation/
 * confirmation layers can down-rank a repeat of the same finding-shape.
 * Metadata-only shape — matches packages/correlation/src/tuning.ts's and
 * packages/confirm/src/tuning.ts's structurally-identical `FalsePositiveTuning`
 * seam so a single runtime object built from this repo satisfies both.
 * --------------------------------------------------------------------------- */

/** One prior FP mark's matchable shape — metadata only (golden rule #1). */
export interface FalsePositiveMarkSignal {
  category: Category;
  file: string;
  line: number;
  ruleId?: string;
}

export interface FalsePositiveMarkRepository {
  /** Every operator FP mark recorded for this client (any scan), newest first. */
  listByClient(clientId: string): Promise<FalsePositiveMarkSignal[]>;
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
  pullRequests: PullRequestRepository;
  reports: ReportRepository;
  resume: ResumeRepository;
  credentials: CredentialRepository;
  audit: AuditLog;
  retention: RetentionEnforcer;
  // Phase-4 (Wave 5) — scale & intelligence.
  customRules: CustomRuleRepository;
  redTeamScenarios: RedTeamScenarioRepository;
  scanSchedules: ScanScheduleRepository;
  posture: PostureRepository;
  /** Versioned LLM prompt templates (§8.2, §15 regression-tuning loop). */
  promptVersions: PromptVersionRepository;
  /** Prior operator FP marks for §15 tuning (A10). */
  falsePositiveMarks: FalsePositiveMarkRepository;
  disconnect(): Promise<void>;
}
