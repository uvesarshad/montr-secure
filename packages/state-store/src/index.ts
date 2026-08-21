/**
 * @montr/state-store — Prisma client wrapper, typed per-client repositories,
 * field-level encryption at rest, resumable pipeline state, per-client AppMap
 * persistence with stale-commit invalidation, and the append-only, hash-chained
 * (tamper-evident) audit log with JSON/CSV export + retention (§8.3, §8.5,
 * DECIDE-2).
 *
 * SAFETY INVARIANTS enforced here:
 *   - Per-client isolation: every query is scoped by `clientId` (row-scoped).
 *   - Encryption at rest: the LLM key + tokens are AES-256-GCM encrypted
 *     (golden rule #1), key sourced from Vault/KMS/k8s secret.
 *   - Tamper-evident audit: every mutation/approval/LLM call (metadata only) is
 *     recorded in a hash-chained log; `audit.verifyChain` detects any edit.
 */

// Crypto + hashing (real, deterministic — no DB needed).
export * from "./crypto.js";
export * from "./hash-chain.js";

// Prisma wrapper + JSON helpers.
export {
  createPrismaClient,
  toJson,
  fromJson,
  toJsonOrNull,
  Prisma,
  type MontrPrismaClient,
  type CreatePrismaClientOptions,
} from "./prisma.js";

// Repository interfaces + the aggregate StateStore contract.
export * from "./types.js";

// Repository implementations + factories.
export {
  RepositoryScopeError,
  ScanRepositoryImpl,
  AppMapRepositoryImpl,
  FixRepositoryImpl,
  PullRequestRepositoryImpl,
  ReportRepositoryImpl,
  ResumeRepositoryImpl,
  CredentialRepositoryImpl,
  FalsePositiveMarkRepositoryImpl,
  makeCandidateRepo,
  makeProbableRepo,
  makeConfirmedRepo,
  makeUnconfirmedRepo,
} from "./repositories.js";

// Phase-4 (Wave 5) repository implementations — scale & intelligence (§16).
export {
  CustomRuleRepositoryImpl,
  RedTeamScenarioRepositoryImpl,
  ScanScheduleRepositoryImpl,
  PostureRepositoryImpl,
} from "./phase4.js";

// OWASP-Top-10-mapped starter catalogue for the red-team scenario library
// (build-plan §8, item A27) — static templates + idempotent seed helper.
export {
  REDTEAM_SCENARIO_CATALOGUE,
  OWASP_TOP_10_2021,
  ALL_OWASP_TOP_10_2021_IDS,
  owaspCoverage,
  instantiateScenario,
  seedRedTeamCatalogue,
  type OwaspTop10Id,
  type RedTeamScenarioTemplate,
  type InstantiateScenarioParams,
  type SeedRedTeamCatalogueOptions,
  type SeedRedTeamCatalogueResult,
} from "./redteam-catalogue.js";

// Versioned LLM prompt templates (§8.2, §15 regression-tuning loop).
export { PromptVersionRepositoryImpl } from "./prompt-version.js";

// Cross-scan memory — durable per-repo learned facts (§15 loop, E8).
export { LearnedFactRepositoryImpl } from "./learned-facts.js";

// Blue-team / purple-team entities (B1) — DetectionRule, AttackPath,
// DetectionCoverage repository implementations. Data model + CRUD only; B2-B5
// build the generation/mapping/graph/verification logic on top.
export {
  DetectionRuleRepositoryImpl,
  AttackPathRepositoryImpl,
  DetectionCoverageRepositoryImpl,
  detectionRuleToCreate,
  detectionRuleFromRow,
  attackPathToCreate,
  attackPathFromRow,
  detectionCoverageToCreate,
  detectionCoverageFromRow,
} from "./blue-team.js";

// Semantic codebase index (E5) — pgvector-backed CodeChunk storage + query.
// Deliberately NOT part of the aggregate StateStore (see code-chunk.ts's doc
// comment); construct it directly with a Prisma client.
export {
  createCodeChunkRepository,
  PrismaCodeChunkRepository,
  CODE_CHUNK_EMBEDDING_DIM,
  type CodeChunkRepository,
  type CodeChunkInput,
  type CodeChunkRow,
  type CodeChunkMatch,
  type QuerySimilarOptions,
} from "./code-chunk.js";

// Audit log (Prisma-backed AuditLogClient) + export helpers.
export { PrismaAuditLogClient, exportAuditLog, type AuditExportFormat } from "./audit.js";

// Retention.
export { RetentionEnforcer, type RetentionPolicy, type RetentionResult } from "./retention.js";

// Mappers (useful for the integration agent / fixtures).
export * as mappers from "./mappers.js";

// Assembly.
export * from "./state-store.js";
