/**
 * State-store assembly (§8.3). Wires the Prisma client, the field cipher, every
 * per-client repository, the hash-chained audit log, and the retention enforcer
 * into a single {@link StateStore}.
 *
 * Two constructors:
 *   - {@link createStateStore}      — owns a PrismaClient it creates + disconnects.
 *   - {@link createStateStoreFromClient} — injects a client (tests use an
 *     in-memory fake; the integration agent can share one client across stores).
 */
import { PrismaAuditLogClient } from "./audit.js";
import { createFieldCipher, type FieldCipher } from "./crypto.js";
import { createPrismaClient, type MontrPrismaClient } from "./prisma.js";
import {
  AppMapRepositoryImpl,
  CredentialRepositoryImpl,
  FixRepositoryImpl,
  PullRequestRepositoryImpl,
  ReportRepositoryImpl,
  ResumeRepositoryImpl,
  ScanRepositoryImpl,
  makeCandidateRepo,
  makeConfirmedRepo,
  makeProbableRepo,
  makeUnconfirmedRepo,
} from "./repositories.js";
import {
  CustomRuleRepositoryImpl,
  PostureRepositoryImpl,
  RedTeamScenarioRepositoryImpl,
  ScanScheduleRepositoryImpl,
} from "./phase4.js";
import { PromptVersionRepositoryImpl } from "./prompt-version.js";
import { RetentionEnforcer } from "./retention.js";
import type { StateStore } from "./types.js";

export interface CreateStateStoreOptions {
  /** Postgres connection string (DATABASE_URL). */
  databaseUrl: string;
  /**
   * AES-256-GCM field-encryption key material (base64/hex 32-byte, or a
   * passphrase). Sourced from Vault/KMS/k8s secret — never a committed file.
   * Required to read/write LLM credentials; other repos work without it.
   */
  fieldEncryptionKey?: string;
  logQueries?: boolean;
}

export interface FromClientOptions {
  fieldEncryptionKey?: string;
  /** Provide a pre-built cipher (e.g. a KMS-backed one) instead of raw key material. */
  cipher?: FieldCipher;
  /** If true, `disconnect()` will disconnect the injected client (default false). */
  ownsClient?: boolean;
}

function buildStateStore(
  prisma: MontrPrismaClient,
  cipher: FieldCipher | undefined,
  ownsClient: boolean,
): StateStore {
  return {
    scans: new ScanRepositoryImpl(prisma),
    appMaps: new AppMapRepositoryImpl(prisma),
    candidates: makeCandidateRepo(prisma),
    probable: makeProbableRepo(prisma),
    confirmed: makeConfirmedRepo(prisma),
    unconfirmed: makeUnconfirmedRepo(prisma),
    fixes: new FixRepositoryImpl(prisma),
    pullRequests: new PullRequestRepositoryImpl(prisma),
    reports: new ReportRepositoryImpl(prisma),
    resume: new ResumeRepositoryImpl(prisma),
    credentials: new CredentialRepositoryImpl(prisma, cipher),
    audit: new PrismaAuditLogClient(prisma),
    retention: new RetentionEnforcer(prisma),
    // Phase-4 (Wave 5) — scale & intelligence. Scenario steps are encrypted at
    // rest, so the scenario repo takes the same field cipher as credentials.
    customRules: new CustomRuleRepositoryImpl(prisma),
    redTeamScenarios: new RedTeamScenarioRepositoryImpl(prisma, cipher),
    scanSchedules: new ScanScheduleRepositoryImpl(prisma),
    posture: new PostureRepositoryImpl(prisma),
    // Versioned LLM prompt templates (§8.2, §15 regression-tuning loop).
    promptVersions: new PromptVersionRepositoryImpl(prisma),
    disconnect: async () => {
      if (ownsClient) await prisma.$disconnect();
    },
  };
}

/** Create a store that owns its PrismaClient. */
export function createStateStore(opts: CreateStateStoreOptions): StateStore {
  const prisma = createPrismaClient({
    databaseUrl: opts.databaseUrl,
    logQueries: opts.logQueries ?? false,
  });
  const cipher = opts.fieldEncryptionKey ? createFieldCipher(opts.fieldEncryptionKey) : undefined;
  return buildStateStore(prisma, cipher, true);
}

/** Create a store around an injected client (dependency-injection / tests). */
export function createStateStoreFromClient(
  prisma: MontrPrismaClient,
  opts: FromClientOptions = {},
): StateStore {
  const cipher =
    opts.cipher ??
    (opts.fieldEncryptionKey ? createFieldCipher(opts.fieldEncryptionKey) : undefined);
  return buildStateStore(prisma, cipher, opts.ownsClient ?? false);
}
