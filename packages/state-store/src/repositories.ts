/**
 * Typed, per-client repositories (§8.3). Every read/write is scoped by
 * `clientId` (row-scoped multitenancy). Mutating operations that Prisma can only
 * key by primary id (`update`) are re-scoped with `updateMany({ where:{id,
 * clientId} })` so one client can never mutate another's row.
 */
import type {
  AppMap,
  CandidateFinding,
  ConfirmedFinding,
  Fix,
  LayerId,
  ProbableFinding,
  PullRequest,
  Report,
  ResumeToken,
  Scan,
  ScanStatus,
  UnconfirmedFinding,
} from "@montr/contracts";
import type { FieldCipher } from "./crypto.js";
import {
  appMapFromRows,
  appMapScalarsToCreate,
  candidateFromRow,
  candidateToCreate,
  confirmedFromRow,
  confirmedToCreate,
  fixFromRow,
  fixToCreate,
  fixToUpdate,
  probableFromRow,
  probableToCreate,
  pullRequestFromRow,
  pullRequestToCreate,
  reportFromRow,
  reportToCreate,
  resumeTokenFromState,
  routeToCreate,
  scanFromRow,
  scanToCreate,
  scanToUpdate,
  taintSinkToCreate,
  taintSourceToCreate,
  toIso,
  unconfirmedFromRow,
  unconfirmedToCreate,
} from "./mappers.js";
import { Prisma, fromJson, toJson, type MontrPrismaClient } from "./prisma.js";
import type {
  AppMapRepository,
  CredentialRepository,
  FindingRepository,
  FixRepository,
  LlmCredentialInput,
  LlmCredentialRecord,
  PullRequestRepository,
  ReportRepository,
  ResumeRepository,
  ScanLayerState,
  ScanRepository,
} from "./types.js";

/** Thrown when a scoped mutation targets a row that is missing or cross-client. */
export class RepositoryScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RepositoryScopeError";
  }
}

/* ============================== Scan ============================== */

export class ScanRepositoryImpl implements ScanRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, scan: Scan): Promise<Scan> {
    const row = await this.prisma.scan.create({ data: scanToCreate(clientId, scan) });
    return scanFromRow(row);
  }

  async get(clientId: string, id: string): Promise<Scan | null> {
    const row = await this.prisma.scan.findFirst({ where: { id, clientId } });
    return row ? scanFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<Scan[]> {
    const rows = await this.prisma.scan.findMany({
      where: { ...(filter as Prisma.ScanWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(scanFromRow);
  }

  async update(clientId: string, scan: Scan): Promise<Scan> {
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.scan.updateMany({
        where: { id: scan.id, clientId },
        data: scanToUpdate(scan),
      });
      if (res.count === 0) throw new RepositoryScopeError(`scan ${scan.id} not found for client`);
      const row = await tx.scan.findFirst({ where: { id: scan.id, clientId } });
      if (!row) throw new RepositoryScopeError(`scan ${scan.id} vanished after update`);
      return scanFromRow(row);
    });
  }
}

/* ============================== AppMap ============================== */

export class AppMapRepositoryImpl implements AppMapRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, appMap: AppMap): Promise<AppMap> {
    return this.prisma.$transaction(async (tx) => {
      await tx.appMap.create({ data: appMapScalarsToCreate(clientId, appMap) });
      if (appMap.routes.length > 0) {
        await tx.route.createMany({ data: appMap.routes.map((r) => routeToCreate(appMap.id, r)) });
      }
      if (appMap.taintSources.length > 0) {
        await tx.taintSource.createMany({
          data: appMap.taintSources.map((t) => taintSourceToCreate(appMap.id, t)),
        });
      }
      if (appMap.taintSinks.length > 0) {
        await tx.taintSink.createMany({
          data: appMap.taintSinks.map((t) => taintSinkToCreate(appMap.id, t)),
        });
      }
      const created = await this.assemble(tx, clientId, appMap.id);
      if (!created) throw new RepositoryScopeError(`appMap ${appMap.id} missing after create`);
      return created;
    });
  }

  async get(clientId: string, id: string): Promise<AppMap | null> {
    return this.assemble(this.prisma, clientId, id);
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<AppMap[]> {
    const rows = await this.prisma.appMap.findMany({
      where: { ...(filter as Prisma.AppMapWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    const out: AppMap[] = [];
    for (const row of rows) {
      const map = await this.assemble(this.prisma, clientId, row.id);
      if (map) out.push(map);
    }
    return out;
  }

  async latestForCommit(clientId: string, repo: string, commitSha: string): Promise<AppMap | null> {
    const row = await this.prisma.appMap.findFirst({
      where: { clientId, repo, commitSha },
      orderBy: { createdAt: "desc" },
    });
    return row ? this.assemble(this.prisma, clientId, row.id) : null;
  }

  async latestForRepo(clientId: string, repo: string): Promise<AppMap | null> {
    const row = await this.prisma.appMap.findFirst({
      where: { clientId, repo },
      orderBy: { createdAt: "desc" },
    });
    return row ? this.assemble(this.prisma, clientId, row.id) : null;
  }

  async markStale(clientId: string, appMapId: string): Promise<void> {
    const res = await this.prisma.appMap.updateMany({
      where: { id: appMapId, clientId },
      data: { stale: true },
    });
    if (res.count === 0) throw new RepositoryScopeError(`appMap ${appMapId} not found for client`);
  }

  async invalidateStaleForCommit(
    clientId: string,
    repo: string,
    currentCommitSha: string,
  ): Promise<number> {
    const res = await this.prisma.appMap.updateMany({
      where: { clientId, repo, commitSha: { not: currentCommitSha }, stale: false },
      data: { stale: true },
    });
    return res.count;
  }

  private async assemble(
    db: Pick<MontrPrismaClient, "appMap" | "route" | "taintSource" | "taintSink">,
    clientId: string,
    id: string,
  ): Promise<AppMap | null> {
    const row = await db.appMap.findFirst({ where: { id, clientId } });
    if (!row) return null;
    const [routes, sources, sinks] = await Promise.all([
      db.route.findMany({ where: { appMapId: id } }),
      db.taintSource.findMany({ where: { appMapId: id } }),
      db.taintSink.findMany({ where: { appMapId: id } }),
    ]);
    return appMapFromRows(row, routes, sources, sinks);
  }
}

/* ============================== Findings (generic) ============================== */

interface FindingDelegate<Row, Create> {
  create(args: { data: Create }): Promise<Row>;
  createMany(args: { data: Create[]; skipDuplicates?: boolean }): Promise<{ count: number }>;
  findFirst(args: { where: Record<string, unknown> }): Promise<Row | null>;
  findMany(args: {
    where: Record<string, unknown>;
    orderBy?: Record<string, unknown>;
  }): Promise<Row[]>;
}

class FindingRepo<
  TContract extends { id: string },
  Row,
  Create,
> implements FindingRepository<TContract> {
  constructor(
    private readonly delegate: FindingDelegate<Row, Create>,
    private readonly toCreate: (clientId: string, entity: TContract) => Create,
    private readonly fromRow: (row: Row) => TContract,
    private readonly baseWhere: Record<string, unknown> = {},
  ) {}

  async create(clientId: string, entity: TContract): Promise<TContract> {
    const row = await this.delegate.create({ data: this.toCreate(clientId, entity) });
    return this.fromRow(row);
  }

  async bulkCreate(clientId: string, findings: TContract[]): Promise<TContract[]> {
    if (findings.length === 0) return [];
    // The pipeline is resumable, so a retried Layer-2/3 job may re-persist the same
    // findings; skipDuplicates keeps bulkCreate idempotent (unique id) instead of
    // failing the whole scan. (Probable + unconfirmed share the probableFinding table.)
    await this.delegate.createMany({
      data: findings.map((f) => this.toCreate(clientId, f)),
      skipDuplicates: true,
    });
    return findings.map((f) => ({ ...f, clientId }) as TContract);
  }

  async get(clientId: string, id: string): Promise<TContract | null> {
    const row = await this.delegate.findFirst({ where: { ...this.baseWhere, id, clientId } });
    return row ? this.fromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<TContract[]> {
    const rows = await this.delegate.findMany({
      where: { ...this.baseWhere, ...(filter ?? {}), clientId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map((r) => this.fromRow(r));
  }

  async listByScan(clientId: string, scanId: string): Promise<TContract[]> {
    const rows = await this.delegate.findMany({
      where: { ...this.baseWhere, clientId, scanId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map((r) => this.fromRow(r));
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyDelegate = FindingDelegate<any, any>;

export function makeCandidateRepo(prisma: MontrPrismaClient): FindingRepository<CandidateFinding> {
  return new FindingRepo(
    prisma.candidateFinding as unknown as AnyDelegate,
    candidateToCreate,
    candidateFromRow,
  );
}

export function makeProbableRepo(prisma: MontrPrismaClient): FindingRepository<ProbableFinding> {
  return new FindingRepo(
    prisma.probableFinding as unknown as AnyDelegate,
    probableToCreate,
    probableFromRow,
    { status: "probable" },
  );
}

export function makeConfirmedRepo(prisma: MontrPrismaClient): FindingRepository<ConfirmedFinding> {
  return new FindingRepo(
    prisma.confirmedFinding as unknown as AnyDelegate,
    confirmedToCreate,
    confirmedFromRow,
  );
}

export function makeUnconfirmedRepo(
  prisma: MontrPrismaClient,
): FindingRepository<UnconfirmedFinding> {
  return new FindingRepo(
    prisma.probableFinding as unknown as AnyDelegate,
    unconfirmedToCreate,
    unconfirmedFromRow,
    { status: "unconfirmed" },
  );
}

/* ============================== Fix ============================== */

export class FixRepositoryImpl implements FixRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, fix: Fix): Promise<Fix> {
    const row = await this.prisma.fix.create({ data: fixToCreate(clientId, fix) });
    return fixFromRow(row);
  }

  async get(clientId: string, id: string): Promise<Fix | null> {
    const row = await this.prisma.fix.findFirst({ where: { id, clientId } });
    return row ? fixFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<Fix[]> {
    const rows = await this.prisma.fix.findMany({
      where: { ...(filter as Prisma.FixWhereInput | undefined), clientId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map(fixFromRow);
  }

  async listByScan(clientId: string, scanId: string): Promise<Fix[]> {
    const rows = await this.prisma.fix.findMany({
      where: { clientId, scanId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map(fixFromRow);
  }

  async update(clientId: string, fix: Fix): Promise<Fix> {
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.fix.updateMany({
        where: { id: fix.id, clientId },
        data: fixToUpdate(fix),
      });
      if (res.count === 0) throw new RepositoryScopeError(`fix ${fix.id} not found for client`);
      const row = await tx.fix.findFirst({ where: { id: fix.id, clientId } });
      if (!row) throw new RepositoryScopeError(`fix ${fix.id} vanished after update`);
      return fixFromRow(row);
    });
  }
}

/* ============================== PullRequest ============================== */

export class PullRequestRepositoryImpl implements PullRequestRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, pr: PullRequest): Promise<PullRequest> {
    const row = await this.prisma.pullRequest.create({ data: pullRequestToCreate(clientId, pr) });
    return pullRequestFromRow(row);
  }

  async get(clientId: string, id: string): Promise<PullRequest | null> {
    const row = await this.prisma.pullRequest.findFirst({ where: { id, clientId } });
    return row ? pullRequestFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<PullRequest[]> {
    const rows = await this.prisma.pullRequest.findMany({
      where: { ...(filter as Prisma.PullRequestWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(pullRequestFromRow);
  }

  async listByScan(clientId: string, scanId: string): Promise<PullRequest[]> {
    const rows = await this.prisma.pullRequest.findMany({
      where: { clientId, scanId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map(pullRequestFromRow);
  }

  async update(clientId: string, pr: PullRequest): Promise<PullRequest> {
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.pullRequest.updateMany({
        where: { id: pr.id, clientId },
        data: {
          url: pr.url ?? null,
          number: pr.number ?? null,
          title: pr.title,
          bodySummary: pr.bodySummary,
          fixIds: toJson(pr.fixIds),
          status: pr.status,
        },
      });
      if (res.count === 0) throw new RepositoryScopeError(`pr ${pr.id} not found for client`);
      const row = await tx.pullRequest.findFirst({ where: { id: pr.id, clientId } });
      if (!row) throw new RepositoryScopeError(`pr ${pr.id} vanished after update`);
      return pullRequestFromRow(row);
    });
  }
}

/* ============================== Report ============================== */

export class ReportRepositoryImpl implements ReportRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async upsert(clientId: string, report: Report): Promise<Report> {
    const create = reportToCreate(clientId, report);
    const row = await this.prisma.report.upsert({
      where: { scanId: report.scanId },
      create,
      update: { document: toJson(report), generatedAt: create.generatedAt },
    });
    return reportFromRow(row);
  }

  async getByScan(clientId: string, scanId: string): Promise<Report | null> {
    const row = await this.prisma.report.findFirst({ where: { scanId, clientId } });
    return row ? reportFromRow(row) : null;
  }
}

/* ============================== Resume / pipeline state ============================== */

export class ResumeRepositoryImpl implements ResumeRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async save(clientId: string, token: ResumeToken): Promise<ResumeToken> {
    const completed = token.completedLayers ?? [];
    const layer: LayerId = token.lastCompletedLayer ?? completed[completed.length - 1] ?? "layer0";
    const status: ScanStatus = completed.includes("layer5") ? "completed" : "running";
    const checkpoint = token.checkpointRef ? { checkpointRef: token.checkpointRef } : undefined;
    return this.prisma.$transaction(async (tx) => {
      const existing = await tx.scanState.findFirst({
        where: { clientId, scanId: token.scanId },
        orderBy: { updatedAt: "desc" },
      });
      if (existing) {
        await tx.scanState.updateMany({
          where: { id: existing.id, clientId },
          data: {
            layer,
            status,
            completedLayers: toJson(completed),
            checkpoint: checkpoint ? toJson(checkpoint) : Prisma.DbNull,
          },
        });
        const row = await tx.scanState.findFirst({ where: { id: existing.id, clientId } });
        if (!row) throw new RepositoryScopeError(`scanState vanished after update`);
        return resumeTokenFromState(row);
      }
      const row = await tx.scanState.create({
        data: {
          ...(token.id ? { id: token.id } : {}),
          clientId,
          scanId: token.scanId,
          layer,
          status,
          completedLayers: toJson(completed),
          checkpoint: checkpoint ? toJson(checkpoint) : Prisma.DbNull,
        },
      });
      return resumeTokenFromState(row);
    });
  }

  async get(clientId: string, scanId: string): Promise<ResumeToken | null> {
    const row = await this.prisma.scanState.findFirst({
      where: { clientId, scanId },
      orderBy: { updatedAt: "desc" },
    });
    return row ? resumeTokenFromState(row) : null;
  }

  async markLayerCompleted(
    clientId: string,
    scanId: string,
    layer: LayerId,
    checkpointRef?: string,
  ): Promise<ResumeToken> {
    const current = await this.get(clientId, scanId);
    const completed = current?.completedLayers ?? [];
    const merged = completed.includes(layer) ? completed : [...completed, layer];
    return this.save(clientId, {
      scanId,
      completedLayers: merged,
      lastCompletedLayer: layer,
      checkpointRef: checkpointRef ?? current?.checkpointRef,
      updatedAt: new Date().toISOString(),
    });
  }

  async listStates(clientId: string, scanId: string): Promise<ScanLayerState[]> {
    const rows = await this.prisma.scanState.findMany({
      where: { clientId, scanId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map((r) => ({
      scanId: r.scanId,
      layer: r.layer,
      status: r.status,
      completedLayers: fromJson<LayerId[]>(r.completedLayers),
      updatedAt: toIso(r.updatedAt),
    }));
  }
}

/* ============================== LLM credential (encrypted) ============================== */

export class CredentialRepositoryImpl implements CredentialRepository {
  constructor(
    private readonly prisma: MontrPrismaClient,
    private readonly cipher: FieldCipher | undefined,
  ) {}

  private requireCipher(): FieldCipher {
    if (!this.cipher) {
      throw new Error(
        "field-encryption key is required to read/write LLM credentials (set security.fieldEncryptionKeyRef)",
      );
    }
    return this.cipher;
  }

  async upsert(clientId: string, cred: LlmCredentialInput): Promise<LlmCredentialRecord> {
    const cipher = this.requireCipher();
    const apiKey = cipher.encrypt(cred.apiKey, clientId);
    const refreshToken = cred.refreshToken ? cipher.encrypt(cred.refreshToken, clientId) : null;
    const keyTier = cred.keyTier ?? "unknown";
    const row = await this.prisma.llmCredential.upsert({
      where: { clientId },
      create: {
        clientId,
        provider: cred.provider,
        endpoint: cred.endpoint ?? null,
        apiKey,
        refreshToken,
        keyTier,
      },
      update: {
        provider: cred.provider,
        endpoint: cred.endpoint ?? null,
        apiKey,
        refreshToken,
        keyTier,
      },
    });
    return {
      clientId,
      provider: row.provider,
      endpoint: row.endpoint ?? undefined,
      apiKey: cred.apiKey,
      refreshToken: cred.refreshToken,
      keyTier: row.keyTier,
      createdAt: toIso(row.createdAt),
      updatedAt: toIso(row.updatedAt),
    };
  }

  async get(clientId: string): Promise<LlmCredentialRecord | null> {
    const cipher = this.requireCipher();
    const row = await this.prisma.llmCredential.findFirst({ where: { clientId } });
    if (!row) return null;
    return {
      clientId,
      provider: row.provider,
      endpoint: row.endpoint ?? undefined,
      apiKey: cipher.decrypt(row.apiKey, clientId),
      refreshToken: row.refreshToken ? cipher.decrypt(row.refreshToken, clientId) : undefined,
      keyTier: row.keyTier,
      createdAt: toIso(row.createdAt),
      updatedAt: toIso(row.updatedAt),
    };
  }

  async getMetadata(
    clientId: string,
  ): Promise<Pick<LlmCredentialRecord, "provider" | "endpoint" | "keyTier"> | null> {
    const row = await this.prisma.llmCredential.findFirst({
      where: { clientId },
      select: { provider: true, endpoint: true, keyTier: true },
    });
    if (!row) return null;
    return { provider: row.provider, endpoint: row.endpoint ?? undefined, keyTier: row.keyTier };
  }

  async delete(clientId: string): Promise<void> {
    await this.prisma.llmCredential.deleteMany({ where: { clientId } });
  }
}
