/**
 * Phase-4 (Wave 5) repositories — custom rules, red-team scenarios, scan
 * schedules, posture snapshots (build-plan §8, PRD §16).
 *
 * Every method is scoped by `clientId` (row-scoped multitenancy, §8.3) exactly
 * like the core repos; scoped mutations use `updateMany/deleteMany({ where:{ id,
 * clientId } })` so one client can never touch another's row.
 *
 * ⛔ ENCRYPTION AT REST (§11, golden rule #1): a red-team scenario's `steps` is
 *    an attack playbook bound to a client's live target — sensitive. It is stored
 *    AES-256-GCM encrypted (same {@link FieldCipher} used for the LLM key), with
 *    `clientId` as additional-authenticated-data. The scenario repo therefore
 *    requires a cipher (mirrors {@link CredentialRepositoryImpl}); custom rules,
 *    schedules and posture carry no secrets and need none.
 */
import type {
  CustomRule,
  Language,
  PostureDelta,
  PostureSnapshot,
  RedTeamCategory,
  RedTeamScenario,
  RedTeamStep,
  ScanSchedule,
  SeverityCounts,
} from "@montr/contracts";
import type {
  CustomRule as CustomRuleRow,
  PostureSnapshot as PostureSnapshotRow,
  RedTeamScenario as RedTeamScenarioRow,
  ScanSchedule as ScanScheduleRow,
} from "@prisma/client";
import type { FieldCipher } from "./crypto.js";
import { toDate, toDateOpt, toIso, toIsoOpt } from "./mappers.js";
import { Prisma, fromJson, toJson, toJsonOrNull, type MontrPrismaClient } from "./prisma.js";
import { RepositoryScopeError } from "./repositories.js";
import type {
  CustomRuleRepository,
  PostureRepository,
  RedTeamScenarioRepository,
  ScanScheduleRepository,
} from "./types.js";

/* ============================== CustomRule ============================== */

export function customRuleToCreate(
  clientId: string,
  r: CustomRule,
): Prisma.CustomRuleUncheckedCreateInput {
  return {
    id: r.id,
    clientId,
    name: r.name,
    language: r.language,
    engine: r.engine,
    body: r.body,
    version: r.version,
    enabled: r.enabled,
    createdBy: r.createdBy,
    createdAt: toDate(r.createdAt),
  };
}

export function customRuleFromRow(row: CustomRuleRow): CustomRule {
  return {
    id: row.id,
    clientId: row.clientId,
    name: row.name,
    language: row.language as Language,
    engine: row.engine,
    body: row.body,
    version: row.version,
    enabled: row.enabled,
    createdBy: row.createdBy,
    createdAt: toIso(row.createdAt),
  };
}

export class CustomRuleRepositoryImpl implements CustomRuleRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, rule: CustomRule): Promise<CustomRule> {
    const row = await this.prisma.customRule.create({ data: customRuleToCreate(clientId, rule) });
    return customRuleFromRow(row);
  }

  async get(clientId: string, id: string): Promise<CustomRule | null> {
    const row = await this.prisma.customRule.findFirst({ where: { id, clientId } });
    return row ? customRuleFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<CustomRule[]> {
    const rows = await this.prisma.customRule.findMany({
      where: { ...(filter as Prisma.CustomRuleWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(customRuleFromRow);
  }

  async update(clientId: string, rule: CustomRule): Promise<CustomRule> {
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.customRule.updateMany({
        where: { id: rule.id, clientId },
        data: {
          name: rule.name,
          language: rule.language,
          engine: rule.engine,
          body: rule.body,
          version: rule.version,
          enabled: rule.enabled,
        },
      });
      if (res.count === 0)
        throw new RepositoryScopeError(`customRule ${rule.id} not found for client`);
      const row = await tx.customRule.findFirst({ where: { id: rule.id, clientId } });
      if (!row) throw new RepositoryScopeError(`customRule ${rule.id} vanished after update`);
      return customRuleFromRow(row);
    });
  }

  async delete(clientId: string, id: string): Promise<void> {
    const res = await this.prisma.customRule.deleteMany({ where: { id, clientId } });
    if (res.count === 0) throw new RepositoryScopeError(`customRule ${id} not found for client`);
  }
}

/* ============================ RedTeamScenario ============================ */
/* ⛔ `steps` is encrypted at rest (attack playbook) — cipher required.        */

export class RedTeamScenarioRepositoryImpl implements RedTeamScenarioRepository {
  constructor(
    private readonly prisma: MontrPrismaClient,
    private readonly cipher: FieldCipher | undefined,
  ) {}

  private requireCipher(): FieldCipher {
    if (!this.cipher) {
      throw new Error(
        "field-encryption key is required to read/write red-team scenarios (set security.fieldEncryptionKeyRef)",
      );
    }
    return this.cipher;
  }

  private toCreate(
    clientId: string,
    s: RedTeamScenario,
  ): Prisma.RedTeamScenarioUncheckedCreateInput {
    const cipher = this.requireCipher();
    return {
      id: s.id,
      clientId,
      name: s.name,
      category: s.category,
      steps: cipher.encrypt(JSON.stringify(s.steps), clientId),
      targetAllowlistRef: s.targetAllowlistRef,
      version: s.version,
      enabled: s.enabled,
      createdBy: s.createdBy,
      createdAt: toDate(s.createdAt),
    };
  }

  private fromRow(row: RedTeamScenarioRow): RedTeamScenario {
    const cipher = this.requireCipher();
    return {
      id: row.id,
      clientId: row.clientId,
      name: row.name,
      category: row.category as RedTeamCategory,
      steps: JSON.parse(cipher.decrypt(row.steps, row.clientId)) as RedTeamStep[],
      targetAllowlistRef: row.targetAllowlistRef,
      version: row.version,
      enabled: row.enabled,
      createdBy: row.createdBy,
      createdAt: toIso(row.createdAt),
    };
  }

  async create(clientId: string, scenario: RedTeamScenario): Promise<RedTeamScenario> {
    const row = await this.prisma.redTeamScenario.create({
      data: this.toCreate(clientId, scenario),
    });
    return this.fromRow(row);
  }

  async get(clientId: string, id: string): Promise<RedTeamScenario | null> {
    const row = await this.prisma.redTeamScenario.findFirst({ where: { id, clientId } });
    return row ? this.fromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<RedTeamScenario[]> {
    const rows = await this.prisma.redTeamScenario.findMany({
      where: { ...(filter as Prisma.RedTeamScenarioWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map((r) => this.fromRow(r));
  }

  async update(clientId: string, scenario: RedTeamScenario): Promise<RedTeamScenario> {
    const cipher = this.requireCipher();
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.redTeamScenario.updateMany({
        where: { id: scenario.id, clientId },
        data: {
          name: scenario.name,
          category: scenario.category,
          steps: cipher.encrypt(JSON.stringify(scenario.steps), clientId),
          targetAllowlistRef: scenario.targetAllowlistRef,
          version: scenario.version,
          enabled: scenario.enabled,
        },
      });
      if (res.count === 0) {
        throw new RepositoryScopeError(`redTeamScenario ${scenario.id} not found for client`);
      }
      const row = await tx.redTeamScenario.findFirst({ where: { id: scenario.id, clientId } });
      if (!row)
        throw new RepositoryScopeError(`redTeamScenario ${scenario.id} vanished after update`);
      return this.fromRow(row);
    });
  }

  async delete(clientId: string, id: string): Promise<void> {
    const res = await this.prisma.redTeamScenario.deleteMany({ where: { id, clientId } });
    if (res.count === 0)
      throw new RepositoryScopeError(`redTeamScenario ${id} not found for client`);
  }
}

/* ============================== ScanSchedule ============================== */

export function scanScheduleToCreate(
  clientId: string,
  s: ScanSchedule,
): Prisma.ScanScheduleUncheckedCreateInput {
  return {
    id: s.id,
    clientId,
    repo: s.repo,
    mode: s.mode,
    cron: s.cron,
    budgetCeiling: s.budgetCeiling,
    enabled: s.enabled,
    nextRunAt: toDateOpt(s.nextRunAt) ?? null,
    createdBy: s.createdBy,
    createdAt: toDate(s.createdAt),
  };
}

export function scanScheduleFromRow(row: ScanScheduleRow): ScanSchedule {
  return {
    id: row.id,
    clientId: row.clientId,
    repo: row.repo,
    mode: row.mode,
    cron: row.cron,
    budgetCeiling: row.budgetCeiling,
    enabled: row.enabled,
    nextRunAt: toIsoOpt(row.nextRunAt),
    createdBy: row.createdBy,
    createdAt: toIso(row.createdAt),
  };
}

export class ScanScheduleRepositoryImpl implements ScanScheduleRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, schedule: ScanSchedule): Promise<ScanSchedule> {
    const row = await this.prisma.scanSchedule.create({
      data: scanScheduleToCreate(clientId, schedule),
    });
    return scanScheduleFromRow(row);
  }

  async get(clientId: string, id: string): Promise<ScanSchedule | null> {
    const row = await this.prisma.scanSchedule.findFirst({ where: { id, clientId } });
    return row ? scanScheduleFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<ScanSchedule[]> {
    const rows = await this.prisma.scanSchedule.findMany({
      where: { ...(filter as Prisma.ScanScheduleWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(scanScheduleFromRow);
  }

  /** Enabled schedules (the scheduler dispatch loop reads these). */
  async listEnabled(clientId: string): Promise<ScanSchedule[]> {
    return this.list(clientId, { enabled: true });
  }

  async update(clientId: string, schedule: ScanSchedule): Promise<ScanSchedule> {
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.scanSchedule.updateMany({
        where: { id: schedule.id, clientId },
        data: {
          repo: schedule.repo,
          mode: schedule.mode,
          cron: schedule.cron,
          budgetCeiling: schedule.budgetCeiling,
          enabled: schedule.enabled,
          nextRunAt: toDateOpt(schedule.nextRunAt) ?? null,
        },
      });
      if (res.count === 0) {
        throw new RepositoryScopeError(`scanSchedule ${schedule.id} not found for client`);
      }
      const row = await tx.scanSchedule.findFirst({ where: { id: schedule.id, clientId } });
      if (!row) throw new RepositoryScopeError(`scanSchedule ${schedule.id} vanished after update`);
      return scanScheduleFromRow(row);
    });
  }

  async delete(clientId: string, id: string): Promise<void> {
    const res = await this.prisma.scanSchedule.deleteMany({ where: { id, clientId } });
    if (res.count === 0) throw new RepositoryScopeError(`scanSchedule ${id} not found for client`);
  }
}

/* ============================= PostureSnapshot ============================= */

export function postureSnapshotToCreate(
  clientId: string,
  s: PostureSnapshot,
): Prisma.PostureSnapshotUncheckedCreateInput {
  return {
    id: s.id,
    clientId,
    scanId: s.scanId,
    repo: s.repo,
    at: toDate(s.at),
    confirmedBySeverity: toJson(s.confirmedBySeverity),
    total: s.total,
    delta: toJsonOrNull(s.delta),
  };
}

export function postureSnapshotFromRow(row: PostureSnapshotRow): PostureSnapshot {
  return {
    id: row.id,
    clientId: row.clientId,
    scanId: row.scanId,
    repo: row.repo,
    at: toIso(row.at),
    confirmedBySeverity: fromJson<SeverityCounts>(row.confirmedBySeverity),
    total: row.total,
    ...(row.delta != null ? { delta: fromJson<PostureDelta>(row.delta) } : {}),
  };
}

export class PostureRepositoryImpl implements PostureRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async record(clientId: string, snapshot: PostureSnapshot): Promise<PostureSnapshot> {
    const row = await this.prisma.postureSnapshot.create({
      data: postureSnapshotToCreate(clientId, snapshot),
    });
    return postureSnapshotFromRow(row);
  }

  async list(clientId: string): Promise<PostureSnapshot[]> {
    const rows = await this.prisma.postureSnapshot.findMany({
      where: { clientId },
      orderBy: { at: "asc" },
    });
    return rows.map(postureSnapshotFromRow);
  }

  /** A repo's posture time-series in chronological order (trend dashboard). */
  async listByRepo(clientId: string, repo: string): Promise<PostureSnapshot[]> {
    const rows = await this.prisma.postureSnapshot.findMany({
      where: { clientId, repo },
      orderBy: { at: "asc" },
    });
    return rows.map(postureSnapshotFromRow);
  }

  async latestForRepo(clientId: string, repo: string): Promise<PostureSnapshot | null> {
    const row = await this.prisma.postureSnapshot.findFirst({
      where: { clientId, repo },
      orderBy: { at: "desc" },
    });
    return row ? postureSnapshotFromRow(row) : null;
  }
}
