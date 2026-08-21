/**
 * Blue-team / purple-team repositories (B1) — `DetectionRule`, `AttackPath`,
 * `DetectionCoverage`. Every method is scoped by `clientId` (row-scoped
 * multitenancy, §8.3), mirroring `phase4.ts`'s `CustomRuleRepositoryImpl`
 * exactly: scoped mutations use `updateMany({ where: { id, clientId } })` so
 * one client can never touch another's row, and a zero-count result throws
 * {@link RepositoryScopeError} rather than silently succeeding.
 *
 * DATA MODEL ONLY (B1): this file persists/retrieves the shapes B2 (ATT&CK
 * mapping), B3 (rule authoring), B4 (attack-path graph), and B5 (purple-team
 * verification) will populate — it contains no generation, mapping, or graph
 * logic of its own.
 *
 * ENCRYPTION: none of these rows carry a field-encrypted column — see
 * schema.prisma's "Blue-team / purple-team entities (B1)" section header and
 * docs/api/database.md for why `DetectionRule.content` et al. are plaintext.
 */
import type {
  AttackPath,
  DetectionCoverage,
  DetectionRule,
  DetectionStatus,
  DetectionVerificationResult,
  Severity,
} from "@montr/contracts";
import type {
  AttackPath as AttackPathRow,
  DetectionCoverage as DetectionCoverageRow,
  DetectionRule as DetectionRuleRow,
  DetectionStatus as DetectionStatusRow,
} from "@prisma/client";
import { toDate, toIso } from "./mappers.js";
import { Prisma, fromJson, toJson, toJsonOrNull, type MontrPrismaClient } from "./prisma.js";
import { RepositoryScopeError } from "./repositories.js";
import type {
  AttackPathRepository,
  DetectionCoverageRepository,
  DetectionRuleRepository,
} from "./types.js";

/* ============================== DetectionRule ============================== */

export function detectionRuleToCreate(
  clientId: string,
  r: DetectionRule,
): Prisma.DetectionRuleUncheckedCreateInput {
  return {
    id: r.id,
    clientId,
    scanId: r.scanId,
    findingId: r.findingId,
    format: r.format,
    content: r.content,
    mitreTechniques: toJson(r.mitreTechniques),
    provenance: r.provenance,
    createdAt: toDate(r.createdAt),
  };
}

export function detectionRuleFromRow(row: DetectionRuleRow): DetectionRule {
  return {
    id: row.id,
    clientId: row.clientId,
    scanId: row.scanId,
    findingId: row.findingId,
    format: row.format as DetectionRule["format"],
    content: row.content,
    mitreTechniques: fromJson<string[]>(row.mitreTechniques),
    provenance: row.provenance,
    createdAt: toIso(row.createdAt),
  };
}

export class DetectionRuleRepositoryImpl implements DetectionRuleRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, rule: DetectionRule): Promise<DetectionRule> {
    const row = await this.prisma.detectionRule.create({
      data: detectionRuleToCreate(clientId, rule),
    });
    return detectionRuleFromRow(row);
  }

  async get(clientId: string, id: string): Promise<DetectionRule | null> {
    const row = await this.prisma.detectionRule.findFirst({ where: { id, clientId } });
    return row ? detectionRuleFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<DetectionRule[]> {
    const rows = await this.prisma.detectionRule.findMany({
      where: { ...(filter as Prisma.DetectionRuleWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(detectionRuleFromRow);
  }

  async listByFinding(clientId: string, findingId: string): Promise<DetectionRule[]> {
    const rows = await this.prisma.detectionRule.findMany({
      where: { clientId, findingId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(detectionRuleFromRow);
  }
}

/* ============================== AttackPath ============================== */

export function attackPathToCreate(
  clientId: string,
  p: AttackPath,
): Prisma.AttackPathUncheckedCreateInput {
  return {
    id: p.id,
    clientId,
    scanId: p.scanId,
    steps: toJson(p.steps),
    feasibilityScore: p.feasibilityScore,
    severity: p.severity,
    narrative: p.narrative,
    createdAt: toDate(p.createdAt),
  };
}

export function attackPathFromRow(row: AttackPathRow): AttackPath {
  return {
    id: row.id,
    clientId: row.clientId,
    scanId: row.scanId,
    steps: fromJson<AttackPath["steps"]>(row.steps),
    feasibilityScore: row.feasibilityScore,
    severity: row.severity as Severity,
    narrative: row.narrative,
    createdAt: toIso(row.createdAt),
  };
}

export class AttackPathRepositoryImpl implements AttackPathRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, path: AttackPath): Promise<AttackPath> {
    const row = await this.prisma.attackPath.create({ data: attackPathToCreate(clientId, path) });
    return attackPathFromRow(row);
  }

  async get(clientId: string, id: string): Promise<AttackPath | null> {
    const row = await this.prisma.attackPath.findFirst({ where: { id, clientId } });
    return row ? attackPathFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<AttackPath[]> {
    const rows = await this.prisma.attackPath.findMany({
      where: { ...(filter as Prisma.AttackPathWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(attackPathFromRow);
  }
}

/* ============================== DetectionCoverage ============================== */

/** `detected: true | false | "unknown"` (contract) <-> the `DetectionStatus` Prisma enum. */
function detectedToRow(v: DetectionStatus): DetectionStatusRow {
  if (v === "unknown") return "unknown";
  return v ? "detected" : "not_detected";
}
function detectedFromRow(v: DetectionStatusRow): DetectionStatus {
  if (v === "unknown") return "unknown";
  return v === "detected";
}

export function detectionCoverageToCreate(
  clientId: string,
  c: DetectionCoverage,
): Prisma.DetectionCoverageUncheckedCreateInput {
  return {
    id: c.id,
    clientId,
    scanId: c.scanId,
    findingId: c.findingId,
    detected: detectedToRow(c.detected),
    reasoning: c.reasoning,
    detectionRuleId: c.detectionRuleId ?? null,
    verification: toJsonOrNull(c.verification),
    createdAt: toDate(c.createdAt),
  };
}

export function detectionCoverageFromRow(row: DetectionCoverageRow): DetectionCoverage {
  return {
    id: row.id,
    clientId: row.clientId,
    scanId: row.scanId,
    findingId: row.findingId,
    detected: detectedFromRow(row.detected),
    reasoning: row.reasoning,
    detectionRuleId: row.detectionRuleId ?? undefined,
    verification: row.verification
      ? fromJson<DetectionVerificationResult>(row.verification)
      : undefined,
    createdAt: toIso(row.createdAt),
  };
}

export class DetectionCoverageRepositoryImpl implements DetectionCoverageRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(clientId: string, coverage: DetectionCoverage): Promise<DetectionCoverage> {
    const row = await this.prisma.detectionCoverage.create({
      data: detectionCoverageToCreate(clientId, coverage),
    });
    return detectionCoverageFromRow(row);
  }

  async get(clientId: string, id: string): Promise<DetectionCoverage | null> {
    const row = await this.prisma.detectionCoverage.findFirst({ where: { id, clientId } });
    return row ? detectionCoverageFromRow(row) : null;
  }

  async list(clientId: string, filter?: Record<string, unknown>): Promise<DetectionCoverage[]> {
    const rows = await this.prisma.detectionCoverage.findMany({
      where: { ...(filter as Prisma.DetectionCoverageWhereInput | undefined), clientId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(detectionCoverageFromRow);
  }

  async listByFinding(clientId: string, findingId: string): Promise<DetectionCoverage[]> {
    const rows = await this.prisma.detectionCoverage.findMany({
      where: { clientId, findingId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map(detectionCoverageFromRow);
  }

  async updateVerification(
    clientId: string,
    id: string,
    verification: DetectionVerificationResult,
  ): Promise<DetectionCoverage> {
    return this.prisma.$transaction(async (tx) => {
      const res = await tx.detectionCoverage.updateMany({
        where: { id, clientId },
        data: { verification: toJson(verification) },
      });
      if (res.count === 0)
        throw new RepositoryScopeError(`detectionCoverage ${id} not found for client`);
      const row = await tx.detectionCoverage.findFirst({ where: { id, clientId } });
      if (!row) throw new RepositoryScopeError(`detectionCoverage ${id} vanished after update`);
      return detectionCoverageFromRow(row);
    });
  }
}
