/**
 * Detection-rule push target repository (suggested enhancement, 2026-09-12
 * red/blue agentic-posture audit — see packages/report/src/detection-rules/push
 * for the adapter this config/credential feeds). Kept as its own file rather
 * than folded into repositories.ts's "LLM credential (encrypted)" section
 * because it is a genuinely separate secret with its own lifecycle (a SOC
 * push destination, not an LLM provider key) — but the implementation is a
 * DELIBERATE mirror of `CredentialRepositoryImpl` (repositories.ts): same
 * encrypt-on-write/decrypt-on-read shape, same `requireCipher` fail-fast, same
 * `clientId`-as-AAD binding, same metadata-only accessor for callers that
 * must never see the secret.
 */
import type { FieldCipher } from "./crypto.js";
import { toIso } from "./mappers.js";
import type { MontrPrismaClient } from "./prisma.js";
import type {
  DetectionRulePushTargetInput,
  DetectionRulePushTargetRecord,
  DetectionRulePushTargetRepository,
} from "./types.js";

export class DetectionRulePushTargetRepositoryImpl implements DetectionRulePushTargetRepository {
  constructor(
    private readonly prisma: MontrPrismaClient,
    private readonly cipher: FieldCipher | undefined,
  ) {}

  private requireCipher(): FieldCipher {
    if (!this.cipher) {
      throw new Error(
        "field-encryption key is required to read/write detection-rule push targets " +
          "(set security.fieldEncryptionKeyRef)",
      );
    }
    return this.cipher;
  }

  async upsert(
    clientId: string,
    target: DetectionRulePushTargetInput,
  ): Promise<DetectionRulePushTargetRecord> {
    const cipher = this.requireCipher();
    const hecToken = cipher.encrypt(target.hecToken, clientId);
    const row = await this.prisma.detectionRulePushTarget.upsert({
      where: { clientId },
      create: {
        clientId,
        type: target.type,
        endpointUrl: target.endpointUrl,
        hecToken,
        index: target.index ?? null,
        sourcetype: target.sourcetype ?? null,
      },
      update: {
        type: target.type,
        endpointUrl: target.endpointUrl,
        hecToken,
        index: target.index ?? null,
        sourcetype: target.sourcetype ?? null,
      },
    });
    return {
      clientId,
      type: row.type,
      endpointUrl: row.endpointUrl,
      hecToken: target.hecToken,
      index: row.index ?? undefined,
      sourcetype: row.sourcetype ?? undefined,
      createdAt: toIso(row.createdAt),
      updatedAt: toIso(row.updatedAt),
    };
  }

  async get(clientId: string): Promise<DetectionRulePushTargetRecord | null> {
    const cipher = this.requireCipher();
    const row = await this.prisma.detectionRulePushTarget.findFirst({ where: { clientId } });
    if (!row) return null;
    return {
      clientId,
      type: row.type,
      endpointUrl: row.endpointUrl,
      hecToken: cipher.decrypt(row.hecToken, clientId),
      index: row.index ?? undefined,
      sourcetype: row.sourcetype ?? undefined,
      createdAt: toIso(row.createdAt),
      updatedAt: toIso(row.updatedAt),
    };
  }

  async getMetadata(
    clientId: string,
  ): Promise<Omit<DetectionRulePushTargetRecord, "hecToken" | "clientId"> | null> {
    const row = await this.prisma.detectionRulePushTarget.findFirst({
      where: { clientId },
      select: {
        type: true,
        endpointUrl: true,
        index: true,
        sourcetype: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!row) return null;
    return {
      type: row.type,
      endpointUrl: row.endpointUrl,
      index: row.index ?? undefined,
      sourcetype: row.sourcetype ?? undefined,
      createdAt: toIso(row.createdAt),
      updatedAt: toIso(row.updatedAt),
    };
  }

  async delete(clientId: string): Promise<void> {
    await this.prisma.detectionRulePushTarget.deleteMany({ where: { clientId } });
  }
}
