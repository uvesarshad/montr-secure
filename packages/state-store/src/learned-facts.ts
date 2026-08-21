/**
 * Cross-scan memory (E8, §15). Generalizes A10's false-positive tuning loop
 * (`FalsePositiveMarkRepository`, sourced from the audit log) to a broader
 * class of durable, per-`(clientId, repo)` learned facts: custom sanitizer
 * names, framework idioms, and explicit operator decisions. These are recorded
 * once and read back on EVERY later scan of the same repo so Layer 1/2/3 LLM
 * prompts can be given real accumulated context instead of starting cold every
 * time — closing the PRD §15 feedback loop A10 showed was dead code, for this
 * broader fact class.
 *
 * `confirmed_false_positive` facts are deliberately NOT persisted on this
 * table — see `LearnedFactType`'s doc comment in ./types.ts. They already live
 * in the audit log's `finding.marked_false_positive` events and are merged in
 * at READ time by the caller (apps/worker/src/runners.ts's
 * `loadLearnedFactsContext`, alongside this repository's `listByRepo`), so a
 * single mutation never has two authoritative homes.
 *
 * Row-scoping: every method takes `clientId` explicitly and the Prisma query
 * always filters on it (plus `repo` for reads) — matches this package's
 * row-scoped multitenancy discipline (see repositories.ts's file header).
 */
import { toIso } from "./mappers.js";
import { toJson, fromJson, type MontrPrismaClient } from "./prisma.js";
import type {
  LearnedFact,
  LearnedFactInput,
  LearnedFactProvenance,
  LearnedFactRepository,
  LearnedFactType,
} from "./types.js";

/** Read-side default cap — generous; the prompt-context cap that actually
 * bounds token spend is applied by the caller (apps/worker/src/runners.ts). */
const DEFAULT_LIST_LIMIT = 25;

interface LearnedFactRow {
  id: string;
  clientId: string;
  repo: string;
  type: string;
  content: unknown;
  provenance: unknown;
  createdAt: Date;
}

function fromRow(row: LearnedFactRow): LearnedFact {
  return {
    id: row.id,
    clientId: row.clientId,
    repo: row.repo,
    type: row.type as LearnedFactType,
    content: fromJson<Record<string, unknown>>(row.content) ?? {},
    provenance: fromJson<LearnedFactProvenance>(row.provenance),
    createdAt: toIso(row.createdAt),
  };
}

export class LearnedFactRepositoryImpl implements LearnedFactRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async record(input: LearnedFactInput): Promise<LearnedFact> {
    const row = await this.prisma.learnedFact.create({
      data: {
        clientId: input.clientId,
        repo: input.repo,
        type: input.type,
        content: toJson(input.content),
        provenance: toJson(input.provenance),
      },
    });
    return fromRow(row as LearnedFactRow);
  }

  async listByRepo(
    clientId: string,
    repo: string,
    limit: number = DEFAULT_LIST_LIMIT,
  ): Promise<LearnedFact[]> {
    const rows = await this.prisma.learnedFact.findMany({
      where: { clientId, repo },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return rows.map((r) => fromRow(r as LearnedFactRow));
  }
}
