/**
 * In-memory {@link PromptVersionSource} (E15 — eval-driven prompt
 * optimization). `@montr/state-store`'s `PromptVersionRepositoryImpl` is the
 * real, Postgres-backed implementation of this seam (`version: Int` counter
 * per `name`, `isActive` flag, `createVersion`/`listVersions`/`getActive`/
 * `markActive`) — this module ships the SAME (name, version, isActive) shape
 * held in a plain `Map`/array instead of a database, for two real uses:
 *
 *  1. An offline eval harness (`@montr/qa`'s `prompt-eval.ts`) that needs to
 *     register a candidate prompt VERSION, mark it active, run the golden
 *     corpus against it, then compare against the currently-active version —
 *     without a running Postgres instance and without ever touching the real
 *     store (a candidate under evaluation is by definition not yet real).
 *  2. Tests of `resolvePromptTemplate`/`resolvePromptVersionTemplate`/
 *     `MontrLlmGateway.resolvePrompt`/`resolvePromptVersion` that want a real
 *     multi-version source rather than a hand-rolled single-method stub.
 *
 * Structurally satisfies {@link PromptVersionSource} (`getActive` +
 * `listVersions`), so every consumer of that seam — `resolvePromptTemplate`,
 * `resolvePromptVersionTemplate`, and both `MontrLlmGateway` methods built on
 * them — works against an instance of this class exactly as it does against
 * the real repository. This is NOT wired into `createLlmGateway`'s default
 * production path (that stays `store.promptVersions`, the real repository);
 * a caller opts in explicitly by passing one as `promptSource`.
 */
import type { PromptVersionSource, PromptVersionSourceRecord } from "./prompts.js";

export interface InMemoryPromptVersionRow extends PromptVersionSourceRecord {
  id: string;
  name: string;
  /** `null` for a global (shared) version — mirrors the real repository's scoping. */
  clientId: string | null;
  version: number;
  isActive: boolean;
}

export interface CreatePromptVersionInput {
  name: string;
  template: string;
  /** Per-client override/tuning candidate; omit for a global (shared) version. */
  clientId?: string | null;
}

/**
 * A minimal, dependency-free, in-process versioned-prompt registry. Not
 * thread-safe across processes (it is a single `Map`) — that is exactly why
 * the real deployment path uses `@montr/state-store`'s Postgres-backed
 * repository instead; this class is for offline evaluation and tests only.
 */
export class InMemoryPromptVersionRegistry implements PromptVersionSource {
  private readonly rows: InMemoryPromptVersionRow[] = [];
  private nextId = 1;

  /**
   * Register the next version for `name`: `version` = `max(version WHERE
   * name) + 1` (starting at 1), mirroring
   * `PromptVersionRepositoryImpl.createVersion`. The new row starts INACTIVE
   * — callers promote it explicitly via {@link markActive} (create-then-
   * promote, same convention as the real repository's §15 tuning-loop shape).
   */
  createVersion(input: CreatePromptVersionInput): InMemoryPromptVersionRow {
    const clientId = input.clientId ?? null;
    const last = this.rows
      .filter((r) => r.name === input.name)
      .reduce((max, r) => Math.max(max, r.version), 0);
    const row: InMemoryPromptVersionRow = {
      id: `pv_${this.nextId++}`,
      name: input.name,
      template: input.template,
      clientId,
      version: last + 1,
      isActive: false,
    };
    this.rows.push(row);
    return row;
  }

  /**
   * Promote `id` to active, deactivating any other active row in the same
   * `(name, clientId)` scope first — mirrors
   * `PromptVersionRepositoryImpl.markActive`'s "at most one active row per
   * scope" invariant.
   */
  markActive(id: string): InMemoryPromptVersionRow {
    const target = this.rows.find((r) => r.id === id);
    if (!target) throw new Error(`promptVersion ${id} not found`);
    for (const r of this.rows) {
      if (r.name === target.name && r.clientId === target.clientId) r.isActive = false;
    }
    target.isActive = true;
    return target;
  }

  /** All versions for `name`, newest first (own scope's rows before global). */
  listVersions(name: string, clientId?: string | null): Promise<PromptVersionSourceRecord[]> {
    const scoped = clientId
      ? this.rows.filter((r) => r.name === name && (r.clientId === clientId || r.clientId === null))
      : this.rows.filter((r) => r.name === name && r.clientId === null);
    return Promise.resolve([...scoped].sort((a, b) => b.version - a.version));
  }

  /**
   * The active version for `name`: a `clientId`-scoped active row wins over
   * the global active row; `null` when neither exists — same resolution order
   * as the real repository's `getActive`.
   */
  getActive(name: string, clientId?: string | null): Promise<PromptVersionSourceRecord | null> {
    if (clientId) {
      const own = this.rows.find((r) => r.name === name && r.clientId === clientId && r.isActive);
      if (own) return Promise.resolve(own);
    }
    const global = this.rows.find((r) => r.name === name && r.clientId === null && r.isActive);
    return Promise.resolve(global ?? null);
  }
}
