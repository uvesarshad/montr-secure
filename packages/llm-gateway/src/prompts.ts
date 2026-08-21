/**
 * Versioned-prompt resolution (§8.2, §15 regression-tuning loop).
 *
 * `PromptVersion` (@montr/state-store) used to be dead schema: nothing wrote
 * it, nothing read it, and every caller of this gateway hardcodes its prompt
 * template as a source constant (e.g. `FIX_SYSTEM_PROMPT` in
 * `packages/fix/src/generate.ts`, `TRIAGE_SYSTEM` in
 * `packages/discovery/src/triage.ts`). This module gives those hardcoded
 * strings somewhere to hand off to: a caller now MAY resolve its prompt
 * through {@link resolvePromptTemplate} instead of using the constant
 * directly, layering a DB-backed override on top of it.
 *
 * `PromptVersionSource` is a small, structurally-compatible seam — the same
 * shape as `packages/correlation/src/tuning.ts`'s `FalsePositiveTuning` seam
 * — so this package can resolve prompts from
 * @montr/state-store's `PromptVersionRepository` WITHOUT taking a build-time
 * dependency on @montr/state-store (and the @prisma/client + native-engine
 * weight it drags in transitively). `PromptVersionRepositoryImpl` already
 * satisfies this interface structurally; the one caller that constructs both
 * (apps/worker/src/main.ts) injects `store.promptVersions` directly.
 *
 * Fallback contract: the hardcoded template a caller already has IS "version
 * 1" — {@link resolvePromptTemplate} returns it verbatim whenever no
 * `PromptVersionSource` is configured, the source has no active version for
 * that key, or the lookup itself fails. Behavior with an empty (or absent)
 * database is therefore byte-for-byte identical to before this module
 * existed; a DB-backed override is opt-in and additive only.
 */
export interface PromptVersionSourceRecord {
  template: string;
  /**
   * Monotonic version number for this record (E15 — eval-driven prompt
   * optimization). Optional for back-compat with a minimal source that only
   * ever implements {@link PromptVersionSource.getActive} — such a source
   * structurally satisfies this interface without ever setting `version`,
   * since nothing reads it unless {@link resolvePromptVersionTemplate} is
   * used.
   */
  version?: number;
}

/** The subset of `@montr/state-store`'s `PromptVersionRepository` this package needs. */
export interface PromptVersionSource {
  getActive(name: string, clientId?: string | null): Promise<PromptVersionSourceRecord | null>;
  /**
   * E15 — list every stored version for `name` (any order; callers that care
   * about order, like {@link resolvePromptVersionTemplate}, filter by exact
   * version number rather than relying on array order). `@montr/state-store`'s
   * `PromptVersionRepositoryImpl.listVersions` already satisfies this shape
   * (its richer `PromptVersionRecord` return type is a structural superset of
   * {@link PromptVersionSourceRecord}) — this is a WIDENING of the existing
   * seam, not a new one, so today's single caller (`resolvePromptTemplate`,
   * via `getActive`) is unaffected. Optional: a source that only supports
   * "give me the active one" (e.g. a hand-rolled test double) can omit it;
   * {@link resolvePromptVersionTemplate} then falls back to its `fallback` arg.
   */
  listVersions?(name: string, clientId?: string | null): Promise<PromptVersionSourceRecord[]>;
}

export interface ResolvePromptOptions {
  /** Client-scoped override lookup; omit/null to resolve the global version only. */
  clientId?: string | null;
}

/**
 * Resolve prompt `name`'s live template: the active DB version (client-scoped
 * override first, else the global version) when `source` is configured and
 * has one; otherwise `fallback`, unchanged. Never throws — a DB error during
 * lookup is reported via `onError` (metadata only) and treated the same as
 * "no active version": a prompt lookup must never break a scan.
 */
export async function resolvePromptTemplate(
  source: PromptVersionSource | undefined,
  name: string,
  fallback: string,
  opts: ResolvePromptOptions = {},
  onError?: (err: unknown) => void,
): Promise<string> {
  if (!source) return fallback;
  try {
    const active = await source.getActive(name, opts.clientId ?? null);
    return active?.template ?? fallback;
  } catch (err) {
    onError?.(err);
    return fallback;
  }
}

/**
 * Resolve prompt `name`'s template at a SPECIFIC version (E15 — eval-driven
 * prompt optimization). {@link resolvePromptTemplate} always resolves
 * whichever version is marked ACTIVE; this instead lets a caller — typically
 * an offline eval harness A/B-testing a candidate prompt version against the
 * golden corpus before promoting it — pin an exact version number, so a
 * candidate can be scored WITHOUT first flipping it active in the real store.
 *
 * Same fail-safe contract as {@link resolvePromptTemplate}: never throws. A
 * missing source, a source with no {@link PromptVersionSource.listVersions}
 * support, a version number that doesn't exist, or a lookup error all resolve
 * to `fallback` unchanged.
 */
export async function resolvePromptVersionTemplate(
  source: PromptVersionSource | undefined,
  name: string,
  version: number,
  fallback: string,
  opts: ResolvePromptOptions = {},
  onError?: (err: unknown) => void,
): Promise<string> {
  if (!source?.listVersions) return fallback;
  try {
    const versions = await source.listVersions(name, opts.clientId ?? null);
    const match = versions.find((v) => v.version === version);
    return match?.template ?? fallback;
  } catch (err) {
    onError?.(err);
    return fallback;
  }
}
