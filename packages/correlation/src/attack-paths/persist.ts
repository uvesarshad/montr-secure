/**
 * Persists discovered attack paths via `StateStore.attackPaths` (B1's
 * repository — `packages/state-store/src/blue-team.ts`'s
 * `AttackPathRepositoryImpl`). `./graph.ts`'s `buildAttackPaths` stays pure/
 * I/O-free (like `../correlate.ts`'s own scoring core); this is the thin,
 * optional persistence seam a pipeline step wires in later.
 */
import type { AttackPath } from "@montr/contracts";
import type { AttackPathRepository } from "@montr/state-store";
import { buildAttackPaths, type BuildAttackPathsInput } from "./graph.js";

/** Builds attack paths and creates one row per path via `repo`, in ranked order. */
export async function discoverAndPersistAttackPaths(
  repo: AttackPathRepository,
  input: BuildAttackPathsInput,
): Promise<AttackPath[]> {
  const paths = buildAttackPaths(input);
  const persisted: AttackPath[] = [];
  for (const path of paths) {
    persisted.push(await repo.create(input.clientId, path));
  }
  return persisted;
}
