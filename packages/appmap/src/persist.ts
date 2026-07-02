/**
 * AppMap persistence + DECIDE-2 stale-commit invalidation + audit.
 *
 * The map is persisted per-client (the store enforces row-scoping + encryption
 * at rest). DECIDE-2: on a NEW commit, every previously-persisted map for the
 * repo on a different commit is marked stale (never deleted — a stale map still
 * seeds an incremental diff). A fresh, non-stale map for the exact commit is
 * reused instead of rebuilt. ⛔ Every persisted mutation is audit-logged
 * (golden rule #7); metadata is counts/ids only — never code bodies.
 */
import type { AppMap } from "@montr/contracts";
import type { AppMapRepository } from "@montr/state-store";
import type { AuditLogClient } from "@montr/telemetry";

export interface PersistOptions {
  appMaps: AppMapRepository;
  audit?: AuditLogClient;
  scanId?: string;
  /** Agent/user id recorded as the audit actor. */
  actorId?: string;
}

/**
 * DECIDE-2 reuse: return the persisted map for this exact commit iff it exists
 * and is not stale. Callers skip the (expensive) rebuild when one is returned.
 */
export async function findReusableAppMap(
  appMaps: AppMapRepository,
  clientId: string,
  repo: string,
  commitSha: string,
): Promise<AppMap | null> {
  if (!commitSha) return null;
  const existing = await appMaps.latestForCommit(clientId, repo, commitSha);
  if (existing && !existing.stale) return existing;
  return null;
}

/**
 * Persist a freshly-built map: invalidate stale maps on other commits (DECIDE-2),
 * create the new map, and audit both actions. Returns the persisted map.
 */
export async function persistAppMap(appMap: AppMap, opts: PersistOptions): Promise<AppMap> {
  const { appMaps, audit } = opts;
  const actor = { type: "agent" as const, id: opts.actorId ?? "layer0" };

  // DECIDE-2: mark every prior map for this repo on a different commit stale.
  const invalidated = await appMaps.invalidateStaleForCommit(
    appMap.clientId,
    appMap.repo,
    appMap.commitSha,
  );
  if (invalidated > 0 && audit) {
    await audit.append({
      clientId: appMap.clientId,
      ...(opts.scanId ? { scanId: opts.scanId } : {}),
      actor,
      action: "appmap.invalidated",
      targetType: "AppMap",
      summary: `Invalidated ${invalidated} stale App Map(s) for ${appMap.repo} at commit ${appMap.commitSha}`,
      metadata: { repo: appMap.repo, commitSha: appMap.commitSha, invalidated },
    });
  }

  const persisted = await appMaps.create(appMap.clientId, appMap);

  if (audit) {
    await audit.append({
      clientId: appMap.clientId,
      ...(opts.scanId ? { scanId: opts.scanId } : {}),
      actor,
      action: "appmap.built",
      targetType: "AppMap",
      targetId: persisted.id,
      summary: `App Map built for ${appMap.repo}@${appMap.commitSha} (${appMap.routes.length} routes, ${appMap.taintSinks.length} sinks)`,
      metadata: {
        repo: appMap.repo,
        branch: appMap.branch,
        commitSha: appMap.commitSha,
        routeCount: appMap.routes.length,
        sinkCount: appMap.taintSinks.length,
        sourceCount: appMap.taintSources.length,
        modelCount: appMap.ormModels.length,
      },
    });
  }

  return persisted;
}
