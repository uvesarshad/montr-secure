/**
 * Phase-4 (Wave 5) — cross-scan trend intelligence + org-wide posture dashboards
 * (PRD §16). READ-ONLY and RBAC-scoped: every query is client-scoped (per-client
 * isolation) and available to all authenticated roles (viewer included).
 *
 * ⛔ Golden rule "never headline raw counts": posture aggregates count CONFIRMED
 *    findings only (the {@link PostureSnapshot} the pipeline records per scan) —
 *    never the raw Layer-1 candidate pile.
 *
 * STUB SEAM (WS-R fills): the trend/aggregation reads below are wired to the
 * posture store and return empty until the pipeline records posture snapshots on
 * scan completion. WS-R owns snapshot recording + any richer aggregation.
 */
import type { FastifyInstance } from "fastify";
import type { OrgPostureSummary, PostureTrend, SeverityCounts, Severity } from "@montr/contracts";
import { unauthorized } from "../errors.js";
import { parseQuery } from "../validation.js";
import { TrendQuerySchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/** Accumulate `src` severity counts into `dst` (confirmed-only aggregates). */
function addCounts(dst: SeverityCounts, src: SeverityCounts): void {
  for (const s of SEVERITIES) {
    const v = src[s];
    if (v) dst[s] = (dst[s] ?? 0) + v;
  }
}

export function registerAnalyticsRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  // Per-repo posture over time (regression / new-issue detection).
  app.get(
    "/analytics/trends",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["analytics"],
        summary: "Posture trend for a repo (confirmed findings over time)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req): Promise<{ trend: PostureTrend }> => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { repo } = parseQuery(TrendQuerySchema, req);
      const snapshots = await store.posture.listByRepo(user.clientId, repo);
      const trend: PostureTrend = {
        clientId: user.clientId,
        repo,
        snapshots,
        ...(snapshots.length > 0 ? { latest: snapshots[snapshots.length - 1] } : {}),
      };
      return { trend };
    },
  );

  // Org-wide posture aggregate across repos (RBAC-scoped to the caller's client).
  app.get(
    "/analytics/posture",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["analytics"],
        summary: "Org-wide posture dashboard (confirmed-by-severity per repo)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req): Promise<{ summary: OrgPostureSummary }> => {
      const user = req.authUser;
      if (!user) throw unauthorized();

      // Latest snapshot per repo = that repo's current posture.
      const all = await store.posture.list(user.clientId);
      const latestByRepo = new Map<string, (typeof all)[number]>();
      for (const snap of all) {
        const cur = latestByRepo.get(snap.repo);
        if (!cur || snap.at > cur.at) latestByRepo.set(snap.repo, snap);
      }

      const totalsBySeverity: SeverityCounts = {};
      let total = 0;
      const repos = [...latestByRepo.values()].map((snap) => {
        addCounts(totalsBySeverity, snap.confirmedBySeverity);
        total += snap.total;
        return {
          repo: snap.repo,
          total: snap.total,
          confirmedBySeverity: snap.confirmedBySeverity,
          latestScanId: snap.scanId,
          latestAt: snap.at,
        };
      });

      const summary: OrgPostureSummary = {
        clientId: user.clientId,
        at: deps.clock.now().toISOString(),
        repos,
        totals: { repoCount: repos.length, total, confirmedBySeverity: totalsBySeverity },
      };
      return { summary };
    },
  );
}
