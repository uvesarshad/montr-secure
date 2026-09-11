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
import type {
  BlueTeamAttackCoveragePoint,
  BlueTeamCoverageTrendPoint,
  BlueTeamOrgSummary,
  DedupedDetectionRule,
  DetectionCoverage,
  DetectionRule,
  MitreTechniqueCoverageShape,
  OrgPostureSummary,
  PostureTrend,
  SeverityCounts,
  Severity,
} from "@montr/contracts";
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

  // A5 (red/blue agentic-posture audit) — org-wide blue-team aggregate: ATT&CK
  // coverage over time, a deduped cross-scan detection-rule inventory, and the
  // real (A7) detection-coverage trend. Available to every role, same as the
  // per-scan Blue Team tab it aggregates (viewer included — read-only).
  app.get(
    "/analytics/blue-team",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["analytics"],
        summary:
          "Org-wide blue-team aggregate (ATT&CK coverage, detection-rule inventory, detection-coverage trend)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req): Promise<{ summary: BlueTeamOrgSummary }> => {
      const user = req.authUser;
      if (!user) throw unauthorized();

      const scans = [...(await store.scans.list(user.clientId))].sort((a, b) =>
        (a.finishedAt ?? a.createdAt).localeCompare(b.finishedAt ?? b.createdAt),
      );

      /* ---- ATT&CK coverage: aggregate each scan's already-built
       * Report.blueTeam.mitreAttack.coverage (B2/B10) — no re-derivation. ---- */
      const techniqueMap = new Map<
        string,
        {
          technique: MitreTechniqueCoverageShape["technique"];
          findingCount: number;
          findingIds: Set<string>;
        }
      >();
      const cumulativeSeen = new Set<string>();
      const overTime: BlueTeamAttackCoveragePoint[] = [];
      let scansConsidered = 0;

      for (const scan of scans) {
        const report = await store.reports.getByScan(user.clientId, scan.id);
        if (!report) continue;
        scansConsidered += 1;
        const seenThisScan = new Set<string>();
        for (const row of report.blueTeam.mitreAttack.coverage) {
          seenThisScan.add(row.technique.id);
          cumulativeSeen.add(row.technique.id);
          const existing = techniqueMap.get(row.technique.id);
          if (existing) {
            existing.findingCount += row.findingCount;
            for (const id of row.findingIds) existing.findingIds.add(id);
          } else {
            techniqueMap.set(row.technique.id, {
              technique: row.technique,
              findingCount: row.findingCount,
              findingIds: new Set(row.findingIds),
            });
          }
        }
        overTime.push({
          scanId: scan.id,
          repo: scan.repo,
          at: scan.finishedAt ?? scan.createdAt,
          techniqueCount: seenThisScan.size,
          cumulativeTechniqueCount: cumulativeSeen.size,
        });
      }

      const coverage: MitreTechniqueCoverageShape[] = [...techniqueMap.values()]
        .map((v) => ({
          technique: v.technique,
          findingCount: v.findingCount,
          findingIds: [...v.findingIds],
        }))
        .sort(
          (a, b) => b.findingCount - a.findingCount || a.technique.id.localeCompare(b.technique.id),
        );

      /* ---- Detection-rule inventory: real, persisted (A7) DetectionRule rows
       * across every scan, deduped by (format, content) — see
       * DedupedDetectionRuleSchema's doc comment. ---- */
      const allRules: DetectionRule[] = await store.detectionRules.list(user.clientId);
      const dedupMap = new Map<
        string,
        { rule: DetectionRule; scanIds: Set<string>; findingIds: Set<string>; occurrences: number }
      >();
      for (const rule of allRules) {
        const key = `${rule.format}::${rule.content}`;
        const existing = dedupMap.get(key);
        if (existing) {
          existing.occurrences += 1;
          existing.scanIds.add(rule.scanId);
          existing.findingIds.add(rule.findingId);
          if (rule.createdAt > existing.rule.createdAt) existing.rule = rule;
        } else {
          dedupMap.set(key, {
            rule,
            scanIds: new Set([rule.scanId]),
            findingIds: new Set([rule.findingId]),
            occurrences: 1,
          });
        }
      }
      const dedupedRules: DedupedDetectionRule[] = [...dedupMap.values()]
        .map((v) => ({
          rule: v.rule,
          occurrences: v.occurrences,
          scanIds: [...v.scanIds],
          findingIds: [...v.findingIds],
        }))
        .sort(
          (a, b) =>
            b.occurrences - a.occurrences || b.rule.createdAt.localeCompare(a.rule.createdAt),
        );

      /* ---- Detection-coverage trend: real, persisted (A7) DetectionCoverage
       * rows, one point per scan that has any, chronological. ---- */
      const allCoverage: DetectionCoverage[] = await store.detectionCoverage.list(user.clientId);
      const coverageByScan = new Map<string, DetectionCoverage[]>();
      for (const row of allCoverage) {
        const list = coverageByScan.get(row.scanId) ?? [];
        list.push(row);
        coverageByScan.set(row.scanId, list);
      }
      const trendPoints: BlueTeamCoverageTrendPoint[] = [];
      const totals = { detected: 0, undetected: 0, unknown: 0 };
      for (const scan of scans) {
        const rows = coverageByScan.get(scan.id);
        if (!rows || rows.length === 0) continue;
        let detected = 0;
        let undetected = 0;
        let unknown = 0;
        for (const row of rows) {
          if (row.detected === "unknown") unknown += 1;
          else if (row.detected) detected += 1;
          else undetected += 1;
        }
        totals.detected += detected;
        totals.undetected += undetected;
        totals.unknown += unknown;
        trendPoints.push({
          scanId: scan.id,
          repo: scan.repo,
          at: scan.finishedAt ?? scan.createdAt,
          detected,
          undetected,
          unknown,
        });
      }

      const summary: BlueTeamOrgSummary = {
        clientId: user.clientId,
        at: deps.clock.now().toISOString(),
        scansConsidered,
        attackCoverage: { coverage, overTime },
        detectionRules: { rules: dedupedRules, totalGenerated: allRules.length },
        detectionCoverageTrend: { points: trendPoints, totals },
      };
      return { summary };
    },
  );
}
