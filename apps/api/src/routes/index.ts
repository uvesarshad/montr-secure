/**
 * Route registration. Swagger + security + auth plugins must already be
 * registered on `app` before this runs.
 */
import type { FastifyInstance } from "fastify";
import type { ResolvedDeps } from "../types.js";
import { registerAuthRoutes } from "./auth.js";
import { registerScanRoutes } from "./scans.js";
import { registerGateRoutes } from "./gate.js";
import { registerDastRoutes } from "./dast.js";
import { registerFindingRoutes } from "./findings.js";
import { registerAuditRoutes } from "./audit.js";
// Phase-4 (Wave 5) — scale & intelligence. Stub seams registered here; the
// feature agents (WS-R) fill the handler bodies in these owned files only.
import { registerAnalyticsRoutes } from "./analytics.js";
import { registerRuleRoutes } from "./rules.js";
import { registerScenarioRoutes } from "./scenarios.js";
import { registerScheduleRoutes } from "./schedules.js";

export function registerRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  app.get(
    "/health",
    { schema: { tags: ["system"], summary: "Liveness probe" }, config: { rateLimit: false } },
    async () => ({ status: "ok" }),
  );

  registerAuthRoutes(app, deps);
  registerScanRoutes(app, deps);
  registerGateRoutes(app, deps);
  registerDastRoutes(app, deps);
  registerFindingRoutes(app, deps);
  registerAuditRoutes(app, deps);

  // Phase-4 (Wave 5) — scale & intelligence stubs.
  registerAnalyticsRoutes(app, deps);
  registerRuleRoutes(app, deps);
  registerScenarioRoutes(app, deps);
  registerScheduleRoutes(app, deps);
}
