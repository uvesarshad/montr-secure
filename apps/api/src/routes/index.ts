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
import { registerWebhookRoutes } from "./webhooks.js";
// §15 cross-scan memory (E8) — explicit operator-facing learned-fact recording.
import { registerLearnedFactRoutes } from "./learned-facts.js";
// Phase-4 (Wave 5) — scale & intelligence: custom rules, red-team scenarios,
// scheduled scans, and cross-scan analytics. Fully implemented, not stubs
// (analytics' aggregation reads stay honestly empty only because no writer
// yet records posture snapshots — see analytics.ts's own header comment).
import { registerAnalyticsRoutes } from "./analytics.js";
import { registerRuleRoutes } from "./rules.js";
import { registerScenarioRoutes } from "./scenarios.js";
import { registerScheduleRoutes } from "./schedules.js";
// Suggested enhancement (2026-09-12 red/blue agentic-posture audit) — real
// push integration for generated detection rules (Splunk HEC).
import { registerDetectionRulePushRoutes } from "./detection-rules.js";

export function registerRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  // Unprefixed liveness probe — k8s/docker-compose/Dockerfile HEALTHCHECK all
  // target plain `/health` (see deploy/docker/Dockerfile.api, docker-compose.yml,
  // deploy/helm values.api.probes.path). Keep it outside the /api/v1 prefix.
  app.get(
    "/health",
    { schema: { tags: ["system"], summary: "Liveness probe" }, config: { rateLimit: false } },
    async () => ({ status: "ok" }),
  );

  // Every other route is versioned under /api/v1 (the web console's contract).
  // Route paths inside each routes/*.ts file are unchanged — only the mount
  // point moves — so this is purely additive from each route module's view.
  void app.register(
    async (api) => {
      registerAuthRoutes(api, deps);
      registerScanRoutes(api, deps);
      registerGateRoutes(api, deps);
      registerDastRoutes(api, deps);
      registerFindingRoutes(api, deps);
      registerAuditRoutes(api, deps);
      registerWebhookRoutes(api, deps);
      registerLearnedFactRoutes(api, deps);

      // Phase-4 (Wave 5) — scale & intelligence.
      registerAnalyticsRoutes(api, deps);
      registerRuleRoutes(api, deps);
      registerScenarioRoutes(api, deps);
      registerScheduleRoutes(api, deps);
      registerDetectionRulePushRoutes(api, deps);
    },
    { prefix: "/api/v1" },
  );
}
