/**
 * Detection-rule PUSH integrations (suggested enhancement, 2026-09-12
 * red/blue agentic-posture audit's "Suggested enhancements" section — "ship
 * detection rules as a real push integration (Splunk, Elastic, Sentinel)
 * rather than only a download, converting an advisory artifact into a
 * surface a SOC team touches weekly"). Until now, generated Sigma/OTel/SIEM
 * rules only ever left the process as a browser download
 * (apps/web/src/lib/exports.ts's `downloadDetectionRule`/
 * `downloadDetectionRuleBundle`, B11/A5) — nothing pushed them anywhere.
 * See packages/report/src/detection-rules/push/types.ts for the full
 * adapter-matrix design (one real adapter, Splunk HTTP Event Collector;
 * Elastic/Sentinel are honest `NotImplementedError` stubs, never fake).
 *
 * DESIGN NOTE — why the push routes take the rule INLINE rather than looking
 * one up by id: `packages/report/src/detection-rules/generate.ts`'s
 * `persistDetectionRules` (the `StateStore.detectionRules` writer) has no
 * real production caller today (verified: no reference anywhere outside its
 * own definition and tests) — `Report.blueTeam.detectionEngineering.rules`
 * is built fresh per report read, never persisted as standalone
 * `DetectionRule` rows in the normal request path. A route that looked up a
 * rule by id against that table would silently 404 on every real deployment.
 * The console already holds the exact, fully-generated `DetectionRule`
 * object (it rendered it from the loaded `Report`), so these routes accept
 * it directly — no invented dependency on a table nothing writes to yet.
 *
 * RBAC: configuring a push target (`POST`/`DELETE .../push-targets`) is
 * approver-only — it stores a live, reversible outbound credential, the same
 * sensitivity class `POST /dast/targets/:id/authorize` (dast.ts) already
 * treats as approver-only. Triggering a push once a target exists is
 * operator+approver — an operational action, mirroring `manage_custom_rules`
 * (docs/auth/authorization.md).
 */
import type { FastifyInstance } from "fastify";
import type { DetectionRule } from "@montr/contracts";
import {
  createDetectionRulePusher,
  type DetectionRulePushResult,
  type DetectionRulePushTargetType,
} from "@montr/report";
import { createEgressGuard } from "@montr/security";
import { badRequest, conflict, HttpError, unauthorized } from "../errors.js";
import { parseBody } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import {
  PushDetectionRuleBodySchema,
  PushDetectionRuleBundleBodySchema,
  UpsertDetectionRulePushTargetBodySchema,
} from "../schemas.js";
import type { AuthenticatedUser, ResolvedDeps } from "../types.js";

/** The `type` values this deployment can genuinely push to. Kept in sync with `UpsertDetectionRulePushTargetBodySchema`'s literal (Zod already refuses anything else at the validation boundary; this is a second, defensive check against a row written by an older/different build). */
const KNOWN_PUSH_TARGET_TYPES = new Set<string>(["splunk_hec"]);

export function registerDetectionRulePushRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  /* ------------------------------ target config ------------------------------ */

  app.post(
    "/detection-rules/push-targets",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["detection-rules"],
        summary: "Configure this client's detection-rule push target (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(UpsertDetectionRulePushTargetBodySchema, req);

      const saved = await store.detectionRulePushTargets.upsert(user.clientId, {
        type: body.type,
        endpointUrl: body.endpointUrl,
        hecToken: body.hecToken,
        ...(body.index !== undefined ? { index: body.index } : {}),
        ...(body.sourcetype !== undefined ? { sourcetype: body.sourcetype } : {}),
      });

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "detection_rule.push_target_configured",
        targetType: "detection_rule_push_target",
        targetId: user.clientId,
        summary: `Detection-rule push target configured (${saved.type}): ${saved.endpointUrl}`,
        // Metadata only — never the token (recordAudit also scrubs defensively).
        metadata: { type: saved.type, endpointUrl: saved.endpointUrl, index: saved.index },
      });

      reply.status(201);
      return {
        target: {
          type: saved.type,
          endpointUrl: saved.endpointUrl,
          index: saved.index,
          sourcetype: saved.sourcetype,
          createdAt: saved.createdAt,
          updatedAt: saved.updatedAt,
        },
      };
    },
  );

  app.get(
    "/detection-rules/push-targets",
    {
      preHandler: [app.authenticate, app.requireRole("operator", "approver")],
      schema: {
        tags: ["detection-rules"],
        summary: "Get this client's configured detection-rule push target (metadata only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const meta = await store.detectionRulePushTargets.getMetadata(user.clientId);
      return { target: meta };
    },
  );

  app.delete(
    "/detection-rules/push-targets",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["detection-rules"],
        summary: "Remove this client's detection-rule push target (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      await store.detectionRulePushTargets.delete(user.clientId);
      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "detection_rule.push_target_deleted",
        targetType: "detection_rule_push_target",
        targetId: user.clientId,
        summary: "Detection-rule push target removed",
      });
      reply.status(204);
      return null;
    },
  );

  /* --------------------------------- push -------------------------------- */

  /**
   * Push one rule to the configured target. Never silently swallows a
   * failure: a non-2xx/transport failure from the adapter is audited as
   * `detection_rule.push_failed` and surfaced as a 502 with the real reason;
   * an egress denial or an honestly-unimplemented target type propagates as
   * its own typed error (403 `EGRESS_BLOCKED` / 501 `NOT_IMPLEMENTED` — see
   * apps/api/src/errors.ts's `montrErrorStatus`), also audited first.
   */
  async function pushOneRule(
    reqDeps: ResolvedDeps,
    user: AuthenticatedUser,
    rule: DetectionRule,
  ): Promise<DetectionRulePushResult> {
    const targetRecord = await reqDeps.store.detectionRulePushTargets.get(user.clientId);
    if (!targetRecord) {
      throw conflict(
        "No detection-rule push target is configured for this client yet — configure one via POST /detection-rules/push-targets first.",
      );
    }
    if (!KNOWN_PUSH_TARGET_TYPES.has(targetRecord.type)) {
      throw badRequest(`Configured push target type '${targetRecord.type}' is not recognised`);
    }

    const egress = createEgressGuard(reqDeps.config);
    const pusher = createDetectionRulePusher(targetRecord.type as DetectionRulePushTargetType, {
      ...(reqDeps.detectionRulePushHttpClient
        ? { httpClient: reqDeps.detectionRulePushHttpClient }
        : {}),
    });

    let result: DetectionRulePushResult;
    try {
      result = await pusher.pushRule(
        rule,
        {
          type: targetRecord.type as DetectionRulePushTargetType,
          endpointUrl: targetRecord.endpointUrl,
          ...(targetRecord.index !== undefined ? { index: targetRecord.index } : {}),
          ...(targetRecord.sourcetype !== undefined ? { sourcetype: targetRecord.sourcetype } : {}),
        },
        { token: targetRecord.hecToken },
        egress,
      );
    } catch (err) {
      await recordAudit(reqDeps.store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "detection_rule.push_failed",
        targetType: "detection_rule",
        targetId: rule.id,
        scanId: rule.scanId,
        summary: `Detection-rule push failed (${targetRecord.type}): ${err instanceof Error ? err.message : String(err)}`,
        metadata: { targetType: targetRecord.type, endpointUrl: targetRecord.endpointUrl },
      });
      throw err;
    }

    await recordAudit(reqDeps.store, {
      clientId: user.clientId,
      actor: actorFromUser(user),
      action: result.success ? "detection_rule.pushed" : "detection_rule.push_failed",
      targetType: "detection_rule",
      targetId: rule.id,
      scanId: rule.scanId,
      summary: result.success
        ? `Detection rule pushed to ${targetRecord.type}: ${targetRecord.endpointUrl}`
        : `Detection-rule push rejected by ${targetRecord.type}: ${result.message}`,
      metadata: {
        targetType: targetRecord.type,
        endpointUrl: targetRecord.endpointUrl,
        statusCode: result.statusCode,
        success: result.success,
      },
    });

    if (!result.success) {
      throw new HttpError(502, "DETECTION_RULE_PUSH_FAILED", result.message, {
        statusCode: result.statusCode,
      });
    }
    return result;
  }

  app.post(
    "/detection-rules/push",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["detection-rules"],
        summary: "Push one generated detection rule to the configured target",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(PushDetectionRuleBodySchema, req);
      const result = await pushOneRule(deps, user, body.rule);
      return { result };
    },
  );

  app.post(
    "/detection-rules/push-bundle",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["detection-rules"],
        summary: "Push every rule in a bundle to the configured target",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(PushDetectionRuleBundleBodySchema, req);

      // Sequential, not Promise.all: each push is a real outbound credentialed
      // call against the SAME operator's Splunk instance — no reason to burst
      // it, and it keeps per-item audit ordering meaningful. A single rule's
      // failure never aborts the rest — every item is reported (never a
      // silently-swallowed partial failure), mirroring this route's own
      // single-push honesty contract.
      const results: Array<{ ruleId: string; success: boolean; message: string }> = [];
      for (const rule of body.rules) {
        try {
          const r = await pushOneRule(deps, user, rule);
          results.push({ ruleId: rule.id, success: true, message: r.message });
        } catch (err) {
          results.push({
            ruleId: rule.id,
            success: false,
            message: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return { results };
    },
  );
}
