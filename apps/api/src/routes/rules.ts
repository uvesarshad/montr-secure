/**
 * Phase-4 (Wave 5) — custom rule authoring (PRD §16). Client Semgrep / secret
 * detectors, stored + VERSIONED, per-client isolated.
 *
 * ⛔ Golden rule "custom rules are validated before use": the rule body is
 *    VALIDATED (@montr/discovery `validateCustomRule` — semgrep `--validate` when
 *    available, structural otherwise) and a rule can NOT be enabled while invalid.
 *    Every mutation is bound to an audit event (rule.created/updated/deleted).
 *
 * RBAC: reads are available to any authenticated role (per-client scoped);
 * authoring mutations require operator or approver (viewers are read-only).
 */
import type { FastifyInstance } from "fastify";
import { CustomRuleSchema, type CustomRule } from "@montr/contracts";
import { validateCustomRule } from "@montr/discovery";
import { badRequest, notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { CreateCustomRuleBodySchema, EntityIdParamsSchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

export function registerRuleRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  app.get(
    "/rules",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["rules"],
        summary: "List custom detection rules",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const rules = await store.customRules.list(user.clientId);
      return { rules };
    },
  );

  app.get(
    "/rules/:id",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["rules"],
        summary: "Get a custom rule",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const rule = await store.customRules.get(user.clientId, id);
      if (!rule) throw notFound("Custom rule not found");
      return { rule };
    },
  );

  // ⛔ Validate the rule body BEFORE create; enabling an invalid rule is refused.
  app.post(
    "/rules",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["rules"],
        summary: "Author a custom rule (validated before use)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(CreateCustomRuleBodySchema, req);

      const validation = await validateCustomRule({
        engine: body.engine,
        language: body.language,
        body: body.body,
      });
      // ⛔ Never enable an invalid rule (golden rule: validated before use). A
      // disabled draft may be stored so the author can iterate on the errors.
      if (body.enabled && !validation.valid) {
        throw badRequest("Custom rule failed validation; cannot enable", {
          errors: validation.errors,
          warnings: validation.warnings,
        });
      }

      const rule: CustomRule = CustomRuleSchema.parse({
        id: deps.idgen("rule"),
        clientId: user.clientId,
        name: body.name,
        language: body.language,
        engine: body.engine,
        body: body.body,
        version: 1,
        enabled: body.enabled ?? false,
        createdBy: user.id,
        createdAt: deps.clock.now().toISOString(),
      });
      const created = await store.customRules.create(user.clientId, rule);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "rule.created",
        targetType: "custom_rule",
        targetId: created.id,
        summary: `Custom ${created.engine} rule authored: ${created.name} (enabled=${created.enabled})`,
        // Metadata is lean + code-free: never store the rule body (golden rule #1).
        metadata: {
          engine: created.engine,
          language: created.language,
          enabled: created.enabled,
          version: created.version,
          validationValid: validation.valid,
          validationErrorCount: validation.errors.length,
        },
      });

      reply.status(201);
      return { rule: created, validation };
    },
  );

  // ⛔ Re-validate on update; enabling an invalid rule is refused. Every update
  // bumps the version (VERSIONING) so rule history is auditable.
  app.put(
    "/rules/:id",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["rules"],
        summary: "Update a custom rule (validated before use)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const existing = await store.customRules.get(user.clientId, id);
      if (!existing) throw notFound("Custom rule not found");
      const body = parseBody(CreateCustomRuleBodySchema, req);

      const validation = await validateCustomRule({
        engine: body.engine,
        language: body.language,
        body: body.body,
      });
      if (body.enabled && !validation.valid) {
        throw badRequest("Custom rule failed validation; cannot enable", {
          errors: validation.errors,
          warnings: validation.warnings,
        });
      }

      const updated: CustomRule = CustomRuleSchema.parse({
        ...existing,
        name: body.name,
        language: body.language,
        engine: body.engine,
        body: body.body,
        enabled: body.enabled ?? false,
        version: existing.version + 1, // ⛔ server-controlled version bump
      });
      const saved = await store.customRules.update(user.clientId, updated);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "rule.updated",
        targetType: "custom_rule",
        targetId: saved.id,
        summary: `Custom rule updated: ${saved.name} (v${existing.version}→v${saved.version}, enabled=${saved.enabled})`,
        metadata: {
          engine: saved.engine,
          language: saved.language,
          enabled: saved.enabled,
          fromVersion: existing.version,
          toVersion: saved.version,
          validationValid: validation.valid,
          validationErrorCount: validation.errors.length,
        },
      });

      return { rule: saved, validation };
    },
  );

  app.delete(
    "/rules/:id",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["rules"],
        summary: "Delete a custom rule",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const existing = await store.customRules.get(user.clientId, id);
      if (!existing) throw notFound("Custom rule not found");

      await store.customRules.delete(user.clientId, id);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "rule.deleted",
        targetType: "custom_rule",
        targetId: existing.id,
        summary: `Custom rule deleted: ${existing.name}`,
        metadata: {
          engine: existing.engine,
          language: existing.language,
          version: existing.version,
        },
      });

      return { ok: true, id: existing.id };
    },
  );
}
