/**
 * Phase-4 (Wave 5) — red-team scenario library (PRD §16). Reusable, VERSIONED
 * DAST/exploit scenarios, per-client isolated; scenario steps are encrypted at
 * rest in @montr/state-store (attack playbooks are sensitive).
 *
 * ⛔ SAFETY (§11, golden rules — never weakened here):
 *   - A scenario is ALLOWLIST-GATED via `targetAllowlistRef`; a run can never hit
 *     a target that is not on the DAST allowlist, and production is blocked.
 *   - Running a scenario is a LIVE-DAST action: approver-authorized (RBAC), routed
 *     through the SAME Layer-3 guardrails as live DAST (@montr/confirm's
 *     `assertScenarioAuthorized` + `runScenario` → allowlist + production block +
 *     kill switch + rate/blast-radius caps + @montr/security egress guard). It
 *     adds NO new egress path, and this route NEVER probes from the API process
 *     (no transport is supplied — probing belongs to the worker).
 *   - `enabled` defaults OFF; a disabled scenario cannot be run.
 *   - Every mutation/run is bound to an audit event.
 *
 * RBAC: scenario definitions are sensitive — reads require operator or approver
 * (hidden from viewers); running requires the approver role (hard guard).
 */
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { RedTeamScenarioSchema, type RedTeamScenario } from "@montr/contracts";
import { hostOf, runScenario, validateScenario } from "@montr/confirm";
import { badRequest, forbidden, notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { CreateRedTeamScenarioBodySchema, EntityIdParamsSchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

/** Optional run body — an allowlisted target OVERRIDE (still allowlist-validated). */
const RunScenarioBodySchema = z.object({ target: z.string().min(1).optional() }).optional();

export function registerScenarioRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store, config } = deps;

  app.get(
    "/scenarios",
    {
      preHandler: [app.authenticate, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scenarios"],
        summary: "List red-team scenarios",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const scenarios = await store.redTeamScenarios.list(user.clientId);
      return { scenarios };
    },
  );

  app.get(
    "/scenarios/:id",
    {
      preHandler: [app.authenticate, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scenarios"],
        summary: "Get a red-team scenario",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const scenario = await store.redTeamScenarios.get(user.clientId, id);
      if (!scenario) throw notFound("Scenario not found");
      return { scenario };
    },
  );

  // ⛔ Create disabled-by-default; structural-validate the steps first; audit.
  app.post(
    "/scenarios",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scenarios"],
        summary: "Author a red-team scenario (disabled until authorized)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(CreateRedTeamScenarioBodySchema, req);

      // ⛔ Structural validation: a step path must be RELATIVE to the allowlisted
      // target — an absolute URL could smuggle an off-allowlist destination.
      const validation = validateScenario({
        name: body.name,
        steps: body.steps,
        targetAllowlistRef: body.targetAllowlistRef,
      });
      if (!validation.valid) {
        throw badRequest("Scenario failed validation", {
          errors: validation.errors,
          warnings: validation.warnings,
        });
      }

      const scenario: RedTeamScenario = RedTeamScenarioSchema.parse({
        id: deps.idgen("scn"),
        clientId: user.clientId,
        name: body.name,
        category: body.category,
        steps: body.steps,
        targetAllowlistRef: body.targetAllowlistRef,
        version: 1,
        enabled: false, // ⛔ always disabled at create (§11 — authorize explicitly)
        createdBy: user.id,
        createdAt: deps.clock.now().toISOString(),
      });
      const created = await store.redTeamScenarios.create(user.clientId, scenario);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "scenario.created",
        targetType: "red_team_scenario",
        targetId: created.id,
        summary: `Red-team scenario authored (disabled): ${created.name}`,
        // Never store the (encrypted-at-rest) steps in the audit log.
        metadata: {
          category: created.category,
          stepCount: created.steps.length,
          targetHost: hostOf(created.targetAllowlistRef),
          enabled: created.enabled,
          version: created.version,
        },
      });

      reply.status(201);
      return { scenario: created, validation };
    },
  );

  // Re-validate + version bump. Enabling here marks the scenario library-usable;
  // RUNNING it stays approver-only and re-gated below.
  app.put(
    "/scenarios/:id",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scenarios"],
        summary: "Update a red-team scenario",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const existing = await store.redTeamScenarios.get(user.clientId, id);
      if (!existing) throw notFound("Scenario not found");
      const body = parseBody(CreateRedTeamScenarioBodySchema, req);

      const validation = validateScenario({
        name: body.name,
        steps: body.steps,
        targetAllowlistRef: body.targetAllowlistRef,
      });
      if (!validation.valid) {
        throw badRequest("Scenario failed validation", {
          errors: validation.errors,
          warnings: validation.warnings,
        });
      }

      const updated: RedTeamScenario = RedTeamScenarioSchema.parse({
        ...existing,
        name: body.name,
        category: body.category,
        steps: body.steps,
        targetAllowlistRef: body.targetAllowlistRef,
        enabled: body.enabled ?? false,
        version: existing.version + 1, // ⛔ server-controlled version bump
      });
      const saved = await store.redTeamScenarios.update(user.clientId, updated);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "scenario.updated",
        targetType: "red_team_scenario",
        targetId: saved.id,
        summary: `Red-team scenario updated: ${saved.name} (v${existing.version}→v${saved.version}, enabled=${saved.enabled})`,
        metadata: {
          category: saved.category,
          stepCount: saved.steps.length,
          targetHost: hostOf(saved.targetAllowlistRef),
          enabled: saved.enabled,
          fromVersion: existing.version,
          toVersion: saved.version,
        },
      });

      return { scenario: saved, validation };
    },
  );

  app.delete(
    "/scenarios/:id",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scenarios"],
        summary: "Delete a red-team scenario",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const existing = await store.redTeamScenarios.get(user.clientId, id);
      if (!existing) throw notFound("Scenario not found");

      await store.redTeamScenarios.delete(user.clientId, id);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "scenario.deleted",
        targetType: "red_team_scenario",
        targetId: existing.id,
        summary: `Red-team scenario deleted: ${existing.name}`,
        metadata: { category: existing.category, version: existing.version },
      });

      return { ok: true, id: existing.id };
    },
  );

  // ⛔ Live-DAST run — approver-only (hard guard). Enforces the allowlist
  // (`targetAllowlistRef` ∈ DAST allowlist, production blocked), routes through the
  // @montr/security egress guard, and honors the kill switch + rate/blast caps by
  // reusing the Layer-3 guardrails. It NEVER probes from the API process (no
  // transport) — it authorizes + gate-checks every step and audits the run.
  app.post(
    "/scenarios/:id/run",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["scenarios"],
        summary: "Run a red-team scenario against an allowlisted target (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const scenario = await store.redTeamScenarios.get(user.clientId, id);
      if (!scenario) throw notFound("Scenario not found");

      // ⛔ Disabled scenarios can never run (disabled-by-default, §11).
      if (!scenario.enabled) {
        throw forbidden("Scenario is disabled — enable it before running");
      }
      // ⛔ Config invariants (defense in depth; both are literal-true in config).
      if (config.dast.productionBlocked !== true) {
        throw forbidden("Production DAST is blocked by policy");
      }
      if (config.dast.killSwitchEnabled !== true) {
        throw forbidden("DAST kill switch must be enabled by policy");
      }

      const body = parseBody(RunScenarioBodySchema, req);

      // ⛔ THE GATE. `requireApprover` already enforced the approver role at the
      // HTTP layer ⇒ allowLive=true; the Layer-3 gate still independently checks
      // dast.enabled + allowlist + production. A non-allowlisted / production
      // target throws DastTargetNotAllowlistedError (→ 403) before any probe.
      // No transport ⇒ authorize + gate-check every step, send nothing.
      const result = await runScenario(
        {
          scenario,
          config,
          allowLive: true,
          ...(body?.target ? { targetOverride: body.target } : {}),
        },
        {},
      );

      // ⛔ Audit the authorized run (golden rule #7). Never store the steps.
      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "scenario.run",
        targetType: "red_team_scenario",
        targetId: scenario.id,
        summary: `Red-team scenario authorized to run against allowlisted target: ${scenario.name}`,
        metadata: {
          category: scenario.category,
          targetHost: hostOf(result.target),
          stepCount: scenario.steps.length,
          probed: result.probed,
          blocked: result.blocked,
          requestsSent: result.requestsSent,
          mutatingSent: result.mutatingSent,
        },
      });

      return { run: result };
    },
  );
}
