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
 *     kill switch + rate/blast-radius caps + @montr/security egress guard).
 *   - `enabled` defaults OFF; a disabled scenario cannot be run.
 *   - Every mutation/run is bound to an audit event.
 *
 * A1 (2026-09-12 red/blue agentic-posture audit): this route used to call
 * `runScenario` with NO transport, so a "run" only ever authorized + gate-
 * checked every step in-process — nothing was ever probed, anywhere, despite
 * the operator-facing UI implying otherwise. Real worker-side execution is
 * now wired (apps/worker/src/scenario-runs), but it is gated behind an
 * ADDITIONAL, explicit WRITTEN authorization beyond RBAC + the allowlist: an
 * approver must first record a free-text authorization reference via
 * `POST /scenarios/:id/authorize` (ticket/agreement reference), bound to the
 * scenario's exact current version (`RedTeamScenarioSchema.liveAuthorized*`,
 * packages/contracts/src/phase4.ts's `hasLiveRunAuthorization`). This route
 * still NEVER probes from the API process itself (no transport is
 * constructed here) — it authorizes + gate-checks + previews every step
 * exactly as before, then, ONLY when written authorization is present,
 * enqueues a real execution job for apps/worker to pick up
 * (apps/api/src/scenario-run-producer.ts). Missing/stale authorization is a
 * hard, honest rejection (403) — never a silent no-op.
 *
 * RBAC: scenario definitions are sensitive — reads require operator or approver
 * (hidden from viewers); running and authorizing both require the approver role
 * (hard guard).
 */
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  hasLiveRunAuthorization,
  RedTeamScenarioSchema,
  type RedTeamScenario,
  type ScenarioRunJob,
} from "@montr/contracts";
import { hostOf, runScenario, validateScenario } from "@montr/confirm";
import { badRequest, forbidden, notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import {
  AuthorizeScenarioBodySchema,
  CreateRedTeamScenarioBodySchema,
  EntityIdParamsSchema,
} from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

/** Optional run body — an allowlisted target OVERRIDE (still allowlist-validated). */
const RunScenarioBodySchema = z.object({ target: z.string().min(1).optional() }).optional();

/**
 * ⛔ A1 — why `POST /scenarios/:id/run` refused to enqueue real execution.
 * Distinguishes "never authorized" from "authorized for a stale version" so
 * the operator/console gets a concrete, actionable reason rather than a
 * generic 403 (never silent, never vague — see route header comment).
 */
function writtenAuthorizationGapReason(scenario: RedTeamScenario): string {
  if (!scenario.liveAuthorizedById || !scenario.liveAuthorizedAt) {
    return (
      "This scenario has never been authorized for live execution. An approver must call " +
      "POST /scenarios/:id/authorize with a written authorizationReference " +
      "(a ticket number or signed agreement reference) before it can run for real."
    );
  }
  if (scenario.liveAuthorizedForVersion !== scenario.version) {
    return (
      `This scenario was authorized for version ${scenario.liveAuthorizedForVersion ?? "?"}, ` +
      `but it is now version ${scenario.version} (edited since authorization). An approver ` +
      "must re-authorize this exact version via POST /scenarios/:id/authorize before it can " +
      "run for real."
    );
  }
  return (
    "This scenario's written authorization is incomplete (missing an authorization " +
    "reference). An approver must authorize it via POST /scenarios/:id/authorize before it " +
    "can run for real."
  );
}

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

      // ⛔ A1 — deliberately NOT spreading `...existing`'s liveAuthorized*
      // fields forward: ANY edit invalidates a prior written authorization
      // outright (never left merely stale/mismatched-version — explicitly
      // cleared), since the authorized steps/target may themselves have just
      // changed. A fresh POST /scenarios/:id/authorize is required after
      // every edit, no exceptions.
      const wasAuthorized = hasLiveRunAuthorization(existing);
      const updated: RedTeamScenario = RedTeamScenarioSchema.parse({
        id: existing.id,
        clientId: existing.clientId,
        createdBy: existing.createdBy,
        createdAt: existing.createdAt,
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
        summary: `Red-team scenario updated: ${saved.name} (v${existing.version}→v${saved.version}, enabled=${saved.enabled})${wasAuthorized ? " — prior live-run authorization invalidated by this edit" : ""}`,
        metadata: {
          category: saved.category,
          stepCount: saved.steps.length,
          targetHost: hostOf(saved.targetAllowlistRef),
          enabled: saved.enabled,
          fromVersion: existing.version,
          toVersion: saved.version,
          liveAuthorizationInvalidated: wasAuthorized,
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

  // ⛔ A1 — WRITTEN authorization for real worker-side live execution.
  // Approver-only (hard guard); mirrors dast.ts's POST /dast/targets/:id/
  // authorize pattern but REQUIRES a free-text authorizationReference (that
  // flow never captured one) and binds the grant to the scenario's exact
  // CURRENT version — any subsequent edit (PUT) invalidates it outright.
  // This does NOT itself run anything; it only makes the scenario eligible
  // for POST /scenarios/:id/run to enqueue real worker-side execution.
  app.post(
    "/scenarios/:id/authorize",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["scenarios"],
        summary: "Record written authorization for real live-run execution (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const existing = await store.redTeamScenarios.get(user.clientId, id);
      if (!existing) throw notFound("Scenario not found");
      const body = parseBody(AuthorizeScenarioBodySchema, req);

      const authorized: RedTeamScenario = RedTeamScenarioSchema.parse({
        ...existing,
        liveAuthorizedById: user.id,
        liveAuthorizationReference: body.authorizationReference,
        liveAuthorizedAt: deps.clock.now().toISOString(),
        liveAuthorizedForVersion: existing.version,
      });
      const saved = await store.redTeamScenarios.update(user.clientId, authorized);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "scenario.authorized",
        targetType: "red_team_scenario",
        targetId: saved.id,
        summary: `Written live-run authorization recorded for scenario "${saved.name}" (v${saved.version}) by approver ${user.id}`,
        metadata: {
          targetHost: hostOf(saved.targetAllowlistRef),
          version: saved.version,
          authorizationReference: saved.liveAuthorizationReference,
        },
      });

      return { scenario: saved };
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

      // ⛔ A1 — THE WRITTEN-AUTHORIZATION GATE. Additive on top of every gate
      // above (never a replacement for RBAC/allowlist/production-block) and
      // checked BEFORE anything else runs: a scenario missing a complete,
      // CURRENT-version authorization is refused outright — a clear, honest
      // 403, never a silent no-op and never a fallback to gate-only mode.
      if (!hasLiveRunAuthorization(scenario)) {
        const reason = writtenAuthorizationGapReason(scenario);
        await recordAudit(store, {
          clientId: user.clientId,
          actor: actorFromUser(user),
          action: "scenario.live_run_rejected",
          targetType: "red_team_scenario",
          targetId: scenario.id,
          summary: `Red-team scenario run refused (no valid written authorization): ${scenario.name}`,
          metadata: {
            category: scenario.category,
            targetHost: hostOf(scenario.targetAllowlistRef),
            version: scenario.version,
            liveAuthorizedForVersion: scenario.liveAuthorizedForVersion ?? null,
            reason,
          },
        });
        throw forbidden(reason);
      }

      const body = parseBody(RunScenarioBodySchema, req);

      // Gate-only preview (unchanged from before A1): `requireApprover`
      // already enforced the approver role at the HTTP layer ⇒ allowLive=true;
      // the Layer-3 gate still independently checks dast.enabled + allowlist +
      // production. A non-allowlisted / production target throws
      // DastTargetNotAllowlistedError (→ 403) before any probe. No transport
      // ⇒ authorize + gate-check every step, send nothing — this route still
      // NEVER probes from the API process itself.
      const result = await runScenario(
        {
          scenario,
          config,
          allowLive: true,
          ...(body?.target ? { targetOverride: body.target } : {}),
        },
        {},
      );

      // ⛔ Audit the authorized preview (golden rule #7). Never store the steps.
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

      // ⛔ A1 — NOW enqueue REAL worker-side execution (apps/worker/src/
      // scenario-runs), reached ONLY after every gate above (RBAC, disabled
      // check, config invariants, AND the new written-authorization gate)
      // passed. No target override — real execution always runs against the
      // scenario's authorized `targetAllowlistRef`, never an ad hoc override
      // (the override above is a gate-only preview convenience only).
      const requestedAt = deps.clock.now().toISOString();
      const job: ScenarioRunJob = {
        scenarioId: scenario.id,
        clientId: user.clientId,
        requestedById: user.id,
        requestedAt,
      };
      const jobId = await deps.scenarioRunProducer.enqueue(job);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "scenario.live_run_enqueued",
        targetType: "red_team_scenario",
        targetId: scenario.id,
        summary: `Real worker-side execution enqueued for scenario "${scenario.name}" (job ${jobId})`,
        metadata: {
          jobId,
          targetHost: hostOf(scenario.targetAllowlistRef),
          version: scenario.version,
          authorizedById: scenario.liveAuthorizedById,
          authorizationReference: scenario.liveAuthorizationReference,
        },
      });

      return {
        run: result,
        liveExecution: { enqueued: true, jobId },
      };
    },
  );
}
