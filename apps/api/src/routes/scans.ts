/**
 * Scan lifecycle routes: create / list / get / status / cancel / resume / kill,
 * plus scan-scoped reads (progress, App Map).
 * Mutations call the orchestrator's lifecycle API and are bound to audit events.
 * Reads are client-scoped (per-client isolation — never cross-tenant).
 */
import type { FastifyInstance } from "fastify";
import { ScanScopeSchema, type PipelineEvent, type ProgressEvent } from "@montr/contracts";
import type { CreateScanInput, Orchestrator } from "@montr/orchestrator";
import { notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { CreateScanBodySchema, KillScanBodySchema, ScanIdParamsSchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

/**
 * Map one pipeline lifecycle event onto the narrower `ProgressEvent` shape the
 * web console's `useProgress` poll + `deriveLayerProgress`/`LayerProgress`
 * consume (A5.1). Only the events that carry a single `layer` + an in-layer
 * completion signal are meaningful here: "progress" (an in-layer %) passes
 * through as-is, and the "layer_started"/"layer_completed" boundaries are
 * synthesized into pct 0 / pct 100 so a layer that finished without ever
 * emitting an intermediate "progress" tick still reads as "done", not stuck at
 * 0%. Every other lifecycle event (scan-level, gate, budget, kill) is dropped —
 * the console already reads those off `scan.status`/`scan.gateState` via
 * `GET /scans/:id/status`, not the progress stream.
 */
function toProgressEvent(event: PipelineEvent): ProgressEvent | null {
  switch (event.type) {
    case "progress":
      return {
        scanId: event.scanId,
        layer: event.layer,
        phase: event.phase,
        pct: event.pct,
        at: event.at,
      };
    case "layer_started":
      return { scanId: event.scanId, layer: event.layer, phase: "started", pct: 0, at: event.at };
    case "layer_completed":
      return {
        scanId: event.scanId,
        layer: event.layer,
        phase: "completed",
        pct: 100,
        at: event.at,
      };
    default:
      return null;
  }
}

/**
 * Drain the orchestrator's replay-then-live event stream (`Orchestrator.events`,
 * backed by `EventBus.subscribe` — replay-then-live: full history so far, then
 * live) WITHOUT waiting on the live tail. This backs a polled GET (the web
 * console polls every 4s — `apps/web/src/lib/api/hooks.ts` `useProgress`), not
 * a persistent stream, so it must return promptly with whatever has already
 * happened rather than hang until the next event.
 *
 * Races each `next()` call against an already-resolved sentinel: while
 * buffered history remains, `EventBus.subscribe`'s `next()` resolves without
 * ever hitting an `await` (see packages/orchestrator/src/events.ts), so it
 * settles in the same microtask turn as the sentinel and — because it was
 * passed to `Promise.race` first — wins deterministically. Once the iterator
 * would have to wait for a future event, only the sentinel is settled, so it
 * wins and the drain stops there.
 */
async function drainProgress(orchestrator: Orchestrator, scanId: string): Promise<ProgressEvent[]> {
  const iterator = orchestrator.events(scanId)[Symbol.asyncIterator]();
  const STOP = Symbol("progress.drain.stop");
  const out: ProgressEvent[] = [];
  for (;;) {
    const race = await Promise.race([iterator.next(), Promise.resolve(STOP)]);
    if (race === STOP) break;
    const result = race as IteratorResult<PipelineEvent>;
    if (result.done) break;
    const mapped = toProgressEvent(result.value);
    if (mapped) out.push(mapped);
  }
  return out;
}

export function registerScanRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store, orchestrator, clock } = deps;

  app.post(
    "/scans",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "Create a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(CreateScanBodySchema, req);

      const scope = ScanScopeSchema.parse({ ...(body.scope ?? {}), mode: body.mode });
      const input: CreateScanInput = {
        clientId: user.clientId,
        repo: body.repo,
        branch: body.branch,
        mode: body.mode,
        scope,
        operator: user.id,
        ...(body.budgetPolicy ? { budgetPolicy: body.budgetPolicy } : {}),
      };

      const scan = await orchestrator.createScan(input);
      // createScan only persists the "queued" row — start() is what actually
      // transitions to "running" and enqueues Layer 0. Every real caller
      // (see tests/orchestrator.pipeline.test.ts) always pairs the two; the
      // HTTP route must too, or a created scan just sits queued forever.
      await orchestrator.start(scan.id);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: scan.id,
        actor: actorFromUser(user),
        action: "scan.created",
        targetType: "scan",
        targetId: scan.id,
        summary: `Scan created for ${body.repo}@${body.branch} (${body.mode})`,
        metadata: { repo: body.repo, branch: body.branch, mode: body.mode },
      });

      reply.status(201);
      // Re-fetch: `scan` above is the pre-start "queued" snapshot; start()
      // mutates status to "running" in the store, so return the current row.
      return { scan: await orchestrator.status(scan.id) };
    },
  );

  app.get(
    "/scans",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "List scans for the client",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const scans = await store.scans.list(user.clientId);
      return { scans };
    },
  );

  app.get(
    "/scans/:id",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "Get a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);
      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");
      return { scan };
    },
  );

  app.get(
    "/scans/:id/status",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "Scan status + gate state",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      let scan;
      try {
        scan = await orchestrator.status(id);
      } catch {
        throw notFound("Scan not found");
      }
      // Enforce per-client isolation — the lifecycle API is not tenant-scoped.
      if (scan.clientId !== user.clientId) throw notFound("Scan not found");

      return {
        scanId: scan.id,
        status: scan.status,
        gateState: scan.gateState,
        costEstimate: scan.costEstimate ?? null,
        costActual: scan.costActual ?? null,
      };
    },
  );

  // A5.1 — polled layer-progress snapshot. Returns a plain `ProgressEvent[]`
  // (no `{ progress: [...] }` wrapper) to match the existing client contract
  // (apps/web/src/lib/api/client.ts `getProgress`, polled every 4s).
  app.get(
    "/scans/:id/progress",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "Polled layer-progress snapshot",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      return drainProgress(orchestrator, id);
    },
  );

  // A5.2 — the scan's App Map (Layer 0 output). Returns the bare `AppMap` (no
  // wrapper) to match the existing client contract (`getAppMap`).
  app.get(
    "/scans/:id/appmap",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "Retrieve the App Map built for a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");
      if (!scan.appMapId) throw notFound("App Map not available for this scan yet");

      const appMap = await store.appMaps.get(user.clientId, scan.appMapId);
      if (!appMap) throw notFound("App Map not available for this scan yet");

      return appMap;
    },
  );

  app.post(
    "/scans/:id/cancel",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "Cancel a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.cancel(id);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "scan.cancelled",
        targetType: "scan",
        targetId: id,
        summary: `Scan ${id} cancelled`,
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );

  // A3 (§8.1) — resume a scan a crashed worker parked as `running` forever, or
  // one `failScan` marked `failed` after a redelivered layer job (see
  // FindingRepo.bulkCreate's skipDuplicates fix, packages/state-store). Calls
  // the orchestrator's real `resume(scanId)`, which correctly skips finished
  // layers via the persisted ResumeToken checkpoint and re-checks gate state —
  // it never bypasses a pending estimate/fix gate and never re-runs a
  // completed layer. A `completed`/`cancelled` scan is a no-op inside the
  // orchestrator (mirrors the terminal-state guard `cancel`/`kill` rely on);
  // apps/worker also calls this same method automatically at boot (A3.2) — this
  // route is the operator-triggered counterpart.
  app.post(
    "/scans/:id/resume",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "Resume a stuck or failed scan from its last checkpoint",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.resume(id);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "scan.resumed",
        targetType: "scan",
        targetId: id,
        summary: `Scan ${id} resume requested`,
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );

  // ⛔ Kill switch — halts all active work for this scan immediately (esp. live
  // DAST probing), via the orchestrator's cross-process kill (Redis pub/sub +
  // AbortController, §11). Same role bar as cancel/create: operator or approver
  // (mirrors apps/web's canActivateKillSwitch) — a kill switch must stay easy to
  // reach for whoever is running the scan, not gated behind approver-only, which
  // is why this uses `requireRole` (not the hard `requireApprover` guard used
  // by the fix gate / DAST authorization routes).
  app.post(
    "/scans/:id/kill",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "⛔ Kill switch — halt a scan immediately",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);
      const body = parseBody(KillScanBodySchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.kill({
        scope: "scan",
        scanId: id,
        reason: body.reason,
        requestedBy: user.id,
        requestedByRole: user.role,
        at: clock.now().toISOString(),
      });

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "dast.kill_switch",
        targetType: "scan",
        targetId: id,
        summary: `Kill switch activated for scan ${id}: ${body.reason}`,
        metadata: { reason: body.reason },
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );
}
