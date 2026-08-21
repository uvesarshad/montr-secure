/**
 * §15 cross-scan memory (E8) — explicit operator-facing write path.
 *
 * Generalizes A10's §15 false-positive feedback loop (see findings.ts's
 * `POST /findings/:id/false-positive`) to a broader class of durable,
 * per-repo learned facts: custom sanitizer names, framework idioms, and
 * explicit operator decisions. A fact recorded here is read back by
 * apps/worker/src/runners.ts's `loadLearnedFactsContext` on every LATER scan
 * of the same `(clientId, repo)` and appended as additive context to that
 * scan's Layer 1/2/3 LLM prompts — it can never suppress or override a
 * finding on its own (golden rule #4); it only gives the model more context.
 *
 * `confirmed_false_positive` facts are NOT recorded through this route —
 * that class already has its own authoritative path
 * (`finding.marked_false_positive` audit events via
 * `POST /findings/:id/false-positive`) and is merged in at read time instead
 * of duplicated (see LearnedFactType's schema.prisma doc comment).
 */
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { unauthorized } from "../errors.js";
import { parseBody, parseQuery } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { RecordLearnedFactBodySchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

const ListLearnedFactsQuerySchema = z.object({
  repo: z.string().min(1).max(500),
  limit: z.coerce.number().int().positive().max(50).optional(),
});

export function registerLearnedFactRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  // Any authenticated role may read back this client's accumulated facts
  // (informational, read-only) — matches the read-permissiveness of
  // GET /scans/:id/findings above.
  app.get(
    "/learned-facts",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["learned-facts"],
        summary: "This client's accumulated learned facts for a repo (§15 cross-scan memory, E8)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const query = parseQuery(ListLearnedFactsQuerySchema, req);
      const facts = await store.learnedFacts.listByRepo(user.clientId, query.repo, query.limit);
      return { facts };
    },
  );

  // Operators and approvers may record facts; viewers may not (mirrors
  // findings.ts's false-positive marking route's role gate).
  app.post(
    "/learned-facts",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["learned-facts"],
        summary: "Record a durable learned fact about a repo (§15 cross-scan memory, E8)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(RecordLearnedFactBodySchema, req);

      const recordedAt = deps.clock.now().toISOString();
      const fact = await store.learnedFacts.record({
        clientId: user.clientId,
        repo: body.repo,
        type: body.type,
        content: body.content,
        provenance: { source: "operator", operatorId: user.id, at: recordedAt },
      });

      // Audit FIRST-class (§8.5, golden rule #7) — metadata only, mirrors
      // findings.ts's false-positive audit write. Best-effort is NOT
      // appropriate here (unlike the FP route's regression-corpus write):
      // this audit event has no independent corpus fallback, so a failure
      // here should fail the mutation rather than silently under-record it.
      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "learned_fact.recorded",
        targetType: "learned_fact",
        targetId: fact.id,
        summary: `Learned fact recorded for ${body.repo} (${body.type})`,
        metadata: { repo: body.repo, type: body.type, factId: fact.id },
      });

      return { ok: true, fact };
    },
  );
}
