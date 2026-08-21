/**
 * Provider-agnostic scan-trigger webhook (A15 — "trigger surface for
 * autonomous operation"). `POST /webhooks/scan-trigger` accepts a
 * repo/branch/commit payload, verifies an HMAC signature, and creates +
 * starts a scan through the SAME `orchestrator.createScan`/`start` path
 * `POST /scans` already uses — this is what makes "PR opened -> scan runs"
 * possible today, wired to a plain GitHub Actions workflow step (or any
 * webhook-capable CI) rather than a full GitHub App (manifest registration +
 * OAuth installation flow is explicitly out of scope — see
 * docs/plan/26-08-22-tasks-ai-depth.md A15).
 *
 * Unauthenticated by session (no JWT/cookie — the caller is CI, not a
 * browser); authenticity comes entirely from the HMAC signature over the raw
 * body (../auth/webhook-signature.ts), verified in constant time. There is
 * no bearer/cookie principal to attribute the resulting scan to, but
 * `Scan.operator` has a required FK to `User` (packages/state-store/prisma/
 * schema.prisma), so the deployment must name an existing operator/approver
 * account via `deps.webhook.operatorEmail` (`MONTR_WEBHOOK_OPERATOR_EMAIL`) —
 * every webhook-triggered scan is attributed to that account and audited as
 * such. Unset `deps.webhook` (the default) disables this route entirely
 * (503) — consistent with every other hardened-off-by-default control in
 * this codebase (auto-fix, DAST, telemetry).
 */
import { z } from "zod";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { ScanModeSchema, ScanScopeSchema } from "@montr/contracts";
import type { CreateScanInput } from "@montr/orchestrator";
import { postGitHubComment } from "@montr/report";
import { HttpError, badRequest, unauthorized } from "../errors.js";
import { recordAudit } from "../audit.js";
import { WEBHOOK_SIGNATURE_HEADER, verifyWebhookSignature } from "../auth/webhook-signature.js";
import type { ResolvedDeps } from "../types.js";

/** Raw-body-preserving JSON parse result (see the content-type parser below). */
interface RawJsonBody {
  raw: Buffer;
  json: unknown;
}

/**
 * Request body contract. `repo`/`branch` mirror `POST /scans`
 * (`CreateScanBodySchema`, ../schemas.ts); `scope` reuses the same
 * `ScanScopeSchema` diff-mode fields `packages/appmap/src/diff.ts` and the
 * scan-creation API already expect (`changedFiles` — the CLI (apps/cli)
 * populates the identical field for local `montr scan --mode diff`).
 * `pullRequest` is optional and, when present with `deps.webhook.githubToken`
 * configured, triggers a best-effort PR summary comment (A15 §3).
 */
const ScanTriggerWebhookBodySchema = z.object({
  repo: z.string().min(1),
  branch: z.string().min(1).default("main"),
  mode: ScanModeSchema.default("diff"),
  scope: ScanScopeSchema.partial().optional(),
  pullRequest: z
    .object({
      owner: z.string().min(1),
      repo: z.string().min(1),
      number: z.number().int().positive(),
    })
    .optional(),
});
type ScanTriggerWebhookBody = z.infer<typeof ScanTriggerWebhookBodySchema>;

function parseRawWebhookBody(req: FastifyRequest): RawJsonBody {
  const body = req.body as RawJsonBody | undefined;
  if (!body || !Buffer.isBuffer(body.raw)) {
    // The content-type parser below always produces this shape for
    // application/json; any other content-type is rejected by Fastify
    // before the handler runs, so this is a defensive, not reachable-in-
    // practice, guard.
    throw badRequest("Expected a JSON body");
  }
  return body;
}

export function registerWebhookRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  // Isolated child encapsulation context: the custom content-type parser
  // below MUST see the exact raw bytes GitHub (or any signer) computed the
  // HMAC over — Fastify's default JSON parser discards them. Registering it
  // inside this nested `app.register` scopes it to ONLY this route; every
  // other route in the app keeps the default JSON body parser untouched.
  void app.register(async (scope) => {
    scope.addContentTypeParser("application/json", { parseAs: "buffer" }, (_req, body, done) => {
      const raw = body as Buffer;
      try {
        done(null, { raw, json: JSON.parse(raw.toString("utf8")) } satisfies RawJsonBody);
      } catch (err) {
        done(err as Error, undefined);
      }
    });

    scope.post(
      "/webhooks/scan-trigger",
      {
        schema: {
          tags: ["webhooks"],
          summary:
            "Provider-agnostic scan trigger: HMAC-verified webhook that creates + starts a scan",
        },
      },
      async (req, reply) => {
        const wh = deps.webhook;
        if (!wh) {
          throw new HttpError(
            503,
            "WEBHOOK_NOT_CONFIGURED",
            "Webhook scan trigger is not configured on this deployment " +
              "(set MONTR_WEBHOOK_SECRET and MONTR_WEBHOOK_OPERATOR_EMAIL)",
          );
        }

        const { raw, json } = parseRawWebhookBody(req);
        const header = req.headers[WEBHOOK_SIGNATURE_HEADER];
        if (!verifyWebhookSignature(wh.secret, raw, header)) {
          throw unauthorized("Invalid webhook signature");
        }

        const parsed = ScanTriggerWebhookBodySchema.safeParse(json);
        if (!parsed.success) {
          throw badRequest("Invalid webhook payload", { issues: parsed.error.issues });
        }
        const input: ScanTriggerWebhookBody = parsed.data;

        const clientId = deps.config.clientId;
        const operatorUser = await deps.store.users.findByEmail(clientId, wh.operatorEmail);
        if (
          !operatorUser ||
          (operatorUser.role !== "operator" && operatorUser.role !== "approver")
        ) {
          throw new HttpError(
            503,
            "WEBHOOK_MISCONFIGURED",
            "The configured webhook operator account is missing or lacks the " +
              "operator/approver role required to create scans",
          );
        }

        const scope2 = ScanScopeSchema.parse({
          ...(input.scope ?? {}),
          mode: input.mode,
        });
        const scanInput: CreateScanInput = {
          clientId,
          repo: input.repo,
          branch: input.branch,
          mode: input.mode,
          scope: scope2,
          operator: operatorUser.id,
        };

        const scan = await deps.orchestrator.createScan(scanInput);
        // Mirror POST /scans (scans.ts): createScan() alone only persists a
        // "queued" row — start() is what actually enqueues Layer 0.
        await deps.orchestrator.start(scan.id);

        await recordAudit(deps.store, {
          clientId,
          scanId: scan.id,
          actor: { type: "system", id: "webhook:scan-trigger" },
          action: "scan.created",
          targetType: "scan",
          targetId: scan.id,
          summary: `Scan created via webhook for ${input.repo}@${input.branch} (${input.mode})`,
          metadata: {
            repo: input.repo,
            branch: input.branch,
            mode: input.mode,
            source: "webhook",
            ...(input.pullRequest ? { pullRequest: input.pullRequest } : {}),
          },
        });

        // A15 §3 — PR-annotation reuse (scoped down, see module doc comment):
        // best-effort single summary comment acknowledging the triggered
        // scan. Posting the CONFIRMED-findings summary itself would require
        // apps/worker's Layer 5 to know the originating PR (owner/repo/
        // number is not yet a persisted Scan field) and post a follow-up
        // comment when the report is ready — that plumbing is deferred, not
        // built here (see A15 task notes). This never blocks or fails scan
        // creation: a comment-post failure is logged, not thrown.
        if (wh.githubToken && input.pullRequest) {
          try {
            await postGitHubComment({
              token: wh.githubToken,
              owner: input.pullRequest.owner,
              repo: input.pullRequest.repo,
              issueNumber: input.pullRequest.number,
              body:
                `🛡️ **Montr Secure** — ${input.mode}-mode scan \`${scan.id}\` triggered for this PR.\n\n` +
                `Findings are not posted automatically yet (tracked, A15) — check the ` +
                `operator console or \`GET /api/v1/scans/${scan.id}/report\` once the scan completes.`,
              logger: deps.logger,
            });
          } catch (err) {
            deps.logger.warn("webhook.pr_comment_failed", {
              scanId: scan.id,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        reply.status(202);
        return { scan: await deps.orchestrator.status(scan.id) };
      },
    );
  });
}
