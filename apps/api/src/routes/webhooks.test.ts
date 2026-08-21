/**
 * POST /webhooks/scan-trigger (A15) — provider-agnostic, HMAC-verified scan
 * trigger. Covers: disabled-by-default (503) when `deps.webhook` is unset,
 * signature verification (missing/invalid header rejected, valid header
 * accepted), payload validation, misconfigured-operator handling, and that a
 * valid request calls the orchestrator's real `createScan` + `start` (mirrors
 * `POST /scans`) and is client-scoped to `deps.config.clientId`.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import type { CreateScanInput } from "@montr/orchestrator";
import type { Scan } from "@montr/contracts";
import { buildServer, createInMemoryDeps } from "../server.js";
import { signWebhookPayload, WEBHOOK_SIGNATURE_HEADER } from "../auth/webhook-signature.js";

const PASSWORD = "correct-horse-battery-staple"; // >= 12 chars (PasswordSchema)
const SECRET = "webhook-secret-at-least-this-long";
const OPERATOR_EMAIL = "webhook-operator@example.internal";

async function registerBootstrapUser(app: FastifyInstance, email: string): Promise<void> {
  // First registration for a fresh client is auto-granted `approver` (see
  // apps/api/src/routes/auth.ts) — qualifies as a webhook operator account.
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/register",
    payload: { email, password: PASSWORD },
  });
  expect(res.statusCode).toBe(201);
}

function sign(body: string): string {
  return signWebhookPayload(SECRET, body);
}

async function post(
  app: FastifyInstance,
  body: string,
  headers: Record<string, string> = {},
): Promise<{ statusCode: number; json: () => unknown }> {
  return app.inject({
    method: "POST",
    url: "/api/v1/webhooks/scan-trigger",
    payload: body,
    headers: { "content-type": "application/json", ...headers },
  });
}

const VALID_PAYLOAD = JSON.stringify({
  repo: "acme/webhook-app",
  branch: "feature/x",
  mode: "diff",
  scope: { changedFiles: ["src/index.ts"] },
});

describe("POST /webhooks/scan-trigger", () => {
  describe("when webhook trigger is not configured (default)", () => {
    let app: FastifyInstance;

    beforeAll(async () => {
      const deps = createInMemoryDeps();
      app = await buildServer(deps);
    });
    afterAll(async () => {
      await app.close();
    });

    it("503s regardless of signature", async () => {
      const res = await post(app, VALID_PAYLOAD, {
        [WEBHOOK_SIGNATURE_HEADER]: sign(VALID_PAYLOAD),
      });
      expect(res.statusCode).toBe(503);
      const body = res.json() as { error: { code: string } };
      expect(body.error.code).toBe("WEBHOOK_NOT_CONFIGURED");
    });
  });

  describe("when configured", () => {
    let app: FastifyInstance;
    let deps: ReturnType<typeof createInMemoryDeps>;
    let createScanSpy: ReturnType<typeof vi.fn>;
    let startSpy: ReturnType<typeof vi.fn>;

    beforeAll(async () => {
      deps = createInMemoryDeps({
        webhook: { secret: SECRET, operatorEmail: OPERATOR_EMAIL },
      });
      const realCreateScan = deps.orchestrator.createScan.bind(deps.orchestrator);
      const realStart = deps.orchestrator.start.bind(deps.orchestrator);
      createScanSpy = vi.fn((input: CreateScanInput) => realCreateScan(input));
      startSpy = vi.fn((id: string) => realStart(id));
      deps.orchestrator = { ...deps.orchestrator, createScan: createScanSpy, start: startSpy };

      app = await buildServer(deps);
      await registerBootstrapUser(app, OPERATOR_EMAIL);
    });
    afterAll(async () => {
      await app.close();
    });

    it("401s with no signature header", async () => {
      const res = await post(app, VALID_PAYLOAD);
      expect(res.statusCode).toBe(401);
      expect(createScanSpy).not.toHaveBeenCalled();
    });

    it("401s with a wrong signature", async () => {
      const res = await post(app, VALID_PAYLOAD, {
        [WEBHOOK_SIGNATURE_HEADER]: "sha256=" + "0".repeat(64),
      });
      expect(res.statusCode).toBe(401);
      expect(createScanSpy).not.toHaveBeenCalled();
    });

    it("401s when the signature was computed over a DIFFERENT body than the one sent", async () => {
      const otherBody = JSON.stringify({ repo: "acme/other", branch: "main", mode: "full" });
      const res = await post(app, VALID_PAYLOAD, {
        [WEBHOOK_SIGNATURE_HEADER]: sign(otherBody),
      });
      expect(res.statusCode).toBe(401);
      expect(createScanSpy).not.toHaveBeenCalled();
    });

    it("400s on an invalid payload (missing repo) even with a valid signature", async () => {
      const body = JSON.stringify({ branch: "main" });
      const res = await post(app, body, { [WEBHOOK_SIGNATURE_HEADER]: sign(body) });
      expect(res.statusCode).toBe(400);
      expect(createScanSpy).not.toHaveBeenCalled();
    });

    it("accepts a validly-signed payload, creates + starts a scan via the real orchestrator, and audits it", async () => {
      const res = await post(app, VALID_PAYLOAD, {
        [WEBHOOK_SIGNATURE_HEADER]: sign(VALID_PAYLOAD),
      });
      expect(res.statusCode).toBe(202);
      const { scan } = res.json() as { scan: Scan };
      expect(scan.repo).toBe("acme/webhook-app");
      expect(scan.branch).toBe("feature/x");
      expect(scan.mode).toBe("diff");
      expect(scan.status).toBe("running"); // start() was called, not just createScan()
      expect(scan.clientId).toBe(deps.config.clientId);
      expect(scan.scope.changedFiles).toEqual(["src/index.ts"]);

      expect(createScanSpy).toHaveBeenCalledTimes(1);
      expect(startSpy).toHaveBeenCalledTimes(1);
      const input = createScanSpy.mock.calls[0]?.[0] as CreateScanInput;
      expect(input.clientId).toBe(deps.config.clientId);
      expect(input.operator).toBeTruthy();

      const audit = await deps.store.audit.list(deps.config.clientId, { scanId: scan.id });
      expect(audit.some((e) => e.action === "scan.created" && e.actor.type === "system")).toBe(
        true,
      );
    });
  });

  describe("when the configured operator account does not exist", () => {
    let app: FastifyInstance;

    beforeAll(async () => {
      const deps = createInMemoryDeps({
        webhook: { secret: SECRET, operatorEmail: "nobody@example.internal" },
      });
      app = await buildServer(deps);
    });
    afterAll(async () => {
      await app.close();
    });

    it("503s (misconfigured) instead of creating a scan with no valid operator", async () => {
      const res = await post(app, VALID_PAYLOAD, {
        [WEBHOOK_SIGNATURE_HEADER]: sign(VALID_PAYLOAD),
      });
      expect(res.statusCode).toBe(503);
      const body = res.json() as { error: { code: string } };
      expect(body.error.code).toBe("WEBHOOK_MISCONFIGURED");
    });
  });
});
