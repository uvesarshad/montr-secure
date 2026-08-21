#!/usr/bin/env node
/**
 * apps/worker process entrypoint (deploy/docker/Dockerfile.worker `CMD ["dist/main.js"]`).
 *
 * Builds real production deps — env-driven @montr/config, a real Postgres
 * StateStore (@montr/state-store), and the real BYO-key LLM gateway
 * (@montr/llm-gateway, golden rule #2) — and brings up the durable BullMQ
 * worker (`startWorker`, see ./index.ts). Handles SIGTERM/SIGINT: stop
 * consuming new jobs, let in-flight layer work finish, then close the
 * Postgres/Redis connections before exiting.
 */
import { loadConfig, resolveFieldEncryptionKey } from "@montr/config";
import { createLogger } from "@montr/telemetry";
import { createLlmGateway } from "@montr/llm-gateway";
import { createBudgetRegistry } from "@montr/cost-meter";
import {
  createPrismaClient,
  createStateStoreFromClient,
  type StateStore,
} from "@montr/state-store";

import {
  startWorker,
  reconcileStuckScans,
  DEFAULT_STUCK_SCAN_THRESHOLD_MS,
  type WorkerRuntimeDeps,
} from "./index.js";

/** Max time to wait for the in-flight job (if any) to finish on shutdown. */
const SHUTDOWN_TIMEOUT_MS = Number(process.env["SHUTDOWN_TIMEOUT_MS"] ?? 30_000);

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}. apps/worker needs it — see deploy/docker/.env.example.`,
    );
  }
  return value;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger({ name: "montr-worker", bindings: { clientId: config.clientId } });

  const databaseUrl = requireEnv("DATABASE_URL");
  const redisUrl = process.env["REDIS_URL"] ?? "redis://redis:6379";

  const prisma = createPrismaClient({ databaseUrl });
  // See apps/api/src/production-deps.ts for why: every row has a required FK
  // to Client, and config.clientId IS the tenant identity for an on-prem,
  // single-tenant deploy. Idempotent upsert so it's safe regardless of
  // whether apps/api or apps/worker boots first.
  await prisma.client.upsert({
    where: { id: config.clientId },
    update: {},
    create: { id: config.clientId, name: config.clientId },
  });
  // Goes through the pluggable KeySource (env/file/vault, packages/config/src/
  // key-source.ts) rather than reading fieldEncryptionKeyRef directly, so
  // security.keySource = "vault" actually resolves real key bytes from Vault
  // here instead of silently falling back to an unset ref (A10).
  const fieldEncryptionKey = await resolveFieldEncryptionKey(config);
  const store: StateStore = createStateStoreFromClient(prisma, {
    ...(fieldEncryptionKey ? { fieldEncryptionKey } : {}),
    ownsClient: true,
  });

  // ⛔ PRE-call budget guard (A2, DECIDE-4). One registry, shared by the
  // gateway (reads it per call, keyed by `request.metadata.scanId`) and the
  // orchestrator (registers each running scan's live meter + ceiling the
  // moment a layer starts). Additive to the orchestrator's own between-layers
  // `enforceBudget` — this one stops a single call before it reaches the wire.
  const budgetRegistry = createBudgetRegistry();

  // ⛔ The one LLM egress path (golden rule #2). BYO-key, sourced from
  // @montr/config (MONTR_LLM_* env vars — see deploy/docker/.env.example).
  // `promptSource` (§8.2, §15) lets the gateway resolve a versioned prompt
  // from the DB via `store.promptVersions`; with none active yet it falls
  // back to each caller's hardcoded template, unchanged.
  const gateway = createLlmGateway({
    config,
    logger,
    promptSource: store.promptVersions,
    budgetRegistry,
  });

  const runtimeDeps: WorkerRuntimeDeps = {
    store,
    gateway,
    redis: redisUrl,
    logger,
    budgetRegistry,
    ...(process.env["MONTR_WORKSPACE_DIR"]
      ? { runnerOptions: { workspaceRoot: process.env["MONTR_WORKSPACE_DIR"] } }
      : {}),
  };

  // Constructing the worker asserts the ⛔ egress boot guard (golden rule #1)
  // before anything else runs — see startWorker()'s doc comment in ./index.ts.
  const worker = startWorker(config, runtimeDeps);
  await worker.start();
  logger.info("worker.process.started", { redisUrl: redisUrl.replace(/:\/\/[^@]*@/, "://***@") });

  // A3 (§8.1) boot-time reconciliation: find scans a crashed worker parked as
  // `running` forever and resume() them from their last persisted checkpoint.
  // Best-effort by design (reconcileStuckScans never throws) — a reconciliation
  // hiccup must not prevent this worker from coming up and consuming new jobs.
  const stuckScanThresholdMs = Number(
    process.env["MONTR_STUCK_SCAN_THRESHOLD_MS"] ?? DEFAULT_STUCK_SCAN_THRESHOLD_MS,
  );
  await reconcileStuckScans({
    store,
    orchestrator: worker.orchestrator,
    clientId: config.clientId,
    logger,
    thresholdMs: stuckScanThresholdMs,
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("worker.shutdown.start", { signal });

    const timeout = setTimeout(() => {
      logger.error("worker.shutdown.timeout", { timeoutMs: SHUTDOWN_TIMEOUT_MS });
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
    timeout.unref();

    void (async () => {
      try {
        // Stop consuming new jobs / let the in-flight one finish, then release
        // the Postgres + Redis connections.
        await worker.stop();
        await store.disconnect();
        clearTimeout(timeout);
        logger.info("worker.shutdown.complete", { signal });
        process.exit(0);
      } catch (err) {
        clearTimeout(timeout);
        logger.error("worker.shutdown.error", { signal, error: String(err) });
        process.exit(1);
      }
    })();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err: unknown) => {
  console.error("apps/worker fatal startup error:", err);
  process.exit(1);
});
