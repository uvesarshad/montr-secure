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
import { loadConfig } from "@montr/config";
import { createLogger } from "@montr/telemetry";
import { createLlmGateway } from "@montr/llm-gateway";
import {
  createPrismaClient,
  createStateStoreFromClient,
  type StateStore,
} from "@montr/state-store";

import { startWorker, type WorkerRuntimeDeps } from "./index.js";

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
  const store: StateStore = createStateStoreFromClient(prisma, {
    ...(config.security.fieldEncryptionKeyRef
      ? { fieldEncryptionKey: config.security.fieldEncryptionKeyRef }
      : {}),
    ownsClient: true,
  });

  // ⛔ The one LLM egress path (golden rule #2). BYO-key, sourced from
  // @montr/config (MONTR_LLM_* env vars — see deploy/docker/.env.example).
  // `promptSource` (§8.2, §15) lets the gateway resolve a versioned prompt
  // from the DB via `store.promptVersions`; with none active yet it falls
  // back to each caller's hardcoded template, unchanged.
  const gateway = createLlmGateway({ config, logger, promptSource: store.promptVersions });

  const runtimeDeps: WorkerRuntimeDeps = {
    store,
    gateway,
    redis: redisUrl,
    logger,
    ...(process.env["MONTR_WORKSPACE_DIR"]
      ? { runnerOptions: { workspaceRoot: process.env["MONTR_WORKSPACE_DIR"] } }
      : {}),
  };

  // Constructing the worker asserts the ⛔ egress boot guard (golden rule #1)
  // before anything else runs — see startWorker()'s doc comment in ./index.ts.
  const worker = startWorker(config, runtimeDeps);
  await worker.start();
  logger.info("worker.process.started", { redisUrl: redisUrl.replace(/:\/\/[^@]*@/, "://***@") });

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
