/**
 * apps/worker composition root — the durable pipeline host (build-plan §8.1).
 *
 * Wires the REAL runtime collaborators from environment config and starts the
 * BullMQ worker that consumes every layer job (this is the ONLY process with the
 * scanners + git, so it runs the whole L0→L5 pipeline). apps/api is a produce-only
 * peer that enqueues + controls scans over the same Redis.
 *
 * Boot order: run DB migrations (idempotent) → build the encrypted Postgres store
 * + BYO-key gateway → `startWorker().start()` (asserts the default-deny egress
 * policy first, golden rule #1). SIGTERM/SIGINT drain the queues + disconnect.
 */
import { loadConfig } from "@montr/config";
import { createStateStore } from "@montr/state-store";
import { createLlmGateway } from "@montr/llm-gateway";
import { createLogger } from "@montr/telemetry";
import { startWorker } from "./index.js";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required environment variable: ${name}`);
  return v;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger({ name: "montr-worker", bindings: { clientId: config.clientId } });

  const databaseUrl = requireEnv("DATABASE_URL");
  const redis = requireEnv("REDIS_URL");

  const store = createStateStore({
    databaseUrl,
    ...(process.env.MONTR_FIELD_ENCRYPTION_KEY
      ? { fieldEncryptionKey: process.env.MONTR_FIELD_ENCRYPTION_KEY }
      : {}),
  });
  const gateway = createLlmGateway({ config, logger });

  const worker = startWorker(config, { store, gateway, redis, logger });
  await worker.start();
  logger.info("worker.ready", { redis: true });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("worker.shutdown", { signal });
    try {
      await worker.stop();
      await store.disconnect();
    } finally {
      process.exit(0);
    }
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  // Boot failures are fatal + explicit (no silent degraded start).
  console.error("worker: fatal startup error:", err instanceof Error ? err.stack : err);
  process.exit(1);
});
