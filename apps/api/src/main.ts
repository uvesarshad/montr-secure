#!/usr/bin/env node
/**
 * apps/api process entrypoint (deploy/docker/Dockerfile.api `CMD ["dist/main.js"]`).
 *
 * Two modes, selected by argv:
 *   `node dist/main.js --migrate`  — run `prisma migrate deploy` and exit(0)/exit(1).
 *     Used by the docker-compose `migrate` one-shot service.
 *   `node dist/main.js`            — build real production deps (Postgres + Redis,
 *     no in-memory stores / stub orchestrator — see ./production-deps.ts) and
 *     serve. Handles SIGTERM/SIGINT for a graceful shutdown: stop accepting new
 *     connections, let in-flight requests drain, then close the DB/Redis
 *     connections before exiting.
 */
import { createApiServer } from "./server.js";
import { createProductionDeps } from "./production-deps.js";
import { runMigrations } from "./migrate.js";

const PORT = Number(process.env["PORT"] ?? 3001);
const HOST = process.env["HOST"] ?? "0.0.0.0";
/** Max time to wait for in-flight requests to drain on shutdown. */
const SHUTDOWN_TIMEOUT_MS = Number(process.env["SHUTDOWN_TIMEOUT_MS"] ?? 10_000);

async function runMigrateMode(): Promise<void> {
  await runMigrations();
}

async function runServeMode(): Promise<void> {
  const { deps, close } = await createProductionDeps();
  // createProductionDeps() always sets `logger` (see production-deps.ts).
  const logger = deps.logger as NonNullable<typeof deps.logger>;
  const server = createApiServer(deps);

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info?.("api.shutdown.start", { signal });

    const timeout = setTimeout(() => {
      logger.error?.("api.shutdown.timeout", { timeoutMs: SHUTDOWN_TIMEOUT_MS });
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
    timeout.unref();

    void (async () => {
      try {
        // Stop accepting new connections and let in-flight requests drain.
        await server.close();
        // Then release the durable connections (Postgres + the enqueue-only
        // BullMQ/Redis scheduler).
        await close();
        clearTimeout(timeout);
        logger.info?.("api.shutdown.complete", { signal });
        process.exit(0);
      } catch (err) {
        clearTimeout(timeout);
        logger.error?.("api.shutdown.error", { signal, error: String(err) });
        process.exit(1);
      }
    })();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  await server.listen(PORT, HOST);
  logger.info?.("api.listening", { port: PORT, host: HOST });
}

async function main(): Promise<void> {
  if (process.argv.includes("--migrate")) {
    await runMigrateMode();
    process.exit(0);
  }
  await runServeMode();
}

main().catch((err: unknown) => {
  console.error("apps/api fatal startup error:", err);
  process.exit(1);
});
