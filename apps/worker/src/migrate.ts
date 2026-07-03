/**
 * Run `prisma migrate deploy` against DATABASE_URL before the process starts
 * serving. Idempotent (Prisma takes a Postgres advisory lock, so concurrent
 * runners from other services are safe) and a no-op once the schema is current.
 *
 * The worker image ships the `prisma` CLI (a direct dependency, so its bin is
 * linked at node_modules/.bin/prisma) and the @montr/state-store schema +
 * migrations (shipped in that package's `files`). Both default to the deployed
 * /app layout and are overridable via env for other runtimes.
 */
import { spawn } from "node:child_process";
import type { Logger } from "@montr/telemetry";

const DEFAULT_SCHEMA = "/app/node_modules/@montr/state-store/prisma/schema.prisma";
const DEFAULT_PRISMA_BIN = "/app/node_modules/.bin/prisma";

export async function runMigrations(databaseUrl: string, logger: Logger): Promise<void> {
  const schema = process.env.MONTR_PRISMA_SCHEMA ?? DEFAULT_SCHEMA;
  const prismaBin = process.env.MONTR_PRISMA_BIN ?? DEFAULT_PRISMA_BIN;
  logger.info("migrate.start", { schema });
  await new Promise<void>((resolve, reject) => {
    const child = spawn(prismaBin, ["migrate", "deploy", "--schema", schema], {
      env: { ...process.env, DATABASE_URL: databaseUrl },
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`prisma migrate deploy exited ${code}`)),
    );
  });
  logger.info("migrate.done");
}
