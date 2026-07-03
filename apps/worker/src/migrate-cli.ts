/**
 * One-shot migration entrypoint (compose/k8s `migrate` job). Runs
 * `prisma migrate deploy` against DATABASE_URL, then exits. Kept OUT of the
 * api/worker boot path so those run on a hardened read-only root filesystem —
 * this job runs once on a writable filesystem where Prisma can resolve its
 * schema engine.
 */
import { createLogger } from "@montr/telemetry";
import { runMigrations } from "./migrate.js";

async function main(): Promise<void> {
  const logger = createLogger({ name: "montr-migrate" });
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("missing required environment variable: DATABASE_URL");
  await runMigrations(databaseUrl, logger);
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("migrate: failed:", err instanceof Error ? err.stack : err);
    process.exit(1);
  },
);
