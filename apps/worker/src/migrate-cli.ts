/**
 * One-shot migration + bootstrap-seed entrypoint (compose/k8s `migrate` job).
 * Runs `prisma migrate deploy` against DATABASE_URL, then ensures the tenant
 * `Client` row exists (every table FKs to it), then exits. Kept OUT of the
 * api/worker boot path so those run on a hardened read-only root filesystem —
 * this job runs once on a writable filesystem where Prisma can resolve its
 * schema engine.
 */
import { loadConfig } from "@montr/config";
import { createPrismaClient } from "@montr/state-store";
import { createLogger } from "@montr/telemetry";
import { runMigrations } from "./migrate.js";

async function main(): Promise<void> {
  const logger = createLogger({ name: "montr-migrate" });
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("missing required environment variable: DATABASE_URL");

  await runMigrations(databaseUrl, logger);

  // Ensure the tenant Client row exists — audit events, scans, users, etc. all
  // carry a foreign key to Client, so the first write fails without it.
  const clientId = loadConfig().clientId;
  const prisma = createPrismaClient({ databaseUrl });
  try {
    await prisma.client.upsert({
      where: { id: clientId },
      update: {},
      create: { id: clientId, name: clientId },
    });
    logger.info("client.seeded", { clientId });
  } finally {
    await prisma.$disconnect();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("migrate: failed:", err instanceof Error ? err.stack : err);
    process.exit(1);
  },
);
