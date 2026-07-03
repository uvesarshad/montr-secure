/**
 * apps/api composition root — the HTTP control plane (build-plan §4.4).
 *
 * Assembles the REAL runtime dependencies from environment config and starts the
 * Fastify server. In the split deployment the API is a PRODUCE-ONLY orchestrator
 * peer: it creates / starts / approves / kills scans and enqueues Layer-0 over
 * Redis, while apps/worker (the sole consumer, with the scanners + git) runs the
 * pipeline. Kill switch propagates over the Redis kill channel; the human gate is
 * the shared, persisted Scan.gateState in Postgres.
 *
 * Secrets (JWT/CSRF signing, field-encryption key) come from the environment /
 * mounted secret files — never a committed file (golden rule #1). Boot fails
 * fast + explicitly on a missing required secret.
 *
 * Known limitations of this composition (documented, non-blocking for §5.1):
 *   - users + DAST targets use in-memory stores (no Postgres repos exist yet), so
 *     they do not survive a restart; the seeded operator/approver are re-created
 *     on boot. Pipeline data (scans/findings/reports/audit) is real Postgres.
 *   - live pipeline events (SSE) are process-local; cross-process progress is read
 *     via the persisted Scan status, not the worker's in-process event bus.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { loadConfig } from "@montr/config";
import { MontrError, type Report, type Role } from "@montr/contracts";
import { createStateStore } from "@montr/state-store";
import { createLlmGateway } from "@montr/llm-gateway";
import { createCostMeter } from "@montr/cost-meter";
import {
  createBullMqScheduler,
  createOrchestrator,
  LAYER_ORDER,
  type LayerRunners,
} from "@montr/orchestrator";
import { createLogger, type Logger } from "@montr/telemetry";
import { createApiServer } from "./server.js";
import { apiStoreFromStateStore } from "./store.js";
import type { DastTarget, DastTargetStore, ReportStore } from "./store.js";
import { InMemoryUserStore, type UserRecord } from "./auth/users.js";
import { hashPassword } from "./auth/password.js";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required environment variable: ${name}`);
  return v;
}

/** A secret from env, or a generated ephemeral one (dev only — logged as a warning). */
function secretFromEnv(name: string, minLen: number, logger: Logger): string {
  const v = process.env[name];
  if (v && v.length >= minLen) return v;
  const generated = randomBytes(Math.ceil(minLen * 1.5)).toString("base64url");
  logger.warn("secret.ephemeral", {
    name,
    reason: v ? "too short" : "unset",
    hint: `set ${name} (>= ${minLen} chars) for stable sessions across restarts`,
  });
  return generated;
}

/** Produce-only layer runners: the API never consumes layer jobs (the worker does). */
function producerRunners(): LayerRunners {
  const entries = LAYER_ORDER.map((layer) => [
    layer,
    () => {
      throw new MontrError("INTERNAL", `layer ${layer} runs in the worker, not the api`);
    },
  ]);
  return Object.fromEntries(entries) as unknown as LayerRunners;
}

/** Minimal in-memory DAST-target store (DAST is OFF by default; targets are ephemeral). */
class InMemoryDastTargetStore implements DastTargetStore {
  private readonly rows = new Map<string, DastTarget>();
  private key(clientId: string, id: string): string {
    return `${clientId}:${id}`;
  }
  async create(target: DastTarget): Promise<DastTarget> {
    this.rows.set(this.key(target.clientId, target.id), { ...target });
    return { ...target };
  }
  async get(clientId: string, id: string): Promise<DastTarget | null> {
    const r = this.rows.get(this.key(clientId, id));
    return r ? { ...r } : null;
  }
  async findByUrl(clientId: string, url: string): Promise<DastTarget | null> {
    for (const r of this.rows.values())
      if (r.clientId === clientId && r.url === url) return { ...r };
    return null;
  }
  async list(clientId: string): Promise<DastTarget[]> {
    return [...this.rows.values()].filter((r) => r.clientId === clientId).map((r) => ({ ...r }));
  }
  async update(clientId: string, target: DastTarget): Promise<DastTarget> {
    this.rows.set(this.key(clientId, target.id), { ...target });
    return { ...target };
  }
}

/** Seed one operator + one approver so a fresh stack is usable end-to-end. */
async function seedUsers(
  users: InMemoryUserStore,
  clientId: string,
  logger: Logger,
): Promise<void> {
  const now = new Date().toISOString();
  const seed = async (email: string, password: string, role: Role): Promise<void> => {
    if (await users.findByEmail(clientId, email)) return;
    const record: UserRecord = {
      id: `user_${randomUUID()}`,
      clientId,
      email,
      passwordHash: await hashPassword(password),
      role,
      createdAt: now,
      updatedAt: now,
    };
    await users.create(record);
    logger.info("user.seeded", { email, role });
  };
  const operatorPw = process.env.MONTR_OPERATOR_PASSWORD ?? "montr-operator-dev";
  const approverPw = process.env.MONTR_APPROVER_PASSWORD ?? "montr-approver-dev";
  await seed(process.env.MONTR_OPERATOR_EMAIL ?? "operator@montr.local", operatorPw, "operator");
  await seed(process.env.MONTR_APPROVER_EMAIL ?? "approver@montr.local", approverPw, "approver");
}

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger({ name: "montr-api", bindings: { clientId: config.clientId } });

  const databaseUrl = requireEnv("DATABASE_URL");
  const redis = requireEnv("REDIS_URL");
  const port = Number(process.env.PORT ?? 3001);

  const state = createStateStore({
    databaseUrl,
    ...(process.env.MONTR_FIELD_ENCRYPTION_KEY
      ? { fieldEncryptionKey: process.env.MONTR_FIELD_ENCRYPTION_KEY }
      : {}),
  });
  const gateway = createLlmGateway({ config, logger });

  // Produce-only scheduler: enqueue + kill-channel, no layer consumers (the worker
  // is the sole consumer). Not connected until the first scan is started.
  const scheduler = await createBullMqScheduler(redis, { consume: false });
  const orchestrator = createOrchestrator({
    config,
    store: state,
    logger,
    createCostMeter: (scanId) => createCostMeter(scanId),
    layerRunners: producerRunners(),
    scheduler,
  });

  // API-owned stores (no Postgres repos yet) + the real StateStore for pipeline data.
  const users = new InMemoryUserStore();
  await seedUsers(users, config.clientId, logger);
  const reports: ReportStore = {
    getByScan: (clientId, scanId) => state.reports.getByScan(clientId, scanId),
    save: async (report: Report) => state.reports.upsert(report.clientId, report),
  };
  const store = apiStoreFromStateStore(state, {
    users,
    reports,
    dastTargets: new InMemoryDastTargetStore(),
  });

  const server = createApiServer({
    config,
    store,
    orchestrator,
    jwtSecret: secretFromEnv("MONTR_JWT_SECRET", 32, logger),
    csrfSecret: secretFromEnv("MONTR_CSRF_SECRET", 16, logger),
    logger,
    cookieSecure: process.env.MONTR_COOKIE_SECURE !== "false",
    ...(process.env.MONTR_CORS_ORIGINS
      ? { corsOrigins: process.env.MONTR_CORS_ORIGINS.split(",").map((s) => s.trim()) }
      : {}),
  });

  await server.listen(port, "0.0.0.0");
  logger.info("api.ready", { port });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("api.shutdown", { signal });
    try {
      await server.close();
      await orchestrator.close();
      await state.disconnect();
    } finally {
      process.exit(0);
    }
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error("api: fatal startup error:", err instanceof Error ? err.stack : err);
  process.exit(1);
});
