/**
 * Real (Postgres + Redis backed) production dependency wiring for apps/api —
 * the production counterpart to `createInMemoryDeps` (server.ts) /
 * `createStubOrchestrator` (stub-orchestrator.ts), which are dev/test only.
 *
 * apps/api's Orchestrator is enqueue-only (see ./enqueue-scheduler.ts): it
 * persists real scan/gate state to Postgres and pushes real BullMQ jobs to
 * Redis for apps/worker to execute, but it never runs a pipeline layer itself
 * — apps/worker's image ships the SAST/secrets/SCA toolchain, apps/api's
 * distroless image deliberately does not. Its `layerRunners` /
 * `createCostMeter` deps are therefore defensive stubs that throw if ever
 * actually invoked (they shouldn't be — see enqueue-scheduler.ts for why).
 */
import { randomUUID } from "node:crypto";
import { MontrError, type LayerId } from "@montr/contracts";
import { loadConfig, resolveFieldEncryptionKey } from "@montr/config";
import { createLogger } from "@montr/telemetry";
import {
  createOrchestrator,
  deriveTenantSchedulerOptions,
  type LayerRunner,
  type LayerRunners,
  type Orchestrator,
} from "@montr/orchestrator";
import {
  createPrismaClient,
  createStateStoreFromClient,
  type StateStore,
} from "@montr/state-store";
import type { ApiServerDeps } from "./types.js";
import { apiStoreFromStateStore } from "./store.js";
import { createEnqueueOnlyScheduler } from "./enqueue-scheduler.js";
import { createBullMqScenarioRunProducer } from "./scenario-run-producer.js";
import { PrismaDastTargetStore, PrismaUserStore, ReportRepositoryAdapter } from "./prisma-store.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}. Production apps/api needs it — see deploy/docker/.env.example.`,
    );
  }
  return value;
}

function parseBoolEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

function parseListEnv(name: string): string[] {
  return (process.env[name] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

const UNREACHABLE_LAYERS: readonly LayerId[] = [
  "layer0",
  "layer1",
  "layer2",
  "layer3",
  "layer4",
  "layer5",
];

function unreachableLayerRunner<L extends LayerId>(layer: L): LayerRunner<L> {
  return async () => {
    throw new MontrError(
      "INTERNAL",
      `apps/api must never execute pipeline layer "${layer}" — its BullMQ scheduler is ` +
        "produce-only (see apps/api/src/enqueue-scheduler.ts). Layer execution belongs to " +
        "apps/worker. If this fired, the job-scheduler wiring is broken.",
    );
  };
}

/** Unreachable in apps/api (see file header) — kept only to satisfy `OrchestratorDeps`. */
function unreachableLayerRunners(): LayerRunners {
  const entries = UNREACHABLE_LAYERS.map(
    (layer) => [layer, unreachableLayerRunner(layer)] as const,
  );
  return Object.fromEntries(entries) as unknown as LayerRunners;
}

/** Unreachable in apps/api for the same reason as {@link unreachableLayerRunners}. */
function unreachableCostMeter(_scanId: string): never {
  throw new MontrError(
    "INTERNAL",
    "apps/api must never create a live cost meter — layer execution (and its cost " +
      "accounting) belongs to apps/worker.",
  );
}

export interface ProductionDeps {
  deps: ApiServerDeps;
  /** Close the real Postgres + Redis connections. Call on graceful shutdown. */
  close(): Promise<void>;
}

/** Build real, env-driven `ApiServerDeps` for production (Postgres + Redis, no stubs). */
export async function createProductionDeps(): Promise<ProductionDeps> {
  const config = loadConfig();
  const logger = createLogger({ name: "montr-api", bindings: { clientId: config.clientId } });

  const databaseUrl = requireEnv("DATABASE_URL");
  const redisUrl = requireEnv("REDIS_URL");
  const jwtSecret = requireEnv("JWT_SECRET");
  const csrfSecret = requireEnv("CSRF_SECRET");

  const prisma = createPrismaClient({
    databaseUrl,
    logQueries: parseBoolEnv("MONTR_LOG_SQL", false),
  });
  // Every row (User, Scan, AppMap, ...) has a required FK to Client, but
  // nothing else provisions that row for an on-prem, single-tenant deploy —
  // config.clientId IS the tenant identity here, not a value some separate
  // admin flow assigns. Idempotent: self-heals on every boot regardless of
  // whether the `--migrate` one-shot ran first.
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
  const state: StateStore = createStateStoreFromClient(prisma, {
    ...(fieldEncryptionKey ? { fieldEncryptionKey } : {}),
    ownsClient: true,
  });

  // A27 (opt-in, off by default): MUST derive from the exact same config
  // shape apps/worker's startWorker() does, or a tenant-isolated job apps/api
  // enqueues here lands in a queue apps/worker never listens on.
  const scheduler = await createEnqueueOnlyScheduler(
    redisUrl,
    deriveTenantSchedulerOptions(config),
  );
  // A1 (2026-09-12) — real worker-side scenario execution enqueue. A separate
  // dedicated queue from the per-layer FSM scheduler above (see
  // packages/contracts/src/queue.ts's SCENARIO_RUN_QUEUE_NAME doc comment for
  // why a scenario run is not a pipeline layer job).
  const scenarioRunProducer = await createBullMqScenarioRunProducer(redisUrl);
  const orchestrator: Orchestrator = createOrchestrator({
    config,
    store: state,
    logger,
    createCostMeter: unreachableCostMeter,
    layerRunners: unreachableLayerRunners(),
    scheduler,
  });

  const store = apiStoreFromStateStore(state, {
    users: new PrismaUserStore(prisma),
    reports: new ReportRepositoryAdapter(state.reports),
    dastTargets: new PrismaDastTargetStore(prisma),
  });

  const corsOrigins = parseListEnv("MONTR_API_CORS_ORIGINS");
  const trustProxy = parseBoolEnv("MONTR_API_TRUST_PROXY", false);
  const enableSwaggerUi = parseBoolEnv("MONTR_API_SWAGGER_UI", true);

  // A15 — webhook scan trigger. Fail-closed default: both must be set or the
  // route stays disabled (503), matching every other hardened-off-by-default
  // control in this deployment (auto-fix, DAST, telemetry).
  const webhookSecret = process.env["MONTR_WEBHOOK_SECRET"];
  const webhookOperatorEmail = process.env["MONTR_WEBHOOK_OPERATOR_EMAIL"];
  const webhookGithubToken = process.env["MONTR_WEBHOOK_GITHUB_TOKEN"];
  const webhook =
    webhookSecret && webhookOperatorEmail
      ? {
          secret: webhookSecret,
          operatorEmail: webhookOperatorEmail,
          ...(webhookGithubToken ? { githubToken: webhookGithubToken } : {}),
        }
      : undefined;

  const deps: ApiServerDeps = {
    config,
    store,
    orchestrator,
    jwtSecret,
    csrfSecret,
    logger,
    idgen: (prefix = "id") => `${prefix}_${randomUUID()}`,
    trustProxy,
    enableSwaggerUi,
    // cookieSecure intentionally omitted — resolveDeps() defaults to `true` in
    // the absence of an override, which is the production-safe behavior.
    ...(corsOrigins.length ? { corsOrigins } : {}),
    ...(webhook ? { webhook } : {}),
    scenarioRunProducer,
  };

  return {
    deps,
    async close(): Promise<void> {
      await scheduler.close();
      await scenarioRunProducer.close();
      await state.disconnect();
    },
  };
}
