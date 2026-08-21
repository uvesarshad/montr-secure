import { describe, it, expect } from "vitest";
import { parseConfig, loadConfig } from "./loader.js";
import { getHardenedDefaults, QueueConfigSchema } from "./schema.js";

/**
 * A27 — per-tenant BullMQ queue isolation config (opt-in, OFF by default).
 * See packages/orchestrator/src/bullmq-scheduler.ts for the mechanism this
 * flag drives.
 */

describe("QueueConfigSchema defaults (A27)", () => {
  it("defaults perTenantIsolation to false and tenantIds to an empty list", () => {
    const parsed = QueueConfigSchema.parse({});
    expect(parsed.perTenantIsolation).toBe(false);
    expect(parsed.tenantIds).toEqual([]);
  });

  it("the hardened baseline config carries the same off-by-default queue config", () => {
    const defaults = getHardenedDefaults();
    expect(defaults.queue).toEqual({ perTenantIsolation: false, tenantIds: [] });
  });

  it("rejects an empty-string tenantId", () => {
    expect(() => QueueConfigSchema.parse({ tenantIds: [""] })).toThrow();
  });

  it("accepts an explicit non-empty tenantIds list when isolation is enabled", () => {
    const parsed = QueueConfigSchema.parse({
      perTenantIsolation: true,
      tenantIds: ["client_a", "client_b"],
    });
    expect(parsed).toEqual({ perTenantIsolation: true, tenantIds: ["client_a", "client_b"] });
  });
});

describe("loadConfig — MONTR_QUEUE_* env overlay (A27)", () => {
  it("leaves queue config at its off-by-default values when unset (regression safety)", () => {
    const config = parseConfig({});
    expect(config.queue).toEqual({ perTenantIsolation: false, tenantIds: [] });
  });

  it("MONTR_QUEUE_PER_TENANT_ISOLATION=true flips perTenantIsolation on", () => {
    const config = loadConfig({ env: { MONTR_QUEUE_PER_TENANT_ISOLATION: "true" } });
    expect(config.queue.perTenantIsolation).toBe(true);
  });

  it("MONTR_QUEUE_TENANT_IDS parses a comma-separated list", () => {
    const config = loadConfig({
      env: {
        MONTR_QUEUE_PER_TENANT_ISOLATION: "true",
        MONTR_QUEUE_TENANT_IDS: "client_a, client_b ,client_c",
      },
    });
    expect(config.queue.tenantIds).toEqual(["client_a", "client_b", "client_c"]);
  });

  it("an unset MONTR_QUEUE_* env leaves the rest of the config untouched", () => {
    const config = loadConfig({ env: { MONTR_CLIENT_ID: "acme" } });
    expect(config.clientId).toBe("acme");
    expect(config.queue).toEqual({ perTenantIsolation: false, tenantIds: [] });
  });
});
