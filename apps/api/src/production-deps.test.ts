import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * A10 — Vault key-source wiring. apps/api/src/production-deps.ts used to read
 * `config.security.fieldEncryptionKeyRef` directly, bypassing the pluggable
 * `KeySource` (env/file/vault) in packages/config/src/key-source.ts entirely —
 * so `security.keySource = "vault"` never fetched anything from Vault in
 * production. This test drives `createProductionDeps()` (with all its infra
 * collaborators mocked) and asserts it now goes through
 * `resolveFieldEncryptionKey` and threads the resolved value into
 * `createStateStoreFromClient`.
 */

const resolveFieldEncryptionKeyMock = vi.fn(async () => "vault-resolved-key-bytes");
const testConfig = {
  clientId: "default",
  security: {
    fieldEncryptionKeyRef: undefined,
    keySource: "vault",
    vault: { addr: "https://vault.internal:8200", token: "t", secretPath: "montr/key" },
  },
};
const loadConfigMock = vi.fn(() => testConfig);

vi.mock("@montr/config", () => ({
  loadConfig: loadConfigMock,
  resolveFieldEncryptionKey: resolveFieldEncryptionKeyMock,
}));

vi.mock("@montr/telemetry", () => ({
  createLogger: vi.fn(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() })),
}));

vi.mock("@montr/orchestrator", () => ({
  createOrchestrator: vi.fn(() => ({})),
}));

const createStateStoreFromClientMock = vi.fn(() => ({
  disconnect: vi.fn(async () => {}),
  reports: {},
  promptVersions: {},
}));
const createPrismaClientMock = vi.fn(() => ({
  client: { upsert: vi.fn(async () => {}) },
}));

vi.mock("@montr/state-store", () => ({
  createPrismaClient: createPrismaClientMock,
  createStateStoreFromClient: createStateStoreFromClientMock,
}));

vi.mock("./enqueue-scheduler.js", () => ({
  createEnqueueOnlyScheduler: vi.fn(async () => ({ close: vi.fn(async () => {}) })),
}));

vi.mock("./store.js", () => ({
  apiStoreFromStateStore: vi.fn(() => ({})),
}));

vi.mock("./prisma-store.js", () => ({
  PrismaUserStore: vi.fn(() => ({})),
  PrismaDastTargetStore: vi.fn(() => ({})),
  ReportRepositoryAdapter: vi.fn(() => ({})),
}));

describe("apps/api production-deps — Vault key-source wiring", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    loadConfigMock.mockReturnValue(testConfig);
    resolveFieldEncryptionKeyMock.mockResolvedValue("vault-resolved-key-bytes");
    process.env["DATABASE_URL"] = "postgres://test/test";
    process.env["REDIS_URL"] = "redis://test:6379";
    process.env["JWT_SECRET"] = "x".repeat(32);
    process.env["CSRF_SECRET"] = "y".repeat(16);
  });

  it("resolves the field-encryption key via resolveFieldEncryptionKey and passes it to createStateStoreFromClient", async () => {
    const { createProductionDeps } = await import("./production-deps.js");
    await createProductionDeps();

    expect(resolveFieldEncryptionKeyMock).toHaveBeenCalledTimes(1);
    expect(resolveFieldEncryptionKeyMock).toHaveBeenCalledWith(testConfig);
    expect(createStateStoreFromClientMock).toHaveBeenCalledTimes(1);

    const [, storeOptions] = createStateStoreFromClientMock.mock.calls[0] as [
      unknown,
      { fieldEncryptionKey?: string },
    ];
    expect(storeOptions.fieldEncryptionKey).toBe("vault-resolved-key-bytes");
  });

  it("omits fieldEncryptionKey entirely when the key source resolves undefined", async () => {
    resolveFieldEncryptionKeyMock.mockResolvedValueOnce(undefined);
    const { createProductionDeps } = await import("./production-deps.js");
    await createProductionDeps();

    const [, storeOptions] = createStateStoreFromClientMock.mock.calls[0] as [
      unknown,
      { fieldEncryptionKey?: string },
    ];
    expect(storeOptions.fieldEncryptionKey).toBeUndefined();
  });
});
