import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * A10 — Vault key-source wiring. apps/worker/src/main.ts used to read
 * `config.security.fieldEncryptionKeyRef` directly, bypassing the pluggable
 * `KeySource` (env/file/vault) in packages/config/src/key-source.ts entirely —
 * so `security.keySource = "vault"` never actually fetched anything from
 * Vault in production. This test drives the real entrypoint module (with all
 * its infra collaborators mocked) and asserts it now goes through
 * `resolveFieldEncryptionKey` and threads the resolved value into
 * `createStateStoreFromClient`.
 */

const resolveFieldEncryptionKeyMock = vi.fn(async () => "vault-resolved-key-bytes");
const loadConfigMock = vi.fn(() => ({
  clientId: "default",
  security: {
    fieldEncryptionKeyRef: undefined,
    keySource: "vault",
    vault: { addr: "https://vault.internal:8200", token: "t", secretPath: "montr/key" },
  },
}));

vi.mock("@montr/config", () => ({
  loadConfig: loadConfigMock,
  resolveFieldEncryptionKey: resolveFieldEncryptionKeyMock,
}));

vi.mock("@montr/telemetry", () => ({
  createLogger: vi.fn(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() })),
}));

vi.mock("@montr/llm-gateway", () => ({
  createLlmGateway: vi.fn(() => ({})),
}));

vi.mock("@montr/cost-meter", () => ({
  createBudgetRegistry: vi.fn(() => ({})),
}));

const createStateStoreFromClientMock = vi.fn(() => ({
  disconnect: vi.fn(async () => {}),
  promptVersions: {},
}));
const createPrismaClientMock = vi.fn(() => ({
  client: { upsert: vi.fn(async () => {}) },
}));

vi.mock("@montr/state-store", () => ({
  createPrismaClient: createPrismaClientMock,
  createStateStoreFromClient: createStateStoreFromClientMock,
}));

vi.mock("./index.js", () => ({
  startWorker: vi.fn(() => ({
    start: vi.fn(async () => {}),
    stop: vi.fn(async () => {}),
    orchestrator: {},
  })),
  reconcileStuckScans: vi.fn(async () => {}),
  DEFAULT_STUCK_SCAN_THRESHOLD_MS: 600_000,
}));

describe("apps/worker main entrypoint — Vault key-source wiring", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resolveFieldEncryptionKeyMock.mockClear();
    process.env["DATABASE_URL"] = "postgres://test/test";
    process.env["REDIS_URL"] = "redis://test:6379";
  });

  it("resolves the field-encryption key via resolveFieldEncryptionKey and passes it to createStateStoreFromClient", async () => {
    await import("./main.js");

    await vi.waitFor(() => {
      expect(resolveFieldEncryptionKeyMock).toHaveBeenCalledTimes(1);
      expect(createStateStoreFromClientMock).toHaveBeenCalledTimes(1);
    });

    // resolveFieldEncryptionKey must be called with the loaded config (not a
    // raw fieldEncryptionKeyRef read).
    expect(resolveFieldEncryptionKeyMock).toHaveBeenCalledWith(
      loadConfigMock.mock.results[0]?.value,
    );

    // The resolved value must be the one threaded into the state store, not
    // the (unset) raw fieldEncryptionKeyRef.
    const [, storeOptions] = createStateStoreFromClientMock.mock.calls[0] as [
      unknown,
      { fieldEncryptionKey?: string },
    ];
    expect(storeOptions.fieldEncryptionKey).toBe("vault-resolved-key-bytes");
  });
});
