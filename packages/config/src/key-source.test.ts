import { describe, it, expect, vi } from "vitest";
import { parseConfig } from "./loader.js";
import {
  createKeySource,
  resolveFieldEncryptionKey,
  EnvFileKeySource,
  VaultKeySource,
  VaultKeySourceError,
  type FetchLike,
} from "./key-source.js";

/**
 * A22 follow-up: real Vault client tests. There is no live Vault server to
 * integrate-test against in this environment, so these tests drive the actual
 * request-building / response-parsing logic of `VaultKeySource` against a
 * mocked `fetch`, using response bodies shaped exactly like Vault's real,
 * documented API (see the JSON shapes cited in comments in key-source.ts,
 * sourced from https://developer.hashicorp.com/vault/api-docs).
 */

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

describe("EnvFileKeySource", () => {
  it("resolves the pre-loaded fieldEncryptionKeyRef value unchanged", async () => {
    const source = new EnvFileKeySource("deadbeef".repeat(8), "env");
    await expect(source.resolve()).resolves.toBe("deadbeef".repeat(8));
    expect(source.kind).toBe("env");
  });

  it("resolves undefined when nothing is configured", async () => {
    const source = new EnvFileKeySource(undefined, "file");
    await expect(source.resolve()).resolves.toBeUndefined();
  });
});

describe("VaultKeySource — static token auth", () => {
  it("fetches the key from Vault's real KV v2 response shape", async () => {
    const calls: Array<{ url: string; init: unknown }> = [];
    const fetchImpl: FetchLike = vi.fn(async (url, init) => {
      calls.push({ url, init });
      // Real Vault KV v2 "read secret version" response shape:
      // https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#sample-response-1
      return jsonResponse(200, {
        data: {
          data: { value: "c2VjcmV0LWtleS1ieXRlcw==" },
          metadata: {
            created_time: "2018-03-22T02:24:06.945319214Z",
            custom_metadata: null,
            deletion_time: "",
            destroyed: false,
            version: 1,
          },
        },
      });
    });

    const source = new VaultKeySource(
      {
        addr: "https://vault.internal:8200",
        token: "s.staticToken123",
        kvMount: "secret",
        field: "value",
        secretPath: "montr/field-encryption-key",
        requestTimeoutMs: 5000,
      },
      fetchImpl,
    );

    await expect(source.resolve()).resolves.toBe("c2VjcmV0LWtleS1ieXRlcw==");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(
      "https://vault.internal:8200/v1/secret/data/montr/field-encryption-key",
    );
    const init = calls[0]?.init as { method: string; headers: Record<string, string> };
    expect(init.method).toBe("GET");
    expect(init.headers["X-Vault-Token"]).toBe("s.staticToken123");
  });

  it("includes X-Vault-Namespace when configured (Vault Enterprise)", async () => {
    const fetchImpl: FetchLike = vi.fn(async () =>
      jsonResponse(200, { data: { data: { value: "abc" } } }),
    );
    const source = new VaultKeySource(
      {
        addr: "https://vault.internal:8200",
        token: "t",
        namespace: "eng/",
        kvMount: "secret",
        field: "value",
        secretPath: "k",
        requestTimeoutMs: 5000,
      },
      fetchImpl,
    );
    await source.resolve();
    const call = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    const init = call?.[1] as { headers: Record<string, string> };
    expect(init.headers["X-Vault-Namespace"]).toBe("eng/");
  });
});

describe("VaultKeySource — AppRole auth", () => {
  it("logs in via AppRole then uses the returned client_token to read the secret", async () => {
    const calls: string[] = [];
    const fetchImpl: FetchLike = vi.fn(async (url, init) => {
      calls.push(url);
      if (url.endsWith("/v1/auth/approle/login")) {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(init?.body ?? "{}")).toEqual({
          role_id: "role-123",
          secret_id: "secret-456",
        });
        // Real Vault AppRole login response shape:
        // https://developer.hashicorp.com/vault/api-docs/auth/approle#sample-response-2
        return jsonResponse(200, {
          auth: {
            client_token: "ferf837ha84228h29",
            accessor: "abc123",
            policies: ["default"],
            lease_duration: 2764800,
            renewable: true,
          },
        });
      }
      // Secret read must use the token from the login response.
      expect((init?.headers as Record<string, string>)["X-Vault-Token"]).toBe("ferf837ha84228h29");
      return jsonResponse(200, { data: { data: { value: "rotated-key-bytes" } } });
    });

    const source = new VaultKeySource(
      {
        addr: "https://vault.internal:8200",
        roleId: "role-123",
        secretId: "secret-456",
        kvMount: "secret",
        field: "value",
        secretPath: "montr/field-encryption-key",
        requestTimeoutMs: 5000,
      },
      fetchImpl,
    );

    await expect(source.resolve()).resolves.toBe("rotated-key-bytes");
    expect(calls).toEqual([
      "https://vault.internal:8200/v1/auth/approle/login",
      "https://vault.internal:8200/v1/secret/data/montr/field-encryption-key",
    ]);
  });
});

describe("VaultKeySource — error handling", () => {
  const base = {
    addr: "https://vault.internal:8200",
    token: "t",
    kvMount: "secret",
    field: "value",
    secretPath: "montr/field-encryption-key",
    requestTimeoutMs: 5000,
  };

  it("throws VAULT_NOT_CONFIGURED when addr/secretPath are missing", async () => {
    const source = new VaultKeySource({ ...base, addr: undefined }, vi.fn());
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_NOT_CONFIGURED" });
  });

  it("throws VAULT_NOT_CONFIGURED when neither token nor AppRole creds are set", async () => {
    const source = new VaultKeySource({ ...base, token: undefined }, vi.fn());
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_NOT_CONFIGURED" });
  });

  it("maps a 403 permission-denied response to VAULT_AUTH_FAILED", async () => {
    // Real Vault error response shape:
    // https://developer.hashicorp.com/vault/api-docs#error-response
    const fetchImpl: FetchLike = vi.fn(async () =>
      jsonResponse(403, { errors: ["permission denied"] }),
    );
    const source = new VaultKeySource(base, fetchImpl);
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_AUTH_FAILED" });
    await expect(source.resolve()).rejects.toThrow(/permission denied/);
  });

  it("maps a 404 response to VAULT_SECRET_NOT_FOUND", async () => {
    const fetchImpl: FetchLike = vi.fn(async () => jsonResponse(404, { errors: [] }));
    const source = new VaultKeySource(base, fetchImpl);
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_SECRET_NOT_FOUND" });
  });

  it("throws VAULT_SECRET_NOT_FOUND when the configured field is absent", async () => {
    const fetchImpl: FetchLike = vi.fn(async () =>
      jsonResponse(200, { data: { data: { other_field: "x" } } }),
    );
    const source = new VaultKeySource(base, fetchImpl);
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_SECRET_NOT_FOUND" });
  });

  it("throws VAULT_INVALID_RESPONSE when data.data is missing entirely", async () => {
    const fetchImpl: FetchLike = vi.fn(async () => jsonResponse(200, {}));
    const source = new VaultKeySource(base, fetchImpl);
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_INVALID_RESPONSE" });
  });

  it("wraps a network failure as VAULT_NETWORK_ERROR", async () => {
    const fetchImpl: FetchLike = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const source = new VaultKeySource(base, fetchImpl);
    await expect(source.resolve()).rejects.toMatchObject({ code: "VAULT_NETWORK_ERROR" });
  });

  it("VaultKeySourceError carries its cause", async () => {
    const cause = new Error("boom");
    const err = new VaultKeySourceError("VAULT_NETWORK_ERROR", "wrapped", cause);
    expect(err.cause).toBe(cause);
  });
});

describe("createKeySource / resolveFieldEncryptionKey — config-driven selection", () => {
  it("selects EnvFileKeySource by default", () => {
    const config = parseConfig({ security: { fieldEncryptionKeyRef: "raw-bytes" } });
    const source = createKeySource(config);
    expect(source).toBeInstanceOf(EnvFileKeySource);
    expect(source.kind).toBe("env");
  });

  it("selects VaultKeySource when security.keySource = vault", () => {
    const config = parseConfig({
      security: {
        keySource: "vault",
        vault: { addr: "https://v:8200", token: "t", secretPath: "p" },
      },
    });
    const source = createKeySource(config);
    expect(source).toBeInstanceOf(VaultKeySource);
    expect(source.kind).toBe("vault");
  });

  it("resolveFieldEncryptionKey is a genuine drop-in across both backends", async () => {
    const envConfig = parseConfig({ security: { fieldEncryptionKeyRef: "envbytes" } });
    await expect(resolveFieldEncryptionKey(envConfig)).resolves.toBe("envbytes");

    const vaultConfig = parseConfig({
      security: {
        keySource: "vault",
        vault: { addr: "https://v:8200", token: "t", secretPath: "p", field: "value" },
      },
    });
    const fetchImpl: FetchLike = vi.fn(async () =>
      jsonResponse(200, { data: { data: { value: "vaultbytes" } } }),
    );
    await expect(resolveFieldEncryptionKey(vaultConfig, fetchImpl)).resolves.toBe("vaultbytes");
  });
});
