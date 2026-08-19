/**
 * Key sourcing (A22 follow-up): a real, pluggable backend for resolving the raw
 * AES-256-GCM field-encryption key bytes consumed by `@montr/state-store`'s
 * `FieldCipher` (see that package's `crypto.ts`).
 *
 * Two implementations share one contract ({@link KeySource}):
 *   - {@link EnvFileKeySource} — the pre-existing behaviour. The loader's env
 *     overlay / k8s secret-mount overlay already places the raw key bytes
 *     synchronously into `config.security.fieldEncryptionKeyRef` before this
 *     module ever runs, so this implementation just hands that value back.
 *   - {@link VaultKeySource} — a genuine HashiCorp Vault client. It makes real
 *     HTTP calls to Vault's KV v2 secrets engine (optionally authenticating via
 *     AppRole first) and returns the fetched key bytes. Selected via
 *     `security.keySource = "vault"` (env: `MONTR_KEY_SOURCE=vault`).
 *
 * Both return `Promise<string | undefined>` from `resolve()`, so callers use
 * `resolveFieldEncryptionKey(config)` the same way regardless of backend — a
 * genuine drop-in swap, not a separate bolted-on path.
 *
 * WHY THIS IS ASYNC AND `createFieldCipher`/`createStateStore` ARE NOT:
 * `@montr/state-store`'s `createStateStore` is synchronous by design (it wires
 * a Prisma client + cipher in one call). Callers resolve the key material
 * *before* constructing the store:
 *
 *   const config = loadConfig();
 *   const fieldEncryptionKey = await resolveFieldEncryptionKey(config);
 *   const store = createStateStore({ databaseUrl, fieldEncryptionKey });
 *
 * This keeps the existing synchronous contract intact for the "env"/"file"
 * backends (zero behaviour change) while making the "vault" backend a real
 * async remote fetch, not a synthetic one.
 */

import type { MontrConfig, VaultKeySourceConfig } from "./schema.js";

/** The pluggable key-sourcing contract. Every backend implements this. */
export interface KeySource {
  readonly kind: "env" | "file" | "vault";
  /** Resolve the raw key material (base64/hex 32-byte string, or a passphrase). */
  resolve(): Promise<string | undefined>;
}

/** Error codes for Vault-backed key resolution failures. */
export type VaultKeySourceErrorCode =
  | "VAULT_NOT_CONFIGURED"
  | "VAULT_AUTH_FAILED"
  | "VAULT_SECRET_NOT_FOUND"
  | "VAULT_INVALID_RESPONSE"
  | "VAULT_NETWORK_ERROR";

/** Thrown by {@link VaultKeySource} on any auth/lookup/network failure. */
export class VaultKeySourceError extends Error {
  readonly code: VaultKeySourceErrorCode;

  constructor(code: VaultKeySourceErrorCode, message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "VaultKeySourceError";
    this.code = code;
  }
}

/** Backend for "env"/"file": the value is already resolved by the config loader. */
export class EnvFileKeySource implements KeySource {
  readonly kind: "env" | "file";

  constructor(
    private readonly fieldEncryptionKeyRef: string | undefined,
    kind: "env" | "file" = "env",
  ) {
    this.kind = kind;
  }

  resolve(): Promise<string | undefined> {
    return Promise.resolve(this.fieldEncryptionKeyRef);
  }
}

/** Minimal fetch surface the Vault client needs — matches `fetch`'s type shape. */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/**
 * Vault's error response shape (all endpoints), per
 * https://developer.hashicorp.com/vault/api-docs#error-response:
 *   { "errors": ["permission denied"] }
 */
interface VaultErrorResponse {
  errors?: string[];
}

/**
 * AppRole login response shape, per
 * https://developer.hashicorp.com/vault/api-docs/auth/approle#sample-response-2 :
 *   {
 *     "auth": {
 *       "client_token": "ferf837ha84...",
 *       "accessor": "...",
 *       "policies": ["default"],
 *       "lease_duration": 2764800,
 *       "renewable": true
 *     }
 *   }
 */
interface VaultAppRoleLoginResponse {
  auth?: { client_token?: string };
}

/**
 * KV v2 "read secret version" response shape, per
 * https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#sample-response-1 :
 *   {
 *     "data": {
 *       "data": { "value": "...", "foo": "bar" },
 *       "metadata": {
 *         "created_time": "2018-03-22T02:24:06.945319214Z",
 *         "custom_metadata": null,
 *         "deletion_time": "",
 *         "destroyed": false,
 *         "version": 1
 *       }
 *     }
 *   }
 */
interface VaultKvV2ReadResponse {
  data?: {
    data?: Record<string, unknown>;
  };
}

/**
 * A real HashiCorp Vault client for the "vault" key source. Talks to Vault's
 * HTTP API directly (no `node-vault` dependency needed — Node ≥20 ships a
 * global `fetch`, matching this repo's convention of raw `fetch`-based clients
 * elsewhere, e.g. `packages/llm-gateway`'s provider adapters).
 *
 * Auth: a static token (`config.token`) is used as-is; otherwise, if
 * `roleId`/`secretId` are set, the client logs in via AppRole
 * (`POST /v1/auth/approle/login`) and uses the returned `client_token`.
 */
export class VaultKeySource implements KeySource {
  readonly kind = "vault" as const;
  private readonly fetchImpl: FetchLike;

  constructor(
    private readonly config: VaultKeySourceConfig,
    fetchImpl?: FetchLike,
  ) {
    // Default to the platform's global fetch (Node >=20 per this repo's engines).
    this.fetchImpl = fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  }

  async resolve(): Promise<string | undefined> {
    const { addr, secretPath } = this.config;
    if (!addr || !secretPath) {
      throw new VaultKeySourceError(
        "VAULT_NOT_CONFIGURED",
        "Vault key source selected (security.keySource=vault) but VAULT_ADDR / " +
          "VAULT_SECRET_PATH are not set",
      );
    }

    const token = await this.getToken();
    const data = await this.readSecret(addr, secretPath, token);

    const value = data[this.config.field];
    if (value === undefined) {
      throw new VaultKeySourceError(
        "VAULT_SECRET_NOT_FOUND",
        `Vault secret at "${this.config.kvMount}/${secretPath}" has no field ` +
          `"${this.config.field}"`,
      );
    }
    if (typeof value !== "string") {
      throw new VaultKeySourceError(
        "VAULT_INVALID_RESPONSE",
        `Vault secret field "${this.config.field}" is not a string (got ${typeof value})`,
      );
    }
    return value;
  }

  private async getToken(): Promise<string> {
    if (this.config.token) return this.config.token;
    if (this.config.roleId && this.config.secretId) {
      return this.loginWithAppRole(
        this.config.addr as string,
        this.config.roleId,
        this.config.secretId,
      );
    }
    throw new VaultKeySourceError(
      "VAULT_NOT_CONFIGURED",
      "Vault key source requires either VAULT_TOKEN or VAULT_ROLE_ID + VAULT_SECRET_ID",
    );
  }

  private async loginWithAppRole(addr: string, roleId: string, secretId: string): Promise<string> {
    const res = await this.request(`${trimSlash(addr)}/v1/auth/approle/login`, {
      method: "POST",
      body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
    });
    const body = (await this.parseJson(res)) as VaultAppRoleLoginResponse & VaultErrorResponse;
    if (!res.ok) throw this.authError(res.status, await this.errorsFrom(body));
    const clientToken = body.auth?.client_token;
    if (!clientToken) {
      throw new VaultKeySourceError(
        "VAULT_INVALID_RESPONSE",
        "Vault AppRole login response missing auth.client_token",
      );
    }
    return clientToken;
  }

  private async readSecret(
    addr: string,
    secretPath: string,
    token: string,
  ): Promise<Record<string, unknown>> {
    const url = `${trimSlash(addr)}/v1/${trimSlash(this.config.kvMount)}/data/${trimSlash(secretPath, true)}`;
    const res = await this.request(url, { method: "GET", headers: this.authHeaders(token) });
    const body = (await this.parseJson(res)) as VaultKvV2ReadResponse;

    if (res.status === 404) {
      throw new VaultKeySourceError(
        "VAULT_SECRET_NOT_FOUND",
        `No Vault secret found at "${this.config.kvMount}/${secretPath}"`,
      );
    }
    if (!res.ok) {
      throw this.authError(res.status, await this.errorsFrom(body as VaultErrorResponse));
    }
    const data = body.data?.data;
    if (!data) {
      throw new VaultKeySourceError(
        "VAULT_INVALID_RESPONSE",
        `Vault KV v2 response at "${this.config.kvMount}/${secretPath}" is missing data.data`,
      );
    }
    return data;
  }

  private authHeaders(token: string): Record<string, string> {
    const headers: Record<string, string> = { "X-Vault-Token": token };
    if (this.config.namespace) headers["X-Vault-Namespace"] = this.config.namespace;
    return headers;
  }

  private async request(
    url: string,
    init: { method: string; headers?: Record<string, string>; body?: string },
  ): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      return await this.fetchImpl(url, {
        method: init.method,
        headers: {
          "Content-Type": "application/json",
          ...(this.config.namespace ? { "X-Vault-Namespace": this.config.namespace } : {}),
          ...init.headers,
        },
        ...(init.body !== undefined ? { body: init.body } : {}),
        signal: controller.signal,
      });
    } catch (cause) {
      throw new VaultKeySourceError(
        "VAULT_NETWORK_ERROR",
        `Failed to reach Vault at ${url}: ${cause instanceof Error ? cause.message : String(cause)}`,
        cause,
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  private async parseJson(res: { json(): Promise<unknown> }): Promise<unknown> {
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  private async errorsFrom(body: VaultErrorResponse): Promise<string> {
    return Array.isArray(body.errors) && body.errors.length > 0
      ? body.errors.join("; ")
      : "no error detail returned";
  }

  private authError(status: number, detail: string): VaultKeySourceError {
    if (status === 403 || status === 401) {
      return new VaultKeySourceError("VAULT_AUTH_FAILED", `Vault authentication failed: ${detail}`);
    }
    return new VaultKeySourceError(
      "VAULT_INVALID_RESPONSE",
      `Vault request failed with status ${status}: ${detail}`,
    );
  }
}

function trimSlash(s: string, leading = false): string {
  return leading ? s.replace(/^\/+/, "") : s.replace(/\/+$/, "");
}

/** Build the {@link KeySource} selected by `config.security.keySource`. */
export function createKeySource(config: MontrConfig, fetchImpl?: FetchLike): KeySource {
  switch (config.security.keySource) {
    case "vault":
      return new VaultKeySource(config.security.vault, fetchImpl);
    case "file":
      return new EnvFileKeySource(config.security.fieldEncryptionKeyRef, "file");
    case "env":
    default:
      return new EnvFileKeySource(config.security.fieldEncryptionKeyRef, "env");
  }
}

/**
 * Resolve the raw field-encryption key material for whichever backend is
 * configured. This is the one call sites need — the same contract regardless
 * of "env" | "file" | "vault":
 *
 *   const key = await resolveFieldEncryptionKey(config);
 *   const store = createStateStore({ databaseUrl, fieldEncryptionKey: key });
 */
export async function resolveFieldEncryptionKey(
  config: MontrConfig,
  fetchImpl?: FetchLike,
): Promise<string | undefined> {
  return createKeySource(config, fetchImpl).resolve();
}
