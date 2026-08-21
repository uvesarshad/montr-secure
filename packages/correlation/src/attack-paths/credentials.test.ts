/**
 * B8 — credential-shaped ORM field detection. Precision matters here: a false
 * positive manufactures a fake `idor-credential-leak` chain condition, so this
 * pins down both the intended matches and the deliberate near-misses.
 */
import { describe, it, expect } from "vitest";
import { AppMapSchema, type AppMap } from "@montr/contracts";
import {
  CREDENTIAL_FIELD_PATTERN,
  modelHasCredentialField,
  routeLeaksCredentials,
} from "./credentials.js";

function mkAppMap(ormModels: AppMap["ormModels"], routes: AppMap["routes"] = []): AppMap {
  return AppMapSchema.parse({
    id: "appmap_1",
    clientId: "client_1",
    repo: "https://example.internal/x",
    branch: "main",
    commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334",
    createdAt: "2026-08-22T00:00:00.000Z",
    routes,
    ormModels,
  });
}

describe("CREDENTIAL_FIELD_PATTERN", () => {
  it.each([
    "password",
    "PASSWORD",
    "pwd",
    "secret",
    "token",
    "apiKey",
    "api_key",
    "api-key",
    "credential",
    "privateKey",
    "accessKey",
    "refreshToken",
    "sessionId",
    "authToken",
  ])("matches credential-shaped field name %s", (name) => {
    expect(CREDENTIAL_FIELD_PATTERN.test(name)).toBe(true);
  });

  it.each([
    "content",
    "body",
    "code",
    "evidence",
    "tokenizerVersion",
    "displayName",
    "email",
    "id",
  ])("does NOT match a non-credential field name %s", (name) => {
    expect(CREDENTIAL_FIELD_PATTERN.test(name)).toBe(false);
  });
});

describe("modelHasCredentialField", () => {
  it("returns true when a model has a credential-shaped field", () => {
    const appMap = mkAppMap([
      {
        name: "User",
        fields: [
          { name: "id", type: "Int", isId: true },
          { name: "apiKey", type: "String", isId: false },
        ],
      },
    ]);
    expect(modelHasCredentialField(appMap, "User")).toBe(true);
  });

  it("returns false when no field is credential-shaped", () => {
    const appMap = mkAppMap([
      {
        name: "User",
        fields: [
          { name: "id", type: "Int", isId: true },
          { name: "displayName", type: "String", isId: false },
        ],
      },
    ]);
    expect(modelHasCredentialField(appMap, "User")).toBe(false);
  });

  it("returns false for an unknown model name", () => {
    const appMap = mkAppMap([{ name: "User", fields: [] }]);
    expect(modelHasCredentialField(appMap, "Nonexistent")).toBe(false);
  });
});

describe("routeLeaksCredentials", () => {
  const appMap = mkAppMap([
    {
      name: "User",
      fields: [
        { name: "id", type: "Int", isId: true },
        { name: "password", type: "String", isId: false },
      ],
    },
  ]);

  it("true when the route reads a credential-bearing model", () => {
    const route = {
      path: "/api/profile/:id",
      method: "GET" as const,
      authState: "public" as const,
      isApiRoute: true,
      referencedModels: [{ modelName: "User", operations: ["read" as const] }],
    };
    expect(routeLeaksCredentials(appMap, route)).toBe(true);
  });

  it("false when the route only WRITES the credential-bearing model (no read)", () => {
    const route = {
      path: "/api/profile/:id",
      method: "POST" as const,
      authState: "public" as const,
      isApiRoute: true,
      referencedModels: [{ modelName: "User", operations: ["write" as const] }],
    };
    expect(routeLeaksCredentials(appMap, route)).toBe(false);
  });

  it("false when route is undefined (unresolved)", () => {
    expect(routeLeaksCredentials(appMap, undefined)).toBe(false);
  });

  it("false when the route has no referencedModels at all", () => {
    const route = {
      path: "/api/x",
      method: "GET" as const,
      authState: "public" as const,
      isApiRoute: true,
    };
    expect(routeLeaksCredentials(appMap, route)).toBe(false);
  });
});
