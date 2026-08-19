/**
 * ⛔ Golden rule #7 (§8.5): every mutating action is bound to a tamper-evident
 * audit event. This covers the logout route specifically — logging out MUST
 * record an `auth.logout` event when a valid session is presented, yet MUST NOT
 * fail (or audit) when no credential is present (a logout can never 500 a user).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, createInMemoryDeps } from "../server.js";

const EMAIL = "operator@example.internal";
const PASSWORD = "correct-horse-battery-staple"; // ≥ 12 chars (PasswordSchema)

describe("POST /auth/logout — records an auth.logout audit event", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;

  beforeAll(async () => {
    deps = createInMemoryDeps();
    app = await buildServer(deps);
  });

  afterAll(async () => {
    await app.close();
  });

  it("⛔ appends an auth.logout audit event bound to the session actor (metadata-only)", async () => {
    // Bootstrap user (first registrant) + login for a bearer session.
    const reg = await app.inject({
      method: "POST",
      url: "/api/v1/auth/register",
      payload: { email: EMAIL, password: PASSWORD },
    });
    expect(reg.statusCode).toBe(201);

    const login = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: EMAIL, password: PASSWORD },
    });
    expect(login.statusCode).toBe(200);
    const { token, user } = login.json() as { token: string; user: { id: string } };

    const logout = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(logout.statusCode).toBe(204);

    const events = await deps.store.audit.list(deps.config.clientId);
    const logouts = events.filter((e) => e.action === "auth.logout");
    expect(logouts).toHaveLength(1);
    expect(logouts[0]!.actor.id).toBe(user.id);
    expect(logouts[0]!.targetId).toBe(user.id);
    // ⛔ The audit record carries metadata only — never the session token.
    expect(JSON.stringify(logouts[0]!.metadata)).not.toContain(token);
  });

  it("clears cookies WITHOUT auditing when no valid session is presented (logout never fails)", async () => {
    const before = (await deps.store.audit.list(deps.config.clientId)).filter(
      (e) => e.action === "auth.logout",
    ).length;

    const logout = await app.inject({ method: "POST", url: "/api/v1/auth/logout" });
    expect(logout.statusCode).toBe(204);

    const after = (await deps.store.audit.list(deps.config.clientId)).filter(
      (e) => e.action === "auth.logout",
    ).length;
    expect(after).toBe(before); // an anonymous logout records nothing
  });
});
