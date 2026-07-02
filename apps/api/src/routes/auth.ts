/**
 * Auth routes: register, login, logout, session (me), CSRF token, role change.
 *
 * Safety posture:
 *  - Passwords hashed with scrypt; login compares in constant time and runs a
 *    decoy hash for unknown users (no timing/enumeration oracle).
 *  - Self-registration grants the least-privilege `viewer` role; only the very
 *    first (bootstrap) user of a client may claim a higher role (golden rule #4).
 *  - Role changes are approver-gated, CSRF-protected, and audited.
 */
import type { FastifyInstance } from "fastify";
import type { Role } from "@montr/contracts";
import { conflict, notFound, unauthorized } from "../errors.js";
import { parseBody } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { decoyHash, hashPassword, verifyPassword } from "../auth/password.js";
import { issueCsrfToken } from "../auth/csrf.js";
import { clearAuthCookies, setAuthCookies, setCsrfCookie, signSession } from "../auth/session.js";
import { toPublicUser, type UserRecord } from "../auth/users.js";
import type { ResolvedDeps, SessionClaims } from "../types.js";
import { ChangeRoleBodySchema, LoginBodySchema, RegisterBodySchema } from "../schemas.js";

export function registerAuthRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const clientId = deps.config.clientId;

  app.post(
    "/auth/register",
    {
      config: { rateLimit: deps.authRate },
      schema: { tags: ["auth"], summary: "Register a new user" },
    },
    async (req, reply) => {
      const body = parseBody(RegisterBodySchema, req);

      const existing = await deps.store.users.findByEmail(clientId, body.email);
      if (existing) throw conflict("A user with this email already exists");

      const isBootstrap = (await deps.store.users.countForClient(clientId)) === 0;
      // Least privilege: only the bootstrap user may claim a non-viewer role.
      const role: Role = isBootstrap ? (body.role ?? "approver") : "viewer";

      const now = deps.clock.now().toISOString();
      const record: UserRecord = {
        id: deps.idgen("user"),
        clientId,
        email: body.email,
        passwordHash: await hashPassword(body.password),
        role,
        createdAt: now,
        updatedAt: now,
      };
      const created = await deps.store.users.create(record);

      await recordAudit(deps.store, {
        clientId,
        actor: { type: "user", id: created.id, role: created.role },
        action: "auth.role_changed",
        targetType: "user",
        targetId: created.id,
        summary: `User registered with role '${role}'${isBootstrap ? " (bootstrap)" : ""}`,
        metadata: { email: created.email, role, bootstrap: isBootstrap },
      });

      reply.status(201);
      return { user: toPublicUser(created) };
    },
  );

  app.post(
    "/auth/login",
    {
      config: { rateLimit: deps.authRate },
      schema: { tags: ["auth"], summary: "Log in and receive a session (cookie + bearer token)" },
    },
    async (req, reply) => {
      const body = parseBody(LoginBodySchema, req);
      const user = await deps.store.users.findByEmail(clientId, body.email);

      if (!user) {
        // Equalize timing against the "user exists" path to prevent enumeration.
        await verifyPassword(body.password, await decoyHash());
        throw unauthorized("Invalid email or password");
      }
      const ok = await verifyPassword(body.password, user.passwordHash);
      if (!ok) throw unauthorized("Invalid email or password");

      const claims: SessionClaims = {
        sub: user.id,
        clientId,
        email: user.email,
        role: user.role,
      };
      const token = signSession(app, claims);
      const csrfToken = issueCsrfToken(deps.csrfSecret, user.id);
      setAuthCookies(reply, deps, token, csrfToken);

      await recordAudit(deps.store, {
        clientId,
        actor: actorFromUser({ id: user.id, clientId, email: user.email, role: user.role }),
        action: "auth.login",
        targetType: "user",
        targetId: user.id,
        summary: `User '${user.email}' logged in`,
        metadata: { email: user.email },
      });

      return { user: toPublicUser(user), token, csrfToken };
    },
  );

  app.post(
    "/auth/logout",
    { schema: { tags: ["auth"], summary: "Clear the session cookies" } },
    async (req, reply) => {
      // Best-effort audit (golden rule #7): if a valid session is presented,
      // record the logout in the tamper-evident trail. An absent/expired session
      // still clears cookies — logout must never fail on a missing credential.
      try {
        await req.jwtVerify();
        const claims = req.user;
        await recordAudit(deps.store, {
          clientId,
          actor: { type: "user", id: claims.sub, role: claims.role },
          action: "auth.logout",
          targetType: "user",
          targetId: claims.sub,
          summary: `User '${claims.email}' logged out`,
          metadata: { email: claims.email },
        });
      } catch {
        /* no valid session — nothing to audit; still clear cookies below */
      }
      clearAuthCookies(reply, deps);
      reply.status(204);
      return null;
    },
  );

  app.get(
    "/auth/me",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["auth"],
        summary: "Current session",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      return { user: req.authUser };
    },
  );

  app.get(
    "/auth/csrf",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["auth"],
        summary: "Issue a CSRF token bound to the session",
        security: [{ cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const csrfToken = issueCsrfToken(deps.csrfSecret, user.id);
      setCsrfCookie(reply, deps, csrfToken);
      return { csrfToken };
    },
  );

  // ⛔ Role changes require the approver role, CSRF, and are audited.
  app.post(
    "/auth/role",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["auth"],
        summary: "Change a user's role (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(ChangeRoleBodySchema, req);

      const updated = await deps.store.users.updateRole(clientId, body.userId, body.role);
      if (!updated) throw notFound("User not found");

      await recordAudit(deps.store, {
        clientId,
        actor: actorFromUser(user),
        action: "auth.role_changed",
        targetType: "user",
        targetId: body.userId,
        summary: `Role of user '${updated.email}' changed to '${body.role}'`,
        metadata: { userId: body.userId, newRole: body.role },
      });

      return { user: toPublicUser(updated) };
    },
  );
}
