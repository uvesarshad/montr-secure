/**
 * AuthN + RBAC + CSRF plugin. Registers @fastify/cookie and @fastify/jwt, then
 * decorates the instance with:
 *   - authenticate    verify JWT (Authorization header OR session cookie)
 *   - requireRole     RBAC guard factory
 *   - requireApprover ⛔ hard approver guard (human gate + DAST authorization)
 *   - verifyCsrf      CSRF guard for cookie-authenticated mutations
 */
import fastifyCookie from "@fastify/cookie";
import fastifyJwt from "@fastify/jwt";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Role } from "@montr/contracts";
import { forbidden, unauthorized } from "../errors.js";
import type { AuthenticatedUser, ResolvedDeps } from "../types.js";
import { CSRF_COOKIE, CSRF_HEADER, safeEqual, verifyCsrfToken } from "../auth/csrf.js";
import { SESSION_COOKIE } from "../auth/session.js";

export async function registerAuth(app: FastifyInstance, deps: ResolvedDeps): Promise<void> {
  await app.register(fastifyCookie);

  await app.register(fastifyJwt, {
    secret: deps.jwtSecret,
    cookie: { cookieName: SESSION_COOKIE, signed: false },
    sign: { expiresIn: `${deps.sessionTtlMinutes}m` },
  });

  app.decorateRequest("authUser", undefined);
  app.decorateRequest("authMethod", undefined);

  app.decorate(
    "authenticate",
    async function authenticate(req: FastifyRequest, _reply: FastifyReply) {
      try {
        await req.jwtVerify();
      } catch {
        throw unauthorized();
      }
      const claims = req.user;
      const user: AuthenticatedUser = {
        id: claims.sub,
        clientId: claims.clientId,
        email: claims.email,
        role: claims.role,
      };
      req.authUser = user;
      const authz = req.headers.authorization;
      req.authMethod = authz && /^bearer /i.test(authz) ? "bearer" : "cookie";
    },
  );

  app.decorate("requireRole", function requireRole(...roles: Role[]) {
    return async function roleGuard(req: FastifyRequest, _reply: FastifyReply) {
      const user = req.authUser;
      if (!user) throw unauthorized();
      if (!roles.includes(user.role)) {
        throw forbidden(`Requires role: ${roles.join(" or ")}`, {
          required: roles,
          actual: user.role,
        });
      }
    };
  });

  // ⛔ Hard approver guard — the human gate AND DAST authorization require it
  // regardless of any config toggle (§11, golden rule #3/#4).
  app.decorate(
    "requireApprover",
    async function requireApprover(req: FastifyRequest, _reply: FastifyReply) {
      const user = req.authUser;
      if (!user) throw unauthorized();
      if (user.role !== "approver") {
        throw forbidden("Approver role required", { required: ["approver"], actual: user.role });
      }
    },
  );

  app.decorate("verifyCsrf", async function verifyCsrf(req: FastifyRequest, _reply: FastifyReply) {
    // Bearer-token requests carry no ambient credential and are not CSRF-able.
    if (req.authMethod !== "cookie") return;
    const user = req.authUser;
    if (!user) throw unauthorized();
    const rawHeader = req.headers[CSRF_HEADER];
    const header = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
    const cookie = req.cookies[CSRF_COOKIE];
    if (!header || !cookie || !safeEqual(header, cookie)) {
      throw forbidden("CSRF token missing or mismatched", {
        hint: `send the '${CSRF_HEADER}' header matching the '${CSRF_COOKIE}' cookie`,
      });
    }
    if (!verifyCsrfToken(deps.csrfSecret, user.id, cookie)) {
      throw forbidden("CSRF token invalid");
    }
  });
}
