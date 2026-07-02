/**
 * Session cookie helpers. The JWT lives in an httpOnly, SameSite=Strict cookie
 * (browser flow); the CSRF token lives in a JS-readable, SameSite=Strict cookie.
 * Both are Secure by default. API clients may instead pass `Authorization:
 * Bearer <jwt>` (returned in the login body) and skip cookies entirely.
 */
import type { CookieSerializeOptions } from "@fastify/cookie";
import type { FastifyInstance, FastifyReply } from "fastify";
import type { ResolvedDeps, SessionClaims } from "../types.js";

export const SESSION_COOKIE = "montr_session";
export { CSRF_COOKIE } from "./csrf.js";
import { CSRF_COOKIE } from "./csrf.js";

/** Sign a session JWT for the given claims (TTL is configured on the jwt plugin). */
export function signSession(app: FastifyInstance, claims: SessionClaims): string {
  return app.jwt.sign(claims);
}

function baseCookieOpts(deps: ResolvedDeps): CookieSerializeOptions {
  return {
    path: "/",
    secure: deps.cookieSecure,
    sameSite: "strict",
    maxAge: deps.sessionTtlMinutes * 60,
  };
}

export function setAuthCookies(
  reply: FastifyReply,
  deps: ResolvedDeps,
  token: string,
  csrfToken: string,
): void {
  reply.setCookie(SESSION_COOKIE, token, { ...baseCookieOpts(deps), httpOnly: true });
  // CSRF cookie is intentionally readable by same-origin JS (double-submit).
  reply.setCookie(CSRF_COOKIE, csrfToken, { ...baseCookieOpts(deps), httpOnly: false });
}

/** Re-issue only the CSRF cookie (e.g. GET /auth/csrf refresh). */
export function setCsrfCookie(reply: FastifyReply, deps: ResolvedDeps, csrfToken: string): void {
  reply.setCookie(CSRF_COOKIE, csrfToken, { ...baseCookieOpts(deps), httpOnly: false });
}

export function clearAuthCookies(reply: FastifyReply, deps: ResolvedDeps): void {
  const opts: CookieSerializeOptions = { path: "/", secure: deps.cookieSecure, sameSite: "strict" };
  reply.clearCookie(SESSION_COOKIE, opts);
  reply.clearCookie(CSRF_COOKIE, opts);
}
