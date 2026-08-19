/**
 * Shared request-header helpers for the real cookie/JWT auth flow, plus the
 * MSW-only demo-actor hint. Used by lib/api/client.ts and the co-located
 * app/{schedules,scenarios,rules}/hooks.ts files (each has its own small fetch
 * wrapper — see those files' header comments for why).
 */
import {
  CSRF_COOKIE,
  CSRF_HEADER,
  MOCK_ACTOR_ID_HEADER,
  MOCK_ACTOR_ROLE_HEADER,
  isMswEnabled,
} from "./config.js";
import type { Actor } from "./types.js";

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match?.[1] ? decodeURIComponent(match[1]) : undefined;
}

/**
 * CSRF header for cookie-authenticated mutations (OWASP double-submit
 * pattern — apps/api/src/auth/csrf.ts). Reads the JS-readable `montr_csrf`
 * cookie the API sets on login and echoes it back in the `x-csrf-token`
 * header; the API rejects cookie-authenticated mutations without it.
 * Bearer-token requests don't need this (no ambient credential to forge), but
 * this console always authenticates via cookie.
 */
export function csrfHeaders(): Record<string, string> {
  const token = readCookie(CSRF_COOKIE);
  return token ? { [CSRF_HEADER]: token } : {};
}

/**
 * MSW-only actor hint for the dev role-switcher (see components/role-context
 * + mocks/handlers.ts `getActor`). NEVER sent unless MSW mocking is enabled,
 * and never trusted for real authorization — the real API always derives the
 * actor from the verified session, never a client-supplied header.
 */
export function mockActorHeaders(actor?: Actor): Record<string, string> {
  if (!isMswEnabled || !actor) return {};
  return { [MOCK_ACTOR_ID_HEADER]: actor.id, [MOCK_ACTOR_ROLE_HEADER]: actor.role };
}
