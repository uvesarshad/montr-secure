/**
 * CSRF protection for cookie-based auth — OWASP "signed double-submit" pattern.
 *
 * The token is `<randomHex>.<hmac>` where
 *   hmac = HMAC-SHA256(csrfSecret, `${sessionSubject}.${randomHex}`).
 * It is delivered both in a JS-readable cookie (`montr_csrf`) and expected back
 * in the `x-csrf-token` request header. A cross-site attacker can neither read
 * our cookie (same-origin policy) nor forge the HMAC (secret unknown), so a
 * mutating request only succeeds when both copies match AND the HMAC binds to
 * the authenticated session. Bearer-token requests are exempt (no ambient
 * credential is sent automatically, so they are not CSRF-able).
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const CSRF_HEADER = "x-csrf-token";
export const CSRF_COOKIE = "montr_csrf";

function sign(secret: string, subject: string, nonce: string): string {
  return createHmac("sha256", secret).update(`${subject}.${nonce}`).digest("hex");
}

/** Mint a CSRF token bound to the given session subject (user id). */
export function issueCsrfToken(secret: string, subject: string): string {
  const nonce = randomBytes(18).toString("hex");
  return `${nonce}.${sign(secret, subject, nonce)}`;
}

/** Constant-time string comparison that tolerates unequal lengths. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) {
    // Still run a comparison to avoid leaking length via early return timing.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/** Validate that a CSRF token is well-formed and HMAC-bound to `subject`. */
export function verifyCsrfToken(
  secret: string,
  subject: string,
  token: string | undefined,
): boolean {
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) return false;
  const nonce = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = sign(secret, subject, nonce);
  return safeEqual(mac, expected);
}
