import { NextResponse } from "next/server";

/**
 * VULN (CWE-614/CWE-1004, Insecure Cookie / OWASP A05:2021): the session cookie
 * is set WITHOUT the Secure, HttpOnly, or SameSite flags, exposing it to theft
 * over plaintext, JavaScript access (XSS), and cross-site request forgery.
 */
export async function POST() {
  const res = NextResponse.json({ ok: true });
  res.cookies.set("session", "s3ss10n-token", { path: "/" });
  return res;
}
