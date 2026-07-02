import { NextResponse } from "next/server";

export async function POST() {
  const res = NextResponse.json({ ok: true });
  // Hardened cookie: Secure + HttpOnly + SameSite.
  res.cookies.set("session", "s3ss10n-token", {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
  return res;
}
