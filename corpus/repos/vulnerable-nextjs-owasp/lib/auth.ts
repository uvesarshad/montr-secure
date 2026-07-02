import type { NextRequest } from "next/server";

/**
 * Minimal session helper for the corpus repo. The point of these cases is what
 * the ROUTES fail to check (ownership, role, cookie flags) — not this helper.
 */
export async function getSession(_req: NextRequest) {
  return { userId: 1, role: "user" as const };
}
