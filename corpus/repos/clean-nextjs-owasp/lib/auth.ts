import type { NextRequest } from "next/server";

/** Minimal session helper for the corpus repo (secured counterpart). */
export async function getSession(_req: NextRequest) {
  return { userId: 1, role: "user" as const };
}
