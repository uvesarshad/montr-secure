import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { getSession } from "@/lib/auth";

const prisma = new PrismaClient();

/**
 * VULN (CWE-284, Broken Access Control / OWASP A01:2021): an authenticated
 * session is required, but the caller's ROLE is never checked, so any regular
 * user can hit this admin endpoint and dump every user record.
 */
export async function GET(req: NextRequest) {
  await getSession(req); // role is never checked
  const users = await prisma.user.findMany();
  return NextResponse.json(users);
}
