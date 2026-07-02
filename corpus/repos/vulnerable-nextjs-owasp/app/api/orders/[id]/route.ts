import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { getSession } from "@/lib/auth";

const prisma = new PrismaClient();

/**
 * VULN (CWE-639, IDOR / OWASP A01:2021): the order is looked up by the `id` from
 * the URL with NO check that it belongs to the authenticated user, so any logged
 * in user can read any other user's order by guessing/enumerating ids.
 */
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  await getSession(req); // authenticated, but ownership is never verified
  const order = await prisma.order.findUnique({ where: { id: Number(params.id) } });
  return NextResponse.json(order);
}
