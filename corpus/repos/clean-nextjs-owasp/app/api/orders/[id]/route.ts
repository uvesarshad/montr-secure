import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { getSession } from "@/lib/auth";

const prisma = new PrismaClient();

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const session = await getSession(req);
  const order = await prisma.order.findUnique({ where: { id: Number(params.id) } });
  // Ownership check — a user can only read their own order.
  if (!order || order.userId !== session.userId) {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  return NextResponse.json(order);
}
