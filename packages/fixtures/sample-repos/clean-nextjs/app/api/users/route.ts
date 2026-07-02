import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { requireSession } from "@/lib/auth";

const prisma = new PrismaClient();
export async function GET(req: NextRequest) {
  await requireSession(req); // auth-gated
  const q = req.nextUrl.searchParams.get("q") ?? "";
  // Parameterized query — `q` can never alter SQL structure.
  const rows = await prisma.user.findMany({ where: { name: q } });
  return NextResponse.json(rows, {
    headers: { "Access-Control-Allow-Origin": "https://app.example.com" }, // scoped CORS
  });
}
