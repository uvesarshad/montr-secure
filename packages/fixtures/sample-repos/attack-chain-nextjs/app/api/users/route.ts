import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get("q") ?? "";
  // VULN #1 (CWE-89): tainted `q` interpolated into a raw SQL query.
  const rows = await prisma.$queryRawUnsafe(
    `SELECT * FROM "User" WHERE name = '${q}'`,
  );
  return NextResponse.json(rows);
}
