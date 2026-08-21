import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/** One-hop indirection target: the route handler calls THIS, not prisma directly. */
export async function getWidgets(): Promise<unknown> {
  return prisma.widget.findMany();
}
