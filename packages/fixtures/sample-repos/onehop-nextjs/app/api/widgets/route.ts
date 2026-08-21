import { NextResponse } from "next/server";
import { getWidgets } from "../../../lib/repo.js";

export async function GET() {
  // The handler itself calls no prisma method directly — the model reference
  // is only reachable one hop away, through `getWidgets()` (A18 one-hop test).
  const widgets = await getWidgets();
  return NextResponse.json(widgets);
}
