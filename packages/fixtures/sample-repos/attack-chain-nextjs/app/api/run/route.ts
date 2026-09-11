import { NextRequest, NextResponse } from "next/server";
import { execSync } from "node:child_process";

export async function GET(req: NextRequest) {
  const cmd = req.nextUrl.searchParams.get("cmd") ?? "";
  // VULN #2 (CWE-78): tainted `cmd` passed directly to a shell command.
  const output = execSync(cmd).toString();
  return NextResponse.json({ output });
}
