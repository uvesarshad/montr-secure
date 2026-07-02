import { NextRequest, NextResponse } from "next/server";

// Server-side fetch is constrained to an explicit https allowlist — SSRF-safe.
const ALLOWED_HOSTS = new Set(["api.example.com"]);

export async function POST(req: NextRequest) {
  const { url } = await req.json();
  const parsed = new URL(String(url));
  if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) {
    return NextResponse.json({ error: "host not allowed" }, { status: 400 });
  }
  const upstream = await fetch(parsed.toString());
  return NextResponse.json({ body: await upstream.text() });
}
