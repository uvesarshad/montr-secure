import { NextRequest, NextResponse } from "next/server";

/**
 * VULN (CWE-918, SSRF / OWASP A10:2021): a user-supplied `url` is fetched
 * server-side with no allowlist or protocol/host validation, so an attacker can
 * reach internal services or the cloud metadata endpoint.
 */
export async function POST(req: NextRequest) {
  const { url } = await req.json();
  const upstream = await fetch(url); // SSRF sink — tainted `url` reaches the HTTP client
  const body = await upstream.text();
  return NextResponse.json({ body });
}
