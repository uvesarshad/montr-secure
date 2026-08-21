import { getServerSession } from "./lib/auth";

export async function middleware(): Promise<Response | undefined> {
  const session = await getServerSession();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  return undefined;
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
