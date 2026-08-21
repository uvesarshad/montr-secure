import { withAuth } from "../../../lib/auth";

function handler(req: Request): Response {
  return new Response("ok");
}

export const GET = withAuth(handler);
