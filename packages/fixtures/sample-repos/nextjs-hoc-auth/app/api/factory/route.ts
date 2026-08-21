import { checkPermission } from "../../../lib/auth";

function handler(req: Request): Response {
  return new Response("ok");
}

export const GET = checkPermission("admin")(handler);
