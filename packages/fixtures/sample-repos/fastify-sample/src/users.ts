import type { FastifyInstance } from "fastify";

export function registerUserRoutes(app: FastifyInstance): void {
  app.get(
    "/users",
    { preHandler: requireAuth, schema: { tags: ["users"] } },
    async (req, reply) => {
      return [];
    },
  );

  app.route({
    method: "POST",
    url: "/users/:id",
    handler: async (req, reply) => {
      return { id: (req.params as { id: string }).id };
    },
  });
}

function requireAuth(): void {
  /* no-op guard stub */
}
