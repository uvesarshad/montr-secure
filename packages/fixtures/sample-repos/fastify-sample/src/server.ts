import Fastify from "fastify";
import { registerUserRoutes } from "./users.js";

const app = Fastify();
registerUserRoutes(app);

app.get("/health", async () => ({ status: "ok" }));

export default app;
