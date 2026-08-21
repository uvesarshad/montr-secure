import express from "express";
import { registerPublicRoutes } from "./public.js";

const app = express();
const usersRouter = express.Router();

usersRouter.get("/", (req, res) => {
  res.json([]);
});

usersRouter.post("/:id", requireAuth, (req, res) => {
  res.json({ id: req.params.id });
});

app.use("/users", usersRouter);
registerPublicRoutes(app);

function requireAuth(req: unknown, res: unknown, next: () => void): void {
  next();
}

export default app;
