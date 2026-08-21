import type { Express } from "express";

export function registerPublicRoutes(app: Express): void {
  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });
}
