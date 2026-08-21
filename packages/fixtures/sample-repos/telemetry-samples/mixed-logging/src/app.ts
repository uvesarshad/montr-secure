/**
 * Telemetry-surfaces fixture (B6): a single Express app with three routes
 * covering the three real per-route logging signals `telemetry-surfaces.ts`
 * detects — a structured `winston` logger call, a bare `console.log` call
 * (unstructured, ambiguous), and a route with no logging call at all.
 */
import express from "express";
import winston from "winston";

const app = express();
const logger = winston.createLogger({ transports: [] });

app.get("/orders", (req, res) => {
  logger.info("fetched orders", { userId: req.query.userId });
  res.json([]);
});

app.get("/health", (req, res) => {
  console.log("health check hit");
  res.json({ status: "ok" });
});

app.get("/secret", (req, res) => {
  res.json({ secret: true });
});

export default app;
