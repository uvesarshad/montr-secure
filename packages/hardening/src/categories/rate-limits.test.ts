import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { detectRateLimitGaps } from "./rate-limits.js";
import { baseAppMap, route, confirmedFinding } from "../test-helpers.js";

describe("detectRateLimitGaps", () => {
  it("recommends rate limiting for a public Express route with no limiter installed", async () => {
    const appMap = baseAppMap({
      frameworks: ["express"],
      routes: [route({ path: "/api/login", method: "POST", authState: "public" })],
    });
    const files = memoryFileProvider([
      { path: "package.json", content: JSON.stringify({ dependencies: { express: "^4.19.0" } }) },
    ]);
    const drafts = await detectRateLimitGaps(appMap, files, []);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.gap).toContain("POST /api/login");
    expect(drafts[0]?.recommendation).toContain("express-rate-limit");
  });

  it("does NOT recommend anything when a rate limiter is already a dependency (precision)", async () => {
    const appMap = baseAppMap({
      frameworks: ["express"],
      routes: [route({ path: "/api/login", method: "POST", authState: "public" })],
    });
    const files = memoryFileProvider([
      {
        path: "package.json",
        content: JSON.stringify({
          dependencies: { express: "^4.19.0", "express-rate-limit": "^7.0.0" },
        }),
      },
    ]);
    const drafts = await detectRateLimitGaps(appMap, files, []);
    expect(drafts).toHaveLength(0);
  });

  it("produces nothing when there are no public routes", async () => {
    const appMap = baseAppMap({
      frameworks: ["express"],
      routes: [route({ path: "/api/admin", method: "GET", authState: "authenticated" })],
    });
    const files = memoryFileProvider([]);
    const drafts = await detectRateLimitGaps(appMap, files, []);
    expect(drafts).toHaveLength(0);
  });

  it("attaches a matching rate_limit_missing confirmed finding id as related", async () => {
    const appMap = baseAppMap({
      frameworks: ["express"],
      routes: [route({ path: "/api/login", method: "POST", authState: "public" })],
    });
    const files = memoryFileProvider([]);
    const finding = confirmedFinding({ id: "finding_rl_1", category: "rate_limit_missing" });
    const drafts = await detectRateLimitGaps(appMap, files, [finding]);
    expect(drafts[0]?.relatedFindingIds).toContain("finding_rl_1");
  });
});
