import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { HardeningRecommendationSchema } from "@montr/contracts";
import { generateHardeningRecommendations } from "./generate.js";
import { baseAppMap, route, confirmedFinding, NOW } from "./test-helpers.js";

describe("generateHardeningRecommendations", () => {
  it("assembles real, schema-valid recommendations across categories for a vulnerable target", async () => {
    const appMap = baseAppMap({
      frameworks: ["express"],
      routes: [route({ path: "/api/login", method: "POST", authState: "public" })],
    });
    const files = memoryFileProvider([
      { path: "package.json", content: JSON.stringify({ dependencies: { express: "^4.19.0" } }) },
      { path: "src/app.ts", content: 'res.cookie("session_id", token);' },
    ]);
    const findings = [confirmedFinding({ id: "f1", category: "ssrf" })];

    const recs = await generateHardeningRecommendations({
      appMap,
      files,
      confirmedFindings: findings,
      now: () => NOW,
    });

    expect(recs.length).toBeGreaterThan(0);
    for (const r of recs) {
      expect(() => HardeningRecommendationSchema.parse(r)).not.toThrow();
      expect(r.createdAt).toBe(NOW);
      expect(r.evidence.length).toBeGreaterThan(0);
    }

    const categories = new Set(recs.map((r) => r.category));
    expect(categories.has("security_headers")).toBe(true);
    expect(categories.has("cookie_policy")).toBe(true);
    expect(categories.has("rate_limits")).toBe(true);
    expect(categories.has("network_policy")).toBe(true);
  });

  it("produces nothing for a clean target with no detected gaps and no findings", async () => {
    const appMap = baseAppMap({ frameworks: [], routes: [] });
    const files = memoryFileProvider([]);
    const recs = await generateHardeningRecommendations({
      appMap,
      files,
      confirmedFindings: [],
      now: () => NOW,
    });
    expect(recs).toHaveLength(0);
  });

  it("assigns stable, deterministic ids for identical drafts", async () => {
    const appMap = baseAppMap({ frameworks: ["express"], routes: [] });
    const files = memoryFileProvider([
      { path: "package.json", content: JSON.stringify({ dependencies: { express: "^4.19.0" } }) },
    ]);
    const runOnce = () => generateHardeningRecommendations({ appMap, files, now: () => NOW });
    const [a, b] = await Promise.all([runOnce(), runOnce()]);
    expect(a.map((r) => r.id)).toEqual(b.map((r) => r.id));
  });
});
