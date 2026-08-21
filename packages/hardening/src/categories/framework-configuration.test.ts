import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { detectFrameworkConfigurationGaps } from "./framework-configuration.js";
import { baseAppMap } from "../test-helpers.js";

describe("detectFrameworkConfigurationGaps", () => {
  it("recommends disabling poweredByHeader when next.config doesn't set it", async () => {
    const appMap = baseAppMap({ frameworks: ["nextjs"] });
    const files = memoryFileProvider([
      { path: "next.config.js", content: "module.exports = { reactStrictMode: true };" },
    ]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: false });
    expect(drafts.some((d) => d.title.includes("X-Powered-By") && d.framework === "nextjs")).toBe(
      true,
    );
  });

  it("does NOT recommend poweredByHeader change when already false (precision)", async () => {
    const appMap = baseAppMap({ frameworks: ["nextjs"] });
    const files = memoryFileProvider([
      { path: "next.config.js", content: "module.exports = { poweredByHeader: false };" },
    ]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: false });
    expect(drafts.filter((d) => d.framework === "nextjs")).toHaveLength(0);
  });

  it("recommends app.disable(x-powered-by) for Express with no helmet and no disable call", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([{ path: "src/app.ts", content: "const app = express();" }]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: false });
    expect(drafts.some((d) => d.title.includes("X-Powered-By") && d.framework === "express")).toBe(
      true,
    );
  });

  it("does NOT recommend x-powered-by disable when helmet already covers it (precision)", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([{ path: "src/app.ts", content: "const app = express();" }]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: true });
    expect(drafts.filter((d) => d.title.includes("X-Powered-By"))).toHaveLength(0);
  });

  it("recommends trust proxy config for Express using req.ip with none configured", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([
      {
        path: "src/app.ts",
        content: "const app = express();\napp.get('/x', (req,res)=>{ log(req.ip); });",
      },
    ]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: true });
    expect(drafts.some((d) => d.title.includes("trust proxy"))).toBe(true);
  });

  it("does NOT recommend trust proxy config when already set (precision)", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([
      {
        path: "src/app.ts",
        content:
          "const app = express();\napp.set('trust proxy', 1);\napp.get('/x', (req,res)=>{ log(req.ip); });",
      },
    ]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: true });
    expect(drafts.filter((d) => d.title.includes("trust proxy"))).toHaveLength(0);
  });

  it("does NOT recommend trust proxy config when req.ip/rate-limiter are never used", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([{ path: "src/app.ts", content: "const app = express();" }]);
    const drafts = await detectFrameworkConfigurationGaps(appMap, files, { helmetDetected: true });
    expect(drafts.filter((d) => d.title.includes("trust proxy"))).toHaveLength(0);
  });
});
