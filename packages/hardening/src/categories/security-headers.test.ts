import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { detectSecurityHeaderGaps } from "./security-headers.js";
import { baseAppMap } from "../test-helpers.js";

describe("detectSecurityHeaderGaps", () => {
  it("recommends helmet() for an Express app with no helmet dependency", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([
      { path: "package.json", content: JSON.stringify({ dependencies: { express: "^4.19.0" } }) },
      { path: "src/app.ts", content: 'import express from "express";\nconst app = express();\n' },
    ]);

    const { drafts, signals } = await detectSecurityHeaderGaps(appMap, files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.category).toBe("security_headers");
    expect(drafts[0]?.recommendation).toContain("helmet()");
    expect(signals.helmetDetected).toBe(false);
  });

  it("does NOT recommend helmet when it is already an installed dependency (precision)", async () => {
    const appMap = baseAppMap({ frameworks: ["express"] });
    const files = memoryFileProvider([
      {
        path: "package.json",
        content: JSON.stringify({ dependencies: { express: "^4.19.0", helmet: "^7.0.0" } }),
      },
      { path: "src/app.ts", content: 'import helmet from "helmet";\napp.use(helmet());\n' },
    ]);

    const { drafts, signals } = await detectSecurityHeaderGaps(appMap, files);
    expect(drafts).toHaveLength(0);
    expect(signals.helmetDetected).toBe(true);
  });

  it("recommends @fastify/helmet for a Fastify app missing it", async () => {
    const appMap = baseAppMap({ frameworks: ["fastify"] });
    const files = memoryFileProvider([
      { path: "package.json", content: JSON.stringify({ dependencies: { fastify: "^4.0.0" } }) },
    ]);

    const { drafts } = await detectSecurityHeaderGaps(appMap, files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.framework).toBe("fastify");
    expect(drafts[0]?.recommendation).toContain("@fastify/helmet");
  });

  it("recommends a headers() config for Next.js with no next.config headers export", async () => {
    const appMap = baseAppMap({ frameworks: ["nextjs"] });
    const files = memoryFileProvider([
      { path: "next.config.js", content: "module.exports = { reactStrictMode: true };\n" },
    ]);

    const { drafts } = await detectSecurityHeaderGaps(appMap, files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.framework).toBe("nextjs");
    expect(drafts[0]?.gap).toContain("next.config.js");
  });

  it("does NOT recommend a headers() config when one already exists (precision)", async () => {
    const appMap = baseAppMap({ frameworks: ["nextjs"] });
    const files = memoryFileProvider([
      {
        path: "next.config.js",
        content: "module.exports = { async headers() { return []; } };\n",
      },
    ]);

    const { drafts } = await detectSecurityHeaderGaps(appMap, files);
    expect(drafts).toHaveLength(0);
  });

  it("produces nothing for a framework it has no coverage for", async () => {
    const appMap = baseAppMap({ frameworks: ["django"] });
    const files = memoryFileProvider([]);
    const { drafts } = await detectSecurityHeaderGaps(appMap, files);
    expect(drafts).toHaveLength(0);
  });
});
