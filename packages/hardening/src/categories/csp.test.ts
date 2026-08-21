import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { detectCspGap } from "./csp.js";
import { baseAppMap, route } from "../test-helpers.js";

describe("detectCspGap", () => {
  it("produces nothing when the app has no HTTP routes", async () => {
    const appMap = baseAppMap({ routes: [] });
    const files = memoryFileProvider([
      {
        path: "src/Widget.tsx",
        content: "export const Widget = () => <div dangerouslySetInnerHTML={{ __html: x }} />;",
      },
    ]);
    const drafts = await detectCspGap(appMap, files);
    expect(drafts).toHaveLength(0);
  });

  it("recommends a nonce-based script-src when inline scripts (dangerouslySetInnerHTML) are detected and no CSP exists", async () => {
    const appMap = baseAppMap({ routes: [route()] });
    const files = memoryFileProvider([
      {
        path: "src/Widget.tsx",
        content: "export const Widget = () => <div dangerouslySetInnerHTML={{ __html: x }} />;",
      },
    ]);
    const drafts = await detectCspGap(appMap, files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.recommendation).toContain("nonce");
    expect(drafts[0]?.recommendation).not.toMatch(/script-src[^;]*unsafe-inline/);
  });

  it("recommends a plain script-src 'self' when no inline scripts are found", async () => {
    const appMap = baseAppMap({ routes: [route()] });
    const files = memoryFileProvider([
      {
        path: "src/Widget.tsx",
        content: 'export const Widget = () => <script src="/bundle.js" />;',
      },
    ]);
    const drafts = await detectCspGap(appMap, files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.recommendation).toContain("script-src 'self';");
  });

  it("does NOT recommend anything when a strong CSP is already set (precision)", async () => {
    const appMap = baseAppMap({ routes: [route()] });
    const files = memoryFileProvider([
      {
        path: "src/app.ts",
        content:
          "res.setHeader(\"Content-Security-Policy\", \"default-src 'self'; script-src 'self'\");",
      },
    ]);
    const drafts = await detectCspGap(appMap, files);
    expect(drafts).toHaveLength(0);
  });

  it("flags an existing CSP that allows unsafe-inline as weak", async () => {
    const appMap = baseAppMap({ routes: [route()] });
    const files = memoryFileProvider([
      {
        path: "src/app.ts",
        content:
          "res.setHeader(\"Content-Security-Policy\", \"default-src 'self'; script-src 'self' 'unsafe-inline'\");",
      },
    ]);
    const drafts = await detectCspGap(appMap, files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.title).toContain("Tighten");
  });
});
