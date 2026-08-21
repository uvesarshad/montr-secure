import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { detectCookiePolicyGaps } from "./cookie-policy.js";

describe("detectCookiePolicyGaps", () => {
  it("recommends the specific missing attributes for a session cookie missing all three", async () => {
    const files = memoryFileProvider([
      { path: "src/auth.ts", content: 'res.cookie("session_id", token);' },
    ]);
    const drafts = await detectCookiePolicyGaps(files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.gap).toContain("Secure, HttpOnly, SameSite");
  });

  it("recommends only the specific attribute that is missing", async () => {
    const files = memoryFileProvider([
      {
        path: "src/auth.ts",
        content: 'res.cookie("auth_token", token, { secure: true, httpOnly: true });',
      },
    ]);
    const drafts = await detectCookiePolicyGaps(files);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.title).toContain("SameSite");
    expect(drafts[0]?.title).not.toContain("Secure");
  });

  it("does NOT recommend anything for a fully-hardened session cookie (precision)", async () => {
    const files = memoryFileProvider([
      {
        path: "src/auth.ts",
        content:
          'res.cookie("session_id", token, { secure: true, httpOnly: true, sameSite: "lax" });',
      },
    ]);
    const drafts = await detectCookiePolicyGaps(files);
    expect(drafts).toHaveLength(0);
  });

  it("does NOT flag a non-session-looking cookie missing attributes", async () => {
    const files = memoryFileProvider([
      { path: "src/prefs.ts", content: 'res.cookie("theme", "dark");' },
    ]);
    const drafts = await detectCookiePolicyGaps(files);
    expect(drafts).toHaveLength(0);
  });

  it("matches Fastify's .setCookie(...) call shape too", async () => {
    const files = memoryFileProvider([
      { path: "src/auth.ts", content: 'reply.setCookie("session_id", token);' },
    ]);
    const drafts = await detectCookiePolicyGaps(files);
    expect(drafts).toHaveLength(1);
  });
});
