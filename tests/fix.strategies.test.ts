import { describe, it, expect } from "vitest";
import { pickStrategy, FIX_STRATEGIES, AUTO_ELIGIBLE_CATEGORIES } from "@montr/fix";
import { mockConfirmedFindings } from "@montr/fixtures";
import type { Category, ConfirmedFinding } from "@montr/contracts";

/**
 * Direct unit tests for the deterministic mechanical fix strategies (A14).
 * Mirrors the existing sql_injection/xss coverage in fix.generation.test.ts,
 * but exercises each strategy in isolation: vulnerable() flips false→true
 * around apply(), and the generated proof-of-fix test genuinely detects the
 * vulnerability was fixed (fails pre-patch / passes post-patch).
 */

const baseConfirmed = mockConfirmedFindings[0] as ConfirmedFinding;

function confirmedWith(category: Category, file: string): ConfirmedFinding {
  return { ...baseConfirmed, category, location: { ...baseConfirmed.location, file } };
}

describe("@montr/fix — nosql_injection strategy", () => {
  const strategy = pickStrategy("nosql_injection")!;
  const original = `const user = await db.collection("users").findOne({ username: req.body.username, password: req.body.password });\n`;

  it("detects the vulnerable pattern and produces a fix that passes the predicate", () => {
    expect(strategy.vulnerable(original)).toBe(true);
    const fixed = strategy.apply(original)!;
    expect(fixed).not.toBeNull();
    expect(fixed).toContain("String(req.body.username)");
    expect(fixed).toContain("String(req.body.password)");
    expect(strategy.vulnerable(fixed)).toBe(false);
  });

  it("leaves already-safe queries and unrelated code untouched", () => {
    const safe = `const user = await Model.find({ name: String(req.query.name) });\n`;
    expect(strategy.vulnerable(safe)).toBe(false);
    expect(strategy.apply(safe)).toBeNull();

    const unrelated = `res.json({ echo: req.body.name });\n`;
    expect(strategy.vulnerable(unrelated)).toBe(false);
    expect(strategy.apply(unrelated)).toBeNull();
  });

  it("generates a proof-of-fix test that fails pre-patch and passes post-patch", () => {
    const finding = confirmedWith("nosql_injection", "app/api/login/route.ts");
    const code = strategy.proofTestCode("app/api/login/route.ts", finding);
    expect(code).toContain("readFileSync");
    expect(code).toContain("not.toMatch");
    expect(code).toContain("toMatch");
  });
});

describe("@montr/fix — insecure_cookie strategy", () => {
  const strategy = pickStrategy("insecure_cookie")!;

  it("adds all three missing flags to a bare cookie call", () => {
    const original = `res.cookie("session", token);\n`;
    expect(strategy.vulnerable(original)).toBe(true);
    const fixed = strategy.apply(original)!;
    expect(fixed).toContain("secure: true");
    expect(fixed).toContain("httpOnly: true");
    expect(fixed).toContain('sameSite: "lax"');
    expect(strategy.vulnerable(fixed)).toBe(false);
  });

  it("preserves existing options and only appends the missing flags", () => {
    const original = `res.cookie("session", token, { path: "/", httpOnly: true });\n`;
    const fixed = strategy.apply(original)!;
    expect(fixed).toContain('path: "/"');
    expect(fixed).toContain("httpOnly: true");
    expect(fixed).toContain("secure: true");
    expect(fixed).toContain('sameSite: "lax"');
    expect(strategy.vulnerable(fixed)).toBe(false);
    // Only one httpOnly flag — not duplicated.
    expect(fixed.match(/httpOnly/g)?.length).toBe(1);
  });

  it("does not flag a cookie call that already sets all three flags", () => {
    const alreadySafe = `res.cookie("session", token, { secure: true, httpOnly: true, sameSite: "strict" });\n`;
    expect(strategy.vulnerable(alreadySafe)).toBe(false);
    expect(strategy.apply(alreadySafe)).toBeNull();
  });
});

describe("@montr/fix — missing_security_headers strategy", () => {
  const strategy = pickStrategy("missing_security_headers")!;
  const original = `/** @type {import('next').NextConfig} */\nconst nextConfig = {\n  reactStrictMode: true,\n};\nmodule.exports = nextConfig;\n`;

  it("injects a standard headers() block into a config with none", () => {
    expect(strategy.vulnerable(original)).toBe(true);
    const fixed = strategy.apply(original)!;
    expect(fixed).toContain("X-Content-Type-Options");
    expect(fixed).toContain("X-Frame-Options");
    expect(fixed).toContain("Strict-Transport-Security");
    expect(fixed).toContain("reactStrictMode: true"); // existing config preserved
    expect(strategy.vulnerable(fixed)).toBe(false);
  });

  it("does not re-fire on a config that already defines security headers", () => {
    const already = `module.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [{ key: "X-Content-Type-Options", value: "nosniff" }] }];\n  },\n};\n`;
    expect(strategy.vulnerable(already)).toBe(false);
    expect(strategy.apply(already)).toBeNull();
  });
});

describe("@montr/fix — open_redirect strategy", () => {
  const strategy = pickStrategy("open_redirect")!;

  it("guards a tainted redirect target to same-origin relative paths", () => {
    const original = `return res.redirect(req.query.next);\n`;
    expect(strategy.vulnerable(original)).toBe(true);
    const fixed = strategy.apply(original)!;
    expect(fixed).toContain('.startsWith("/")');
    expect(fixed).toContain('.startsWith("//")');
    expect(strategy.vulnerable(fixed)).toBe(false);
  });

  it("does not touch a static string redirect target", () => {
    const original = `return res.redirect("/login");\n`;
    expect(strategy.vulnerable(original)).toBe(false);
    expect(strategy.apply(original)).toBeNull();
  });

  it("does not guess at a complex (call-expression) redirect target", () => {
    const original = `return res.redirect(getUrl());\n`;
    expect(strategy.vulnerable(original)).toBe(false);
    expect(strategy.apply(original)).toBeNull();
  });
});

describe("@montr/fix — FIX_STRATEGIES / AUTO_ELIGIBLE_CATEGORIES consistency (A14)", () => {
  it("every implemented strategy's proof test is well-formed vitest source", () => {
    for (const strategy of FIX_STRATEGIES) {
      const finding = confirmedWith(strategy.category, "app/some/file.ts");
      const code = strategy.proofTestCode("app/some/file.ts", finding);
      expect(code).toContain("describe(");
      expect(code).toContain("readFileSync");
    }
  });

  it("every auto-eligible category resolves to an implemented strategy via pickStrategy", () => {
    for (const category of AUTO_ELIGIBLE_CATEGORIES) {
      expect(pickStrategy(category), category).toBeDefined();
    }
  });
});
