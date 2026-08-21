/**
 * Architectural boundary test (B9, load-bearing — see index.ts's module
 * doc). This package must have ZERO auto-apply capability: it must never
 * IMPORT `@montr/fix` (the Layer 4 risk classifier / patch generator), and
 * it must never reference the risk-classification vocabulary
 * (`classifyFixRisk`/`classifyConfirmedFindingRisk`/`AUTO_ELIGIBLE_CATEGORIES`)
 * as real CODE (as opposed to this package's own documentation prose, which
 * legitimately names those symbols to EXPLAIN the boundary — see e.g.
 * index.ts's module doc). Comments are stripped before the vocabulary check
 * runs so documenting the boundary does not trip the test meant to guard it.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SRC_DIR = fileURLToPath(new URL(".", import.meta.url));
const PACKAGE_JSON = fileURLToPath(new URL("../package.json", import.meta.url));

function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    const stat = statSync(abs);
    if (stat.isDirectory()) {
      out.push(...listSourceFiles(abs));
    } else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) {
      out.push(abs);
    }
  }
  return out;
}

/** Strip `/* ... *\/` block comments and `// ...` line comments (good enough for this repo's own style, not a full parser). */
function stripComments(content: string): string {
  return content.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

describe("architectural boundary: no auto-apply capability", () => {
  const files = listSourceFiles(SRC_DIR);

  it("finds at least the expected source files (sanity check the walk itself works)", () => {
    expect(files.length).toBeGreaterThan(5);
  });

  it("package.json declares no dependency on @montr/fix", () => {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON, "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    expect(pkg.dependencies?.["@montr/fix"]).toBeUndefined();
    expect(pkg.devDependencies?.["@montr/fix"]).toBeUndefined();
  });

  it("never imports @montr/fix as real code (import/require) anywhere in this package's source", () => {
    const importRe = /(?:from\s+|require\(|import\()\s*["']@montr\/fix["']/;
    const offenders = files.filter((f) => importRe.test(stripComments(readFileSync(f, "utf8"))));
    expect(offenders).toEqual([]);
  });

  it("never references the Layer 4 risk-classification vocabulary as real code", () => {
    const bannedIdentifiers = [
      "classifyFixRisk",
      "classifyConfirmedFindingRisk",
      "AUTO_ELIGIBLE_CATEGORIES",
      "ALWAYS_HUMAN_REQUIRED_CATEGORIES",
    ];
    const offenders: string[] = [];
    for (const f of files) {
      const code = stripComments(readFileSync(f, "utf8"));
      for (const id of bannedIdentifiers) {
        if (code.includes(id)) offenders.push(`${f}: ${id}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("never assigns a riskClass or produces a diff/patch-shaped field as real code", () => {
    const bannedFieldNames = [
      "riskClass:",
      ".riskClass",
      "unifiedDiff",
      '"patch"',
      "patch:",
      '"diff"',
      "diff:",
    ];
    const offenders: string[] = [];
    for (const f of files) {
      const code = stripComments(readFileSync(f, "utf8"));
      for (const name of bannedFieldNames) {
        if (code.includes(name)) offenders.push(`${f}: ${name}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
