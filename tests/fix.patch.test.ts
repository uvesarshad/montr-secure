import { describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import {
  buildUnifiedDiff,
  validatePatch,
  countChangedLines,
  createFsSourceReader,
  createMapSourceReader,
} from "@montr/fix";

// `validatePatch` now spawns real `vitest` subprocesses (twice per call, in
// parallel) — each run costs real wall-clock time well past vitest's default
// 5s per-test budget.
vi.setConfig({ testTimeout: 30_000 });

const VULN_ROOT = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);

/** A minimal, real proof-of-fix test — the exact shape strategies.ts generates. */
function proofTestFor(filePath: string, vulnerable: RegExp): string {
  return [
    `import { readFileSync } from "node:fs";`,
    `import { describe, it, expect } from "vitest";`,
    `const source = readFileSync(${JSON.stringify(filePath)}, "utf8");`,
    `describe("proof-of-fix", () => {`,
    `  it("no longer contains the vulnerable pattern", () => {`,
    `    expect(source).not.toMatch(${vulnerable.toString()});`,
    `  });`,
    `});`,
    ``,
  ].join("\n");
}

describe("@montr/fix — patch build + validation (real vitest execution)", () => {
  it("builds a unified diff that applies cleanly, and REALLY executes the proof test: fails pre-patch, passes post-patch", async () => {
    const original = "line one\nconst x = UNSAFE(value);\nline three\n";
    const fixed = "line one\nconst x = SAFE(value);\nline three\n";
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);
    const proofTestCode = proofTestFor("app/x.ts", /UNSAFE/);

    const v = await validatePatch(original, patch, { filePath: "app/x.ts", proofTestCode });
    expect(v.executionError).toBeUndefined();
    expect(v.applies).toBe(true);
    expect(v.appliedSource).toBe(fixed);
    expect(v.failsPrePatch).toBe(true); // real vitest run against `original` FAILED (UNSAFE present)
    expect(v.passesPostPatch).toBe(true); // real vitest run against `fixed` PASSED (UNSAFE gone)
    expect(v.changedLines).toBeGreaterThan(0);
  });

  it("reports passesPostPatch=false when the change does NOT remove the vulnerability (real run still fails post-patch)", async () => {
    const original = "UNSAFE()\nkeep\n";
    const fixed = "UNSAFE()\nchanged\n"; // still vulnerable
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);
    const proofTestCode = proofTestFor("app/x.ts", /UNSAFE/);

    const v = await validatePatch(original, patch, { filePath: "app/x.ts", proofTestCode });
    expect(v.executionError).toBeUndefined();
    expect(v.applies).toBe(true);
    expect(v.failsPrePatch).toBe(true);
    expect(v.passesPostPatch).toBe(false);
  });

  it("reports applies=false for a patch that does not fit the source (no post-patch run attempted)", async () => {
    const patch = buildUnifiedDiff(
      "app/x.ts",
      "completely different\ncontent\n",
      "changed\ncontent\n",
    );
    const proofTestCode = proofTestFor("app/x.ts", /UNSAFE/);
    const v = await validatePatch("unrelated source text\n", patch, {
      filePath: "app/x.ts",
      proofTestCode,
    });
    expect(v.applies).toBe(false);
    expect(v.appliedSource).toBeNull();
    expect(v.passesPostPatch).toBe(false);
  });

  it("reports a distinct executionError (never a false 'vulnerable' verdict) when vitest cannot even run the test", async () => {
    const original = "const x = UNSAFE(value);\n";
    const fixed = "const x = SAFE(value);\n";
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);
    // Deliberately broken test file — a real syntax error, not a normal assertion failure.
    const brokenProofTestCode = `import { describe, it, expect } from "vitest";\nthis is not valid javascript {{{\n`;

    const v = await validatePatch(original, patch, {
      filePath: "app/x.ts",
      proofTestCode: brokenProofTestCode,
    });
    expect(v.executionError).toBeDefined();
    expect(v.executionError).not.toHaveLength(0);
    // A launch/execution failure must never be silently read as "vulnerable" or "fixed".
    expect(v.failsPrePatch).toBe(false);
    expect(v.passesPostPatch).toBe(false);
  });

  it("countChangedLines is 0 for an empty patch", () => {
    expect(countChangedLines("")).toBe(0);
  });
});

describe("@montr/fix — source readers", () => {
  it("createFsSourceReader reads repo-relative files from the sandbox root", async () => {
    const reader = createFsSourceReader(VULN_ROOT);
    const route = await reader.read("app/api/users/route.ts");
    expect(route).not.toBeNull();
    expect(route).toContain("$queryRawUnsafe");
  });

  it("createFsSourceReader returns null for missing files and refuses path traversal", async () => {
    const reader = createFsSourceReader(VULN_ROOT);
    expect(await reader.read("does/not/exist.ts")).toBeNull();
    expect(await reader.read("../../../../../../etc/passwd")).toBeNull();
  });

  it("createMapSourceReader serves in-memory files and null for the rest", async () => {
    const reader = createMapSourceReader({ "a/b.ts": "hello" });
    expect(await reader.read("a/b.ts")).toBe("hello");
    expect(await reader.read("missing.ts")).toBeNull();
  });
});
