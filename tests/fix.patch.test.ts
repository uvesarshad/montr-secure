import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import {
  buildUnifiedDiff,
  validatePatch,
  countChangedLines,
  createFsSourceReader,
  createMapSourceReader,
} from "@montr/fix";

const VULN_ROOT = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);

const isVulnerable = (src: string): boolean => /UNSAFE/.test(src);

describe("@montr/fix — patch build + validation", () => {
  it("builds a unified diff that applies cleanly and flips the vulnerability predicate", () => {
    const original = "line one\nconst x = UNSAFE(value);\nline three\n";
    const fixed = "line one\nconst x = SAFE(value);\nline three\n";
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);

    const v = validatePatch(original, patch, isVulnerable);
    expect(v.applies).toBe(true);
    expect(v.appliedSource).toBe(fixed);
    expect(v.failsPrePatch).toBe(true); // UNSAFE present before → proof test fails pre-patch
    expect(v.passesPostPatch).toBe(true); // UNSAFE gone after → proof test passes post-patch
    expect(v.changedLines).toBeGreaterThan(0);
  });

  it("reports passesPostPatch=false when the change does NOT remove the vulnerability", () => {
    const original = "UNSAFE()\nkeep\n";
    const fixed = "UNSAFE()\nchanged\n"; // still vulnerable
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);

    const v = validatePatch(original, patch, isVulnerable);
    expect(v.applies).toBe(true);
    expect(v.failsPrePatch).toBe(true);
    expect(v.passesPostPatch).toBe(false);
  });

  it("reports applies=false for a patch that does not fit the source", () => {
    const patch = buildUnifiedDiff(
      "app/x.ts",
      "completely different\ncontent\n",
      "changed\ncontent\n",
    );
    const v = validatePatch("unrelated source text\n", patch, isVulnerable);
    expect(v.applies).toBe(false);
    expect(v.appliedSource).toBeNull();
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
