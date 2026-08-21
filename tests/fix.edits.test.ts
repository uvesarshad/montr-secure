import { describe, it, expect } from "vitest";
import { applyLineEdits, numberLines, parseLlmEdits, type LlmEdit } from "@montr/fix";

// A14 — unit coverage for the line-range edit format that replaced the old
// whole-file-rewrite (`{"fixedSource": "<entire file>"}`) LLM contract in
// @montr/fix/src/generate.ts. See tests/fix.generation.test.ts for the
// full-pipeline (real diff + real vitest execution) coverage of the same
// format, including the large-file truncation-threshold regression test.

describe("@montr/fix — numberLines", () => {
  it("prefixes each line with its 1-based line number", () => {
    expect(numberLines("a\nb\nc")).toBe("1: a\n2: b\n3: c");
  });

  it("handles a single-line, empty, and trailing-newline source", () => {
    expect(numberLines("only")).toBe("1: only");
    expect(numberLines("")).toBe("1: ");
    expect(numberLines("a\n")).toBe("1: a\n2: ");
  });
});

describe("@montr/fix — parseLlmEdits", () => {
  it("returns null for a non-array value", () => {
    expect(parseLlmEdits({ startLine: 1 }, 10)).toBeNull();
    expect(parseLlmEdits(undefined, 10)).toBeNull();
    expect(parseLlmEdits(null, 10)).toBeNull();
    expect(parseLlmEdits("edits", 10)).toBeNull();
  });

  it("returns null for an empty array", () => {
    expect(parseLlmEdits([], 10)).toBeNull();
  });

  it("returns null for a malformed entry", () => {
    expect(parseLlmEdits([{ startLine: 1, endLine: 1 }], 10)).toBeNull(); // missing replacement
    expect(parseLlmEdits([{ startLine: "1", endLine: 1, replacement: "x" }], 10)).toBeNull();
    expect(parseLlmEdits([{ startLine: 1.5, endLine: 2, replacement: "x" }], 10)).toBeNull();
    expect(parseLlmEdits([{ startLine: 0, endLine: 1, replacement: "x" }], 10)).toBeNull(); // < 1
    expect(parseLlmEdits([{ startLine: 2, endLine: 1, replacement: "x" }], 10)).toBeNull(); // end < start
    expect(parseLlmEdits([{ startLine: 1, endLine: 11, replacement: "x" }], 10)).toBeNull(); // past EOF
    expect(parseLlmEdits([null], 10)).toBeNull();
    expect(parseLlmEdits([[1, 2, "x"]], 10)).toBeNull();
  });

  it("returns null for overlapping or duplicate ranges", () => {
    expect(
      parseLlmEdits(
        [
          { startLine: 1, endLine: 3, replacement: "x" },
          { startLine: 3, endLine: 4, replacement: "y" },
        ],
        10,
      ),
    ).toBeNull();
    expect(
      parseLlmEdits(
        [
          { startLine: 5, endLine: 5, replacement: "x" },
          { startLine: 5, endLine: 5, replacement: "y" },
        ],
        10,
      ),
    ).toBeNull();
  });

  it("accepts and sorts valid, non-overlapping edits ascending by startLine", () => {
    const edits = parseLlmEdits(
      [
        { startLine: 8, endLine: 8, replacement: "late" },
        { startLine: 1, endLine: 2, replacement: "early" },
      ],
      10,
    );
    expect(edits).toEqual([
      { startLine: 1, endLine: 2, replacement: "early" },
      { startLine: 8, endLine: 8, replacement: "late" },
    ]);
  });

  it("accepts adjacent (touching, non-overlapping) ranges", () => {
    const edits = parseLlmEdits(
      [
        { startLine: 1, endLine: 2, replacement: "a" },
        { startLine: 3, endLine: 3, replacement: "b" },
      ],
      10,
    );
    expect(edits).toHaveLength(2);
  });
});

describe("@montr/fix — applyLineEdits", () => {
  it("replaces a single line", () => {
    const original = "a\nb\nc\n";
    const edits: LlmEdit[] = [{ startLine: 2, endLine: 2, replacement: "B" }];
    expect(applyLineEdits(original, edits)).toBe("a\nB\nc\n");
  });

  it("replaces a multi-line range with a single line", () => {
    const original = "a\nb\nc\nd\n";
    const edits: LlmEdit[] = [{ startLine: 2, endLine: 3, replacement: "BC" }];
    expect(applyLineEdits(original, edits)).toBe("a\nBC\nd\n");
  });

  it("replaces a single line with multiple lines (a net insertion)", () => {
    const original = "a\nb\nc\n";
    const edits: LlmEdit[] = [{ startLine: 2, endLine: 2, replacement: "b1\nb2" }];
    expect(applyLineEdits(original, edits)).toBe("a\nb1\nb2\nc\n");
  });

  it("applies multiple non-overlapping edits without an earlier edit's line-count change corrupting a later one", () => {
    const original = "1\n2\n3\n4\n5\n";
    const edits: LlmEdit[] = [
      { startLine: 1, endLine: 1, replacement: "ONE\nONE-B" }, // grows by one line
      { startLine: 4, endLine: 4, replacement: "FOUR" },
    ];
    expect(applyLineEdits(original, edits)).toBe("ONE\nONE-B\n2\n3\nFOUR\n5\n");
  });

  it("round-trips through numberLines + parseLlmEdits + applyLineEdits end to end", () => {
    const original = "function greet() {\n  return UNSAFE(input);\n}\n";
    const numbered = numberLines(original);
    expect(numbered).toContain("2:   return UNSAFE(input);");

    // Simulate a model response addressing the numbered line it saw.
    const raw = [{ startLine: 2, endLine: 2, replacement: "  return SAFE(input);" }];
    const edits = parseLlmEdits(raw, original.split("\n").length);
    expect(edits).not.toBeNull();
    const fixed = applyLineEdits(original, edits!);
    expect(fixed).toBe("function greet() {\n  return SAFE(input);\n}\n");
  });
});
