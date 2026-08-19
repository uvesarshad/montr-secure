import { describe, it, expect } from "vitest";
import {
  IdSchema,
  IsoDateTimeSchema,
  CommitShaSchema,
  FilePathSchema,
  LineNumberSchema,
  UrlSchema,
  Score01Schema,
  VersionSchema,
  SourceLocationSchema,
} from "./primitives.js";

/**
 * Primitive schemas are the format-validated building blocks reused across
 * every other contract (ids, timestamps, commit SHAs, scores). Their regexes
 * and bounds are exactly the kind of "real validation logic" worth pinning
 * down — a loosened primitive silently weakens every schema built on it.
 */

describe("IdSchema", () => {
  it("accepts a non-empty string", () => {
    expect(IdSchema.parse("scan_123")).toBe("scan_123");
  });

  it("rejects an empty string", () => {
    expect(() => IdSchema.parse("")).toThrow();
  });

  it("rejects non-string values", () => {
    expect(() => IdSchema.parse(123)).toThrow();
    expect(() => IdSchema.parse(null)).toThrow();
    expect(() => IdSchema.parse(undefined)).toThrow();
  });
});

describe("IsoDateTimeSchema", () => {
  it("accepts an offset ISO-8601 timestamp", () => {
    expect(IsoDateTimeSchema.parse("2026-07-02T12:00:00.000Z")).toBe("2026-07-02T12:00:00.000Z");
  });

  it("accepts a non-Z UTC offset", () => {
    expect(IsoDateTimeSchema.parse("2026-07-02T12:00:00.000+02:00")).toBe(
      "2026-07-02T12:00:00.000+02:00",
    );
  });

  it("rejects a bare date with no time component", () => {
    expect(() => IsoDateTimeSchema.parse("2026-07-02")).toThrow();
  });

  it("rejects an offset-less timestamp (offset: true is required)", () => {
    expect(() => IsoDateTimeSchema.parse("2026-07-02T12:00:00.000")).toThrow();
  });

  it("rejects garbage strings", () => {
    expect(() => IsoDateTimeSchema.parse("not-a-date")).toThrow();
  });
});

describe("CommitShaSchema", () => {
  it("accepts a short (7-char) hex SHA", () => {
    expect(CommitShaSchema.parse("abc1234")).toBe("abc1234");
  });

  it("accepts a full 40-char hex SHA, case-insensitively", () => {
    const sha = "A1B2C3D4E5F60718293A4B5C6D7E8F901234567";
    expect(CommitShaSchema.parse(sha)).toBe(sha);
  });

  it("rejects a too-short hex string (< 7 chars)", () => {
    expect(() => CommitShaSchema.parse("abc12")).toThrow();
  });

  it("rejects non-hex characters", () => {
    expect(() => CommitShaSchema.parse("zzzzzzz")).toThrow();
  });

  it("rejects an over-long string (> 64 chars)", () => {
    expect(() => CommitShaSchema.parse("a".repeat(65))).toThrow();
  });
});

describe("FilePathSchema", () => {
  it("accepts a non-empty relative path", () => {
    expect(FilePathSchema.parse("src/index.ts")).toBe("src/index.ts");
  });

  it("rejects an empty path", () => {
    expect(() => FilePathSchema.parse("")).toThrow();
  });
});

describe("LineNumberSchema", () => {
  it("accepts 0 (whole-file / not-applicable sentinel)", () => {
    expect(LineNumberSchema.parse(0)).toBe(0);
  });

  it("accepts a positive integer", () => {
    expect(LineNumberSchema.parse(42)).toBe(42);
  });

  it("rejects negative numbers", () => {
    expect(() => LineNumberSchema.parse(-1)).toThrow();
  });

  it("rejects non-integers", () => {
    expect(() => LineNumberSchema.parse(1.5)).toThrow();
  });
});

describe("UrlSchema", () => {
  it("accepts a well-formed URL", () => {
    expect(UrlSchema.parse("https://example.com/path")).toBe("https://example.com/path");
  });

  it("rejects a non-URL string", () => {
    expect(() => UrlSchema.parse("not a url")).toThrow();
  });
});

describe("Score01Schema", () => {
  it("accepts boundary values 0 and 1", () => {
    expect(Score01Schema.parse(0)).toBe(0);
    expect(Score01Schema.parse(1)).toBe(1);
  });

  it("accepts a mid-range fraction", () => {
    expect(Score01Schema.parse(0.42)).toBe(0.42);
  });

  it("rejects values below 0", () => {
    expect(() => Score01Schema.parse(-0.01)).toThrow();
  });

  it("rejects values above 1", () => {
    expect(() => Score01Schema.parse(1.01)).toThrow();
  });
});

describe("VersionSchema", () => {
  it("accepts a non-empty version string", () => {
    expect(VersionSchema.parse("1.2.3")).toBe("1.2.3");
  });

  it("rejects an empty string", () => {
    expect(() => VersionSchema.parse("")).toThrow();
  });
});

describe("SourceLocationSchema", () => {
  it("accepts a minimal valid location (file + line only)", () => {
    const loc = { file: "src/a.ts", line: 10 };
    expect(SourceLocationSchema.parse(loc)).toEqual(loc);
  });

  it("accepts a fully-populated location", () => {
    const loc = {
      file: "src/a.ts",
      line: 10,
      endLine: 12,
      column: 4,
      endColumn: 8,
      symbol: "handler",
    };
    expect(SourceLocationSchema.parse(loc)).toEqual(loc);
  });

  it("rejects a missing required `file`", () => {
    expect(() => SourceLocationSchema.parse({ line: 1 })).toThrow();
  });

  it("rejects a missing required `line`", () => {
    expect(() => SourceLocationSchema.parse({ file: "a.ts" })).toThrow();
  });

  it("rejects a negative line number", () => {
    expect(() => SourceLocationSchema.parse({ file: "a.ts", line: -5 })).toThrow();
  });
});
