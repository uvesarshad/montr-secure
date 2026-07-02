import { existsSync } from "node:fs";
import { describe, it, expect } from "vitest";
import type { Category } from "@montr/contracts";
import { loadCorpus } from "../packages/qa/src/corpus";
import { parseScanFindings } from "../packages/qa/src/findings-io";

/**
 * WS-P golden-corpus loader tests. Verifies the fixtures seed + expanded OWASP
 * repos merge into one validated ground-truth manifest with real on-disk repos.
 */

describe("loadCorpus — merged golden corpus", () => {
  it("merges @montr/fixtures seed repos with the expanded corpus/ repos", async () => {
    const corpus = await loadCorpus();
    const names = corpus.repos.map((r) => r.name).sort();
    expect(names).toEqual(
      ["clean-nextjs", "clean-nextjs-owasp", "vulnerable-nextjs", "vulnerable-nextjs-owasp"].sort(),
    );
    expect(corpus.repos.filter((r) => r.source === "fixtures")).toHaveLength(2);
    expect(corpus.repos.filter((r) => r.source === "corpus")).toHaveLength(2);
    expect(corpus.warnings).toEqual([]);
  });

  it("resolves every repo to an existing absolute directory", async () => {
    const corpus = await loadCorpus();
    for (const repo of corpus.repos) {
      expect(repo.path.startsWith("/")).toBe(true);
      expect(existsSync(repo.path)).toBe(true);
    }
  });

  it("covers the requested OWASP-Top-10 representative categories", async () => {
    const corpus = await loadCorpus();
    const categories = new Set<Category>();
    for (const repo of corpus.repos) {
      for (const f of repo.expectedFindings) categories.add(f.category);
    }
    for (const required of [
      "sql_injection",
      "xss",
      "ssrf",
      "idor",
      "broken_access_control",
      "hardcoded_secret",
      "vulnerable_dependency",
      "insecure_cookie",
      "permissive_cors",
    ] as const) {
      expect(categories.has(required)).toBe(true);
    }
  });

  it("clean repos declare zero expected findings", async () => {
    const corpus = await loadCorpus();
    for (const repo of corpus.repos.filter((r) => r.kind === "clean")) {
      expect(repo.expectedFindings).toHaveLength(0);
    }
  });

  it("access-control cases are labelled human-required (DoD / golden rule #3)", async () => {
    const corpus = await loadCorpus();
    const accessControl = corpus.repos
      .flatMap((r) => r.expectedFindings)
      .filter((f) => f.category === "idor" || f.category === "broken_access_control");
    expect(accessControl.length).toBeGreaterThan(0);
    for (const f of accessControl) expect(f.expectedRiskClass).toBe("human-required");
  });

  it("produces a scorer-ready merged manifest with matching repo names", async () => {
    const corpus = await loadCorpus();
    expect(corpus.manifest.repos.map((r) => r.name).sort()).toEqual(
      corpus.repos.map((r) => r.name).sort(),
    );
  });
});

describe("parseScanFindings — real scan output ingestion", () => {
  const finding = {
    id: "c1",
    scanId: "s",
    clientId: "cl",
    title: "SQLi",
    category: "sql_injection",
    cwe: ["CWE-89"],
    severity: "critical",
    exposure: "public",
    location: { file: "app/api/users/route.ts", line: 9 },
    impact: "x",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "a" },
    createdAt: "2026-01-15T10:00:00.000Z",
  };

  it("accepts the { results: [...] } shape", () => {
    const parsed = parseScanFindings({
      results: [{ repo: "vulnerable-nextjs", confirmed: [finding] }],
    });
    expect(parsed).toHaveLength(1);
    expect(parsed[0]!.confirmed[0]!.category).toBe("sql_injection");
  });

  it("accepts a bare array shape", () => {
    const parsed = parseScanFindings([{ repo: "vulnerable-nextjs", confirmed: [] }]);
    expect(parsed[0]!.repo).toBe("vulnerable-nextjs");
  });

  it("rejects an invalid ConfirmedFinding", () => {
    expect(() => parseScanFindings({ results: [{ repo: "r", confirmed: [{ id: "x" }] }] })).toThrow(
      /not a valid ConfirmedFinding/,
    );
  });

  it("rejects a malformed container", () => {
    expect(() => parseScanFindings({ nope: true })).toThrow(/array/);
    expect(() => parseScanFindings({ results: [{ confirmed: [] }] })).toThrow(/repo/);
  });
});
