import { existsSync } from "node:fs";
import { isAbsolute } from "node:path";
import { describe, it, expect } from "vitest";
import type { Category } from "@montr/contracts";
import { loadCorpus } from "../packages/qa/src/corpus";
import { parseScanFindings } from "../packages/qa/src/findings-io";

/**
 * WS-P golden-corpus loader tests. Verifies the fixtures seed + expanded OWASP
 * repos merge into one validated ground-truth manifest with real on-disk repos.
 */

describe("loadCorpus — merged golden corpus", () => {
  it("merges fixtures seed + shared OWASP + standalone python/jvm corpus repos", async () => {
    const corpus = await loadCorpus();
    const names = corpus.repos.map((r) => r.name).sort();
    expect(names).toEqual(
      [
        // @montr/fixtures seed repos (TS/JS)
        "clean-nextjs",
        "vulnerable-nextjs",
        // shared corpus/ground-truth.manifest.json (TS/JS OWASP)
        "clean-nextjs-owasp",
        "vulnerable-nextjs-owasp",
        // Phase-3 stack breadth — standalone corpus/<stack>-vuln manifests (WS-Q)
        "jvm-clean",
        "jvm-vuln",
        "python-clean",
        "python-vuln",
        // A17 — real-world vendored repos grown into the corpus.
        "dvna",
        "pygoat",
        "javaseccode",
        "log4shell-vulnerable-app",
        "spring-petclinic",
        "validatorjs-clean",
        "requests-clean",
        "gson-clean",
      ].sort(),
    );
    expect(corpus.repos.filter((r) => r.source === "fixtures")).toHaveLength(2);
    // 2 shared OWASP + 4 standalone python/jvm + 8 A17 real-world repos all
    // resolve as source "corpus".
    expect(corpus.repos.filter((r) => r.source === "corpus")).toHaveLength(14);
    expect(corpus.warnings).toEqual([]);
  });

  it("wires the Phase-3 python + jvm stacks (Django/FastAPI + Spring) into the gate", async () => {
    const corpus = await loadCorpus();
    for (const name of ["python-vuln", "python-clean", "jvm-vuln", "jvm-clean"] as const) {
      const repo = corpus.repos.find((r) => r.name === name);
      expect(repo, `${name} present in merged corpus`).toBeDefined();
      expect(repo!.source).toBe("corpus");
      expect(existsSync(repo!.path)).toBe(true);
    }
    // The vulnerable python + jvm repos carry the planted OWASP ground truth.
    const pyVuln = corpus.repos.find((r) => r.name === "python-vuln")!;
    const jvmVuln = corpus.repos.find((r) => r.name === "jvm-vuln")!;
    expect(pyVuln.expectedFindings.length).toBeGreaterThanOrEqual(5);
    expect(jvmVuln.expectedFindings.length).toBeGreaterThanOrEqual(5);
    // Stack-specific classes the TS/JS corpus does not exercise are now covered.
    const allCategories = new Set(
      corpus.repos.flatMap((r) => r.expectedFindings).map((f) => f.category),
    );
    expect(allCategories.has("command_injection")).toBe(true); // jvm
    expect(allCategories.has("insecure_deserialization")).toBe(true); // jvm
  });

  it("resolves every repo to an existing absolute directory", async () => {
    const corpus = await loadCorpus();
    for (const repo of corpus.repos) {
      // NOT `.startsWith("/")` — a Windows absolute path starts with a drive
      // letter (e.g. "C:\"), never "/". isAbsolute() is the portable check.
      expect(isAbsolute(repo.path)).toBe(true);
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

  it("clean repos declare zero EXPLOITABLE expected findings", async () => {
    // A17's requests-clean deliberately carries `exploitable: false` (demoted)
    // markers — real weak-crypto-looking patterns a naive scanner might flag,
    // that a correct scanner must NOT confirm. Those are intentional and
    // scored as false positives if ever confirmed; only non-demoted entries
    // would break the "clean" invariant.
    const corpus = await loadCorpus();
    for (const repo of corpus.repos.filter((r) => r.kind === "clean")) {
      const exploitable = repo.expectedFindings.filter((f) => f.exploitable !== false);
      expect(exploitable).toHaveLength(0);
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
