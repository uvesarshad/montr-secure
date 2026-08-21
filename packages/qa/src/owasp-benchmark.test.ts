import { describe, expect, it } from "vitest";
import type { ConfirmedFinding } from "@montr/contracts";
import {
  CWE_TO_OWASP_CATEGORY,
  OWASP_CATEGORY_TO_MONTR_CATEGORY,
  extractCweNumber,
  extractTestName,
  flaggedFromConfirmedFindings,
  flaggedFromSemgrepResults,
  loadOwaspBenchmark,
  parseExpectedResultsCsv,
  scoreOwaspBenchmark,
} from "./owasp-benchmark.js";

/**
 * E14 (closes A29) — the OWASP Benchmark harness. These tests use REAL rows
 * lifted verbatim from OWASP Benchmark's own `expectedresults-1.2.csv` (not
 * an invented format — see https://github.com/OWASP-Benchmark/BenchmarkJava),
 * and the actual vendored subset committed at `corpus/owasp-benchmark/`.
 */

// A real excerpt of expectedresults-1.2.csv's header + a handful of rows
// (verbatim byte-for-byte from the upstream file, same rows this repo's
// corpus/owasp-benchmark/expectedresults-subset.csv vendors).
const REAL_CSV_EXCERPT = `# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,true,22
BenchmarkTest00003,hash,true,328
BenchmarkTest00008,sqli,true,89
BenchmarkTest00052,sqli,false,89
BenchmarkTest00016,securecookie,false,614
`;

describe("parseExpectedResultsCsv", () => {
  it("parses OWASP Benchmark's real CSV format (header comment + rows)", () => {
    const cases = parseExpectedResultsCsv(REAL_CSV_EXCERPT);
    expect(cases).toHaveLength(6);
    expect(cases[0]).toMatchObject({
      testName: "BenchmarkTest00001",
      owaspCategory: "pathtraver",
      realVulnerability: true,
      cwe: "22",
      montrCategory: "path_traversal",
    });
  });

  it("maps a real-vulnerability=false row correctly", () => {
    const cases = parseExpectedResultsCsv(REAL_CSV_EXCERPT);
    const c = cases.find((c) => c.testName === "BenchmarkTest00052");
    expect(c?.realVulnerability).toBe(false);
    expect(c?.montrCategory).toBe("sql_injection");
  });

  it("leaves montrCategory undefined for a category outside this product's taxonomy (hash is folded into weak_crypto, but verify an unmapped one is truly undefined)", () => {
    const cases = parseExpectedResultsCsv(
      "# test name, category, real vulnerability, cwe\nBenchmarkTest00004,trustbound,true,501\n",
    );
    expect(cases[0]?.montrCategory).toBeUndefined();
  });

  it("ignores comment/blank lines and rejects a genuinely malformed row", () => {
    const cases = parseExpectedResultsCsv("# a comment line\n\nBenchmarkTest00099,sqli,true,89\n");
    expect(cases).toHaveLength(1);
    expect(() => parseExpectedResultsCsv("not,a,valid,benchmark,row\n")).toThrow();
  });
});

describe("category mappings", () => {
  it("covers every OWASP category present in the vendored subset", () => {
    for (const cat of ["sqli", "cmdi", "pathtraver", "xss", "securecookie", "crypto"]) {
      expect(OWASP_CATEGORY_TO_MONTR_CATEGORY[cat]).toBeDefined();
    }
  });

  it("CWE_TO_OWASP_CATEGORY resolves every CWE the vendored subset's ground truth cites", () => {
    for (const cwe of ["89", "78", "22", "79", "614", "327"]) {
      expect(CWE_TO_OWASP_CATEGORY[cwe]).toBeDefined();
    }
  });

  it("extractCweNumber parses Semgrep's free-text CWE metadata string", () => {
    expect(extractCweNumber("CWE-89: Improper Neutralization...")).toBe("89");
    expect(extractCweNumber("nonsense")).toBeUndefined();
  });

  it("extractTestName finds a BenchmarkTestNNNNN token in any path", () => {
    expect(
      extractTestName("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java"),
    ).toBe("BenchmarkTest00008");
    expect(extractTestName("no/match/here.java")).toBeUndefined();
  });
});

describe("scoreOwaspBenchmark", () => {
  const cases = parseExpectedResultsCsv(REAL_CSV_EXCERPT);

  it("scores a perfect tool at TPR=100%, FPR=0%, benchmarkScore=1", () => {
    // Perfect: flags every real-vulnerability case, nothing else.
    const flagged = new Set(cases.filter((c) => c.realVulnerability).map((c) => c.testName));
    const score = scoreOwaspBenchmark(cases, flagged, { toolName: "perfect" });
    expect(score.truePositives).toBe(4); // 00001, 00002, 00003, 00008
    expect(score.falseNegatives).toBe(0);
    expect(score.falsePositives).toBe(0);
    expect(score.tpr).toBe(1);
    expect(score.fpr).toBe(0);
    expect(score.benchmarkScore).toBe(1);
  });

  it("scores a tool that flags everything at TPR=100%, FPR=100%, benchmarkScore=0", () => {
    const flagged = new Set(cases.map((c) => c.testName));
    const score = scoreOwaspBenchmark(cases, flagged, { toolName: "flag-everything" });
    expect(score.tpr).toBe(1);
    expect(score.fpr).toBe(1);
    expect(score.benchmarkScore).toBe(0);
  });

  it("scores a tool that flags nothing at TPR=0%, FPR=0%, benchmarkScore=0", () => {
    const score = scoreOwaspBenchmark(cases, new Set(), { toolName: "flag-nothing" });
    expect(score.tpr).toBe(0);
    expect(score.fpr).toBe(0);
    expect(score.truePositives).toBe(0);
    expect(score.falseNegatives).toBe(4);
  });

  it("excludes a case whose category has no montr mapping, and reports it honestly", () => {
    const withUnmapped = parseExpectedResultsCsv(
      `${REAL_CSV_EXCERPT}BenchmarkTest00004,trustbound,true,501\n`,
    );
    const score = scoreOwaspBenchmark(withUnmapped, new Set(), { toolName: "t" });
    expect(score.casesExcluded).toBe(1);
    expect(score.excludedCategories).toEqual(["trustbound"]);
    expect(score.casesScored).toBe(6); // the 6 mapped rows, not 7
  });

  it("real vulnerability + flagged = TP; real vulnerability=false + flagged = FP (a genuine false-positive trap)", () => {
    // BenchmarkTest00052 is sqli, realVulnerability=false — flagging it is a
    // real false positive, exactly OWASP Benchmark's intended trap case.
    const score = scoreOwaspBenchmark(cases, new Set(["BenchmarkTest00052"]), { toolName: "t" });
    const outcome = score.outcomes.find((o) => o.testName === "BenchmarkTest00052");
    expect(outcome?.outcome).toBe("FP");
    expect(score.falsePositives).toBe(1);
  });
});

describe("flaggedFromConfirmedFindings", () => {
  it("only flags a case when the finding's OWN category maps into the SAME OWASP bucket", () => {
    const findings: ConfirmedFinding[] = [
      {
        id: "f1",
        scanId: "s1",
        clientId: "c1",
        title: "sqli",
        category: "sql_injection",
        cwe: [],
        severity: "critical",
        exposure: "public",
        location: {
          file: "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java",
          line: 10,
        },
        impact: "x",
        proofType: "static" as const,
        proofArtifact: {
          kind: "static" as const,
          argument: "x",
          dataFlow: [],
          sanitizersBypassed: [],
        },
        status: "confirmed",
        createdAt: "2026-01-01T00:00:00.000Z",
      },
    ];
    const flagged = flaggedFromConfirmedFindings(findings);
    expect(flagged.has("BenchmarkTest00008")).toBe(true);
  });

  it("does not flag a finding pointing at a file with no BenchmarkTestNNNNN token", () => {
    const findings: ConfirmedFinding[] = [
      {
        id: "f1",
        scanId: "s1",
        clientId: "c1",
        title: "sqli",
        category: "sql_injection",
        cwe: [],
        severity: "critical",
        exposure: "public",
        location: { file: "src/other/File.java", line: 1 },
        impact: "x",
        proofType: "static" as const,
        proofArtifact: {
          kind: "static" as const,
          argument: "x",
          dataFlow: [],
          sanitizersBypassed: [],
        },
        status: "confirmed",
        createdAt: "2026-01-01T00:00:00.000Z",
      },
    ];
    expect(flaggedFromConfirmedFindings(findings).size).toBe(0);
  });
});

describe("flaggedFromSemgrepResults", () => {
  it("flags a case from a real Semgrep-shaped result via CWE metadata", () => {
    const flagged = flaggedFromSemgrepResults({
      results: [
        {
          path: "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java",
          extra: {
            metadata: {
              cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
            },
          },
        },
      ],
    });
    expect(flagged.has("BenchmarkTest00008")).toBe(true);
  });

  it("does not flag a result whose CWE has no OWASP Benchmark category mapping", () => {
    const flagged = flaggedFromSemgrepResults({
      results: [
        {
          path: "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00099.java",
          extra: { metadata: { cwe: ["CWE-999"] } },
        },
      ],
    });
    expect(flagged.size).toBe(0);
  });
});

describe("loadOwaspBenchmark — the actual vendored subset committed at corpus/owasp-benchmark/", () => {
  it("loads real, non-empty ground truth with the expected shape", async () => {
    const { cases, repoPath } = await loadOwaspBenchmark();
    expect(repoPath).toMatch(/corpus[/\\]owasp-benchmark$/);
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(c.testName).toMatch(/^BenchmarkTest\d+$/);
      expect(typeof c.realVulnerability).toBe("boolean");
      expect(c.file).toContain(c.testName);
    }
    // Both TP-eligible and FP-trap (realVulnerability=false) cases are present
    // (this is what makes the subset able to measure BOTH recall and FP-rate).
    expect(cases.some((c) => c.realVulnerability)).toBe(true);
    expect(cases.some((c) => !c.realVulnerability)).toBe(true);
  });

  it("every case's category is in this product's taxonomy (the subset was deliberately hand-picked that way)", async () => {
    const { cases } = await loadOwaspBenchmark();
    for (const c of cases) {
      expect(
        c.montrCategory,
        `${c.testName} (${c.owaspCategory}) has no montr mapping`,
      ).toBeDefined();
    }
  });
});
