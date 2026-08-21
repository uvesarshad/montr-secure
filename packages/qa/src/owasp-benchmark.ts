import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Category, ConfirmedFinding } from "@montr/contracts";
import { ConfigValidationError } from "@montr/contracts";
import { findRepoRoot } from "./corpus.js";

/**
 * E14 — OWASP Benchmark harness (closes A29). Parses OWASP Benchmark's OWN
 * ground-truth format (`expectedresults-<version>.csv`) and scores a tool's
 * output against it using OWASP Benchmark's OWN methodology (per-test-case
 * TP/FP/TN/FN → true-positive-rate, false-positive-rate, and the headline
 * `score = TPR - FPR` the project's own scorecards publish
 * https://owasp.org/www-project-benchmark/ ), NOT this repo's internal
 * `corpus/ground-truth.manifest.json` shape (golden rule: an external
 * benchmark's ground truth is scored on ITS OWN terms, never hand-relabelled
 * into ours — see corpus/owasp-benchmark/README.md).
 *
 * DELIBERATELY separate from `corpus.ts`'s `loadCorpus()`: the vendored subset
 * lives at `corpus/owasp-benchmark/` but its ground-truth file is named
 * `expectedresults-subset.csv`, not `ground-truth.manifest.json` — so
 * `loadCorpus()`'s standalone-manifest glob (one level under `corpus/`,
 * matching only the literal filename `ground-truth.manifest.json`)
 * auto-discovery does NOT pick it up and it never silently merges into the
 * internal golden corpus's `corpus/baseline.json` gate. This is intentional: OWASP Benchmark
 * is an INDEPENDENT, externally-curated dataset (A29's whole point is that a
 * scanner tuned against its own golden corpus will always look good on that
 * corpus) and must be scored, reported, and gated entirely separately.
 */

/** One row of OWASP Benchmark's `expectedresults-*.csv` (their real, unmodified format). */
export interface OwaspBenchmarkCase {
  /** e.g. "BenchmarkTest00008" */
  testName: string;
  /** OWASP Benchmark's own category string, e.g. "sqli", "cmdi", "securecookie". */
  owaspCategory: string;
  /** Numeric CWE id as OWASP Benchmark records it (e.g. "89"). */
  cwe: string;
  /** OWASP Benchmark's own ground-truth label: true = genuinely exploitable. */
  realVulnerability: boolean;
  /** Repo-relative path to the vendored source file (may be absent if not vendored in this subset). */
  file?: string;
  /** This repo's Category, when {@link OWASP_CATEGORY_TO_MONTR_CATEGORY} has a mapping. */
  montrCategory?: Category;
}

/**
 * OWASP Benchmark → this product's taxonomy. OWASP Benchmark ships 11
 * categories; only six have a real, unambiguous analog in `CategorySchema`
 * (`compliance.ts`). The other five (`ldapi`, `xpathi`, `trustbound`,
 * `hash`/`weakrand` beyond the `crypto` bucket already folded in) have no
 * category this product's Layer 1-3 pipeline currently detects for ANY
 * language — scoring them would either silently fabricate a false negative
 * for every case (dishonest: "the pipeline can't find LDAP injection" is not
 * the same claim as "the pipeline was tested for LDAP injection and missed
 * it") or require inventing a mapping with no real detector behind it. Cases
 * in an unmapped category are excluded from scoring and reported as such
 * (never silently dropped — see `OwaspBenchmarkScore.excludedCategories`).
 */
export const OWASP_CATEGORY_TO_MONTR_CATEGORY: Readonly<Record<string, Category>> = {
  sqli: "sql_injection",
  cmdi: "command_injection",
  pathtraver: "path_traversal",
  xss: "xss",
  securecookie: "insecure_cookie",
  // crypto/hash/weakrand are three distinct OWASP Benchmark buckets that all
  // land on this product's single `weak_crypto` category (no finer-grained
  // split exists in CategorySchema).
  crypto: "weak_crypto",
  hash: "weak_crypto",
  weakrand: "weak_crypto",
};

/** Reverse of {@link OWASP_CATEGORY_TO_MONTR_CATEGORY}: montr Category -> OWASP category bucket(s). */
function owaspCategoriesFor(category: Category): string[] {
  return Object.entries(OWASP_CATEGORY_TO_MONTR_CATEGORY)
    .filter(([, montr]) => montr === category)
    .map(([owasp]) => owasp);
}

/**
 * CWE (as reported by an arbitrary external tool's own metadata, e.g. Semgrep
 * rule metadata) -> OWASP Benchmark category bucket. Deliberately lenient on
 * the crypto family: OWASP Benchmark's own `expectedresults` CSV records
 * `crypto` cases under CWE-327 ("broken/risky crypto algorithm"), but a real
 * scanner reporting the same underlying weakness commonly cites the closely
 * related CWE-326 ("inadequate encryption strength") or CWE-328/CWE-338
 * (reversible hash / weak PRNG) instead — verified against this harness's own
 * real Semgrep run (`p/owasp-top-ten`'s `des-is-deprecated` rule reports
 * CWE-326 for what OWASP Benchmark itself labels a CWE-327 `crypto` case).
 * Scoring only exact CWE-327 would under-count a tool that is, in substance,
 * correct.
 */
export const CWE_TO_OWASP_CATEGORY: Readonly<Record<string, string>> = {
  "89": "sqli",
  "78": "cmdi",
  "22": "pathtraver",
  "79": "xss",
  "614": "securecookie",
  "326": "crypto",
  "327": "crypto",
  "328": "crypto",
  "338": "weakrand",
};

/** Extract "BenchmarkTestNNNNN" from a file path (any prefix/suffix). */
export function extractTestName(filePath: string): string | undefined {
  const m = /BenchmarkTest\d+/.exec(filePath);
  return m?.[0];
}

/** Extract the first numeric CWE id from a free-text CWE metadata string (e.g. Semgrep's `"CWE-89: ..."`). */
export function extractCweNumber(raw: string): string | undefined {
  const m = /CWE-(\d+)/i.exec(raw);
  return m?.[1];
}

const CSV_ROW_RE = /^(BenchmarkTest\d+),([a-z]+),(true|false),(\d+)/i;

/**
 * Parse OWASP Benchmark's own `expectedresults-*.csv` format (real header
 * comment + `testName,category,realVulnerability,cwe[,...]` rows — see
 * https://github.com/OWASP-Benchmark/BenchmarkJava's `expectedresults-1.2.csv`).
 * This is OWASP Benchmark's ACTUAL ground-truth file format, parsed as-is —
 * never hand-relabelled (A29/E14's explicit requirement).
 */
export function parseExpectedResultsCsv(text: string): OwaspBenchmarkCase[] {
  const cases: OwaspBenchmarkCase[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = CSV_ROW_RE.exec(trimmed);
    if (!m) {
      throw new ConfigValidationError(
        `expectedresults CSV row did not match the expected OWASP Benchmark format: "${line}"`,
      );
    }
    // Non-null: every group in CSV_ROW_RE is a mandatory (non-optional)
    // capture, so a successful match always populates all four.
    const testName = m[1] as string;
    const owaspCategory = m[2] as string;
    const realVulnerabilityRaw = m[3] as string;
    const cwe = m[4] as string;
    cases.push({
      testName,
      owaspCategory,
      cwe,
      realVulnerability: realVulnerabilityRaw === "true",
      montrCategory: OWASP_CATEGORY_TO_MONTR_CATEGORY[owaspCategory],
    });
  }
  return cases;
}

/** Vendored subset location, relative to the monorepo root. */
export const OWASP_BENCHMARK_DIR = "corpus/owasp-benchmark";
export const OWASP_BENCHMARK_TESTCODE_DIR = "src/main/java/org/owasp/benchmark/testcode";

export interface LoadedOwaspBenchmark {
  /** Absolute path to the vendored subset's repo root (what Layer 0 should scan). */
  repoPath: string;
  cases: OwaspBenchmarkCase[];
}

/**
 * Load the vendored OWASP Benchmark subset (`corpus/owasp-benchmark/`) and its
 * real `expectedresults-subset.csv`, resolving each case's `file` to the
 * vendored Java source it corresponds to.
 */
export async function loadOwaspBenchmark(
  opts: { cwdUrl?: string } = {},
): Promise<LoadedOwaspBenchmark> {
  const root = findRepoRoot(fileURLToPath(opts.cwdUrl ?? import.meta.url));
  const repoPath = join(root, OWASP_BENCHMARK_DIR);
  const csvPath = join(repoPath, "expectedresults-subset.csv");
  let text: string;
  try {
    text = await readFile(csvPath, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read OWASP Benchmark subset CSV: ${csvPath}`, {
      cause: String(cause),
    });
  }
  const cases = parseExpectedResultsCsv(text).map((c) => ({
    ...c,
    file: `${OWASP_BENCHMARK_TESTCODE_DIR}/${c.testName}.java`,
  }));
  return { repoPath, cases };
}

// --------------------------------------------------------------------------
// Scoring — OWASP Benchmark's own methodology: per test case, TP/FP/TN/FN,
// then TPR = TP/(TP+FN), FPR = FP/(FP+TN), and the project's own headline
// `score = TPR - FPR` (their scorecard's "Benchmark Score", a Youden's-J-style
// statistic that rewards true detections and penalizes false alarms
// symmetrically — see https://owasp.org/www-project-benchmark/).
// --------------------------------------------------------------------------

export type OwaspOutcomeKind = "TP" | "FP" | "TN" | "FN";

export interface OwaspCaseOutcome {
  testName: string;
  owaspCategory: string;
  realVulnerability: boolean;
  flagged: boolean;
  outcome: OwaspOutcomeKind;
}

export interface OwaspBenchmarkScore {
  toolName: string;
  casesScored: number;
  casesExcluded: number;
  /** OWASP Benchmark categories present in the subset this tool's taxonomy cannot express. */
  excludedCategories: string[];
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  /** True-positive rate on scored cases: TP / (TP + FN). */
  tpr: number;
  /** False-positive rate on scored cases: FP / (FP + TN). */
  fpr: number;
  precision: number;
  /** OWASP Benchmark's own headline metric: TPR - FPR. */
  benchmarkScore: number;
  outcomes: OwaspCaseOutcome[];
}

function rate(numerator: number, denominator: number, whenEmpty: number): number {
  return denominator === 0 ? whenEmpty : numerator / denominator;
}

/**
 * Score a set of "flagged" test names (whatever a tool's real output claims is
 * vulnerable, already filtered to findings whose OWN reported category falls
 * in the SAME OWASP-Benchmark category bucket as the case — see
 * {@link flaggedFromConfirmedFindings} / {@link flaggedFromSemgrepResults})
 * against OWASP Benchmark's ground truth, using OWASP Benchmark's own
 * TP/FP/TN/FN + TPR/FPR/score methodology.
 */
export function scoreOwaspBenchmark(
  cases: readonly OwaspBenchmarkCase[],
  flagged: ReadonlySet<string>,
  opts: { toolName: string; supportedOwaspCategories?: ReadonlySet<string> },
): OwaspBenchmarkScore {
  const supported =
    opts.supportedOwaspCategories ?? new Set(Object.keys(OWASP_CATEGORY_TO_MONTR_CATEGORY));

  const excludedCategories = new Set<string>();
  const outcomes: OwaspCaseOutcome[] = [];
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let excluded = 0;

  for (const c of cases) {
    if (!supported.has(c.owaspCategory)) {
      excludedCategories.add(c.owaspCategory);
      excluded++;
      continue;
    }
    const isFlagged = flagged.has(c.testName);
    let outcome: OwaspOutcomeKind;
    if (c.realVulnerability && isFlagged) {
      outcome = "TP";
      tp++;
    } else if (c.realVulnerability && !isFlagged) {
      outcome = "FN";
      fn++;
    } else if (!c.realVulnerability && isFlagged) {
      outcome = "FP";
      fp++;
    } else {
      outcome = "TN";
      tn++;
    }
    outcomes.push({
      testName: c.testName,
      owaspCategory: c.owaspCategory,
      realVulnerability: c.realVulnerability,
      flagged: isFlagged,
      outcome,
    });
  }

  const tpr = rate(tp, tp + fn, 1);
  const fpr = rate(fp, fp + tn, 0);
  return {
    toolName: opts.toolName,
    casesScored: outcomes.length,
    casesExcluded: excluded,
    excludedCategories: [...excludedCategories].sort(),
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    tpr,
    fpr,
    precision: rate(tp, tp + fp, 1),
    benchmarkScore: tpr - fpr,
    outcomes,
  };
}

/**
 * Build the "flagged" set from this product's REAL confirmed findings
 * (post-correlation, post-static-confirmation — the actual end output a
 * customer sees), matched to a case by (test file, OWASP category bucket the
 * finding's own `Category` falls in).
 */
export function flaggedFromConfirmedFindings(
  confirmed: readonly ConfirmedFinding[],
): ReadonlySet<string> {
  const flagged = new Set<string>();
  for (const f of confirmed) {
    const testName = extractTestName(f.location.file);
    if (!testName) continue;
    // A finding only "flags" a case when ITS OWN category maps into the SAME
    // OWASP bucket as the case — never credit a right-file/wrong-category hit.
    if (owaspCategoriesFor(f.category).length > 0) flagged.add(testName);
  }
  return flagged;
}

/** Minimal shape of Semgrep's `--json` output this harness reads (see `packages/discovery/src/types.ts`'s `SemgrepJson`). */
export interface RawSemgrepResult {
  path?: string;
  extra?: { metadata?: Record<string, unknown> };
}
export interface RawSemgrepJson {
  results?: RawSemgrepResult[];
}

/**
 * Build the "flagged" set from a RAW Semgrep `--json` run against the SAME
 * vendored subset (the competitor comparison, no correlation/confirmation
 * post-processing — this is genuinely what a user running bare Semgrep would
 * see), matched to a case by (test file, CWE metadata mapped to the same
 * OWASP category bucket via {@link CWE_TO_OWASP_CATEGORY}).
 */
export function flaggedFromSemgrepResults(json: RawSemgrepJson): ReadonlySet<string> {
  const flagged = new Set<string>();
  for (const r of json.results ?? []) {
    const testName = r.path ? extractTestName(r.path) : undefined;
    if (!testName) continue;
    const rawCwe = r.extra?.metadata?.["cwe"];
    const cweStrings = Array.isArray(rawCwe) ? rawCwe.map(String) : rawCwe ? [String(rawCwe)] : [];
    const anyMapped = cweStrings.some((c) => {
      const num = extractCweNumber(c) ?? (/^\d+$/.test(c) ? c : undefined);
      return num !== undefined && CWE_TO_OWASP_CATEGORY[num] !== undefined;
    });
    if (anyMapped) flagged.add(testName);
  }
  return flagged;
}
