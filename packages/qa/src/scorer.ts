import type { Category, ConfirmedFinding } from "@montr/contracts";
import type { GroundTruthFinding, GroundTruthManifest, GroundTruthRepo } from "@montr/fixtures";
import {
  DEFAULT_LINE_TOLERANCE,
  type CategoryScore,
  type ConfusionCounts,
  type CorpusScore,
  type MatchOutcome,
  type RepoScanResult,
  type RepoScore,
  type ScoreOptions,
} from "./types.js";

/**
 * Precision/recall scorer (build-plan §4.7). Compares a scan's ConfirmedFinding[]
 * against the golden-corpus ground truth and reports precision, recall, and the
 * headline false-positive rate — overall and per category.
 *
 * Matching model:
 *  - A confirmed finding matches a ground-truth finding when category + file
 *    agree and the line is within {@link ScoreOptions.lineTolerance}.
 *  - Ground-truth findings with `exploitable: true` are EXPECTED in the confirmed
 *    set (matching one => true positive; missing one => false negative).
 *  - Ground-truth findings with `exploitable: false` should have been DEMOTED to
 *    the appendix; confirming one is a false positive (`overConfirmed`).
 *  - A confirmed finding matching no ground-truth finding is a false positive.
 */

/** Divide-by-zero conventions are documented on {@link CorpusScore}. */
function precisionOf(tp: number, fp: number): number {
  return tp + fp === 0 ? 1 : tp / (tp + fp);
}
function recallOf(tp: number, fn: number): number {
  return tp + fn === 0 ? 1 : tp / (tp + fn);
}
function fpRateOf(tp: number, fp: number): number {
  return tp + fp === 0 ? 0 : fp / (tp + fp);
}
function f1Of(precision: number, recall: number): number {
  return precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
}

function locationMatches(
  finding: ConfirmedFinding,
  gt: GroundTruthFinding,
  lineTolerance: number,
): boolean {
  return (
    finding.category === gt.category &&
    finding.location.file === gt.file &&
    Math.abs(finding.location.line - gt.line) <= lineTolerance
  );
}

/** Score a single repo's confirmed findings against its ground truth. */
export function scoreRepo(
  repo: GroundTruthRepo,
  confirmed: ConfirmedFinding[],
  opts: ScoreOptions = {},
): RepoScore {
  const tol = opts.lineTolerance ?? DEFAULT_LINE_TOLERANCE;
  const expectedConfirmed = repo.expectedFindings.filter((f) => f.exploitable);
  const expectedDemoted = repo.expectedFindings.filter((f) => !f.exploitable);
  const matched = new Set<string>();
  const outcomes: MatchOutcome[] = [];
  let truePositives = 0;
  let falsePositives = 0;
  let overConfirmed = 0;

  for (const finding of confirmed) {
    const hit = expectedConfirmed.find(
      (g) => !matched.has(g.id) && locationMatches(finding, g, tol),
    );
    if (hit) {
      matched.add(hit.id);
      truePositives++;
      outcomes.push({
        kind: "true_positive",
        category: hit.category,
        confirmedId: finding.id,
        groundTruthId: hit.id,
        file: finding.location.file,
        line: finding.location.line,
      });
      continue;
    }
    // No exploitable match: this confirmation is a false positive. Note whether
    // it over-confirmed a case ground truth says should have stayed demoted.
    const demoted = expectedDemoted.find((g) => locationMatches(finding, g, tol));
    falsePositives++;
    if (demoted) overConfirmed++;
    outcomes.push({
      kind: "false_positive",
      category: finding.category,
      confirmedId: finding.id,
      groundTruthId: demoted?.id,
      file: finding.location.file,
      line: finding.location.line,
      note: demoted
        ? "over-confirmed: ground truth marks this non-exploitable (should stay demoted)"
        : "spurious: no matching ground-truth finding",
    });
  }

  let falseNegatives = 0;
  for (const gt of expectedConfirmed) {
    if (matched.has(gt.id)) continue;
    falseNegatives++;
    outcomes.push({
      kind: "false_negative",
      category: gt.category,
      groundTruthId: gt.id,
      file: gt.file,
      line: gt.line,
      note: "expected-exploitable finding was not confirmed",
    });
  }

  return {
    repo: repo.name,
    kind: repo.kind,
    truePositives,
    falsePositives,
    falseNegatives,
    overConfirmed,
    outcomes,
  };
}

function emptyCounts(): ConfusionCounts {
  return { truePositives: 0, falsePositives: 0, falseNegatives: 0 };
}

function finalizeCategory(category: Category, counts: ConfusionCounts): CategoryScore {
  const precision = precisionOf(counts.truePositives, counts.falsePositives);
  const recall = recallOf(counts.truePositives, counts.falseNegatives);
  return {
    category,
    ...counts,
    precision,
    recall,
    f1: f1Of(precision, recall),
    fpRate: fpRateOf(counts.truePositives, counts.falsePositives),
  };
}

/**
 * Aggregate a scan's per-repo results into an overall {@link CorpusScore}.
 * Every repo in the manifest is scored; a repo with no supplied result is scored
 * against an empty finding set (so a clean repo passes and a vulnerable repo
 * yields false negatives).
 */
export function scoreScanResults(
  results: readonly RepoScanResult[],
  manifest: GroundTruthManifest,
  opts: ScoreOptions = {},
): CorpusScore {
  const byRepo = new Map<string, ConfirmedFinding[]>();
  for (const r of results) {
    byRepo.set(r.repo, [...(byRepo.get(r.repo) ?? []), ...r.confirmed]);
  }

  const manifestNames = new Set(manifest.repos.map((r) => r.name));
  const unknownRepoResults = results
    .filter((r) => !manifestNames.has(r.repo))
    .reduce((n, r) => n + r.confirmed.length, 0);

  const perRepo: RepoScore[] = [];
  const perCategory = new Map<Category, ConfusionCounts>();
  const totals = emptyCounts();
  let overConfirmed = 0;
  let reposWithResults = 0;

  const bump = (category: Category, key: keyof ConfusionCounts) => {
    const c = perCategory.get(category) ?? emptyCounts();
    c[key]++;
    perCategory.set(category, c);
    totals[key]++;
  };

  for (const repo of manifest.repos) {
    const confirmed = byRepo.get(repo.name);
    if (confirmed !== undefined) reposWithResults++;
    const rs = scoreRepo(repo, confirmed ?? [], opts);
    perRepo.push(rs);
    overConfirmed += rs.overConfirmed;
    for (const o of rs.outcomes) {
      if (o.kind === "true_positive") bump(o.category, "truePositives");
      else if (o.kind === "false_positive") bump(o.category, "falsePositives");
      else bump(o.category, "falseNegatives");
    }
  }

  const precision = precisionOf(totals.truePositives, totals.falsePositives);
  const recall = recallOf(totals.truePositives, totals.falseNegatives);
  const perCategoryScores = [...perCategory.entries()]
    .map(([category, counts]) => finalizeCategory(category, counts))
    .sort((a, b) => a.category.localeCompare(b.category));

  return {
    ...totals,
    precision,
    recall,
    f1: f1Of(precision, recall),
    fpRate: fpRateOf(totals.truePositives, totals.falsePositives),
    perCategory: perCategoryScores,
    overConfirmed,
    reposScored: manifest.repos.length,
    reposWithResults,
    unknownRepoResults,
    perRepo,
  };
}
