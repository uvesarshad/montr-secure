import type { ConfirmedFinding } from "@montr/contracts";
import type { LoadedCorpus, LoadedRepo } from "./corpus.js";
import { scoreScanResults } from "./scorer.js";
import { perfectConfirmedForRepo } from "./synthetic.js";
import type { CorpusScore, RepoScanResult, ScoreOptions } from "./types.js";

export type Promisable<T> = T | Promise<T>;

/**
 * A pluggable scanner: given a corpus repo, return the ConfirmedFinding[] a scan
 * produced. The real Layer-0..3 pipeline (WS-E..H) plugs in here at integration;
 * until then tests/self-check inject synthetic scanners. This keeps @montr/qa
 * decoupled from other agents' live code (golden rule #9).
 */
export type CorpusScanner = (repo: LoadedRepo) => Promisable<ConfirmedFinding[]>;

export interface CorpusRun {
  score: CorpusScore;
  results: RepoScanResult[];
}

/** Run a scanner across the whole corpus and score it against ground truth. */
export async function runCorpus(
  corpus: LoadedCorpus,
  scan: CorpusScanner,
  opts: ScoreOptions = {},
): Promise<CorpusRun> {
  const results: RepoScanResult[] = [];
  for (const repo of corpus.repos) {
    results.push({ repo: repo.name, confirmed: await scan(repo) });
  }
  return { score: scoreScanResults(results, corpus.manifest, opts), results };
}

/**
 * Self-check "perfect scanner": emits exactly the exploitable ground-truth
 * findings. Lets `qa:corpus` run green end-to-end (exercising corpus load →
 * scorer → baseline gate → exit code) before the real pipeline is wired.
 */
export const perfectScanner: CorpusScanner = (repo) => perfectConfirmedForRepo(repo);
