import { readFile } from "node:fs/promises";
import { ConfigValidationError } from "@montr/contracts";
import type { CorpusScore } from "./types.js";

/**
 * Committed regression baseline for the golden-corpus gate. The scorer exits
 * non-zero when a scan falls below these thresholds (build-plan §4.7). Thresholds
 * are the contract; tighten (never loosen) them as accuracy improves.
 */
export interface CategoryThreshold {
  precisionMin?: number;
  recallMin?: number;
  fpRateMax?: number;
}

export interface Baseline {
  /** Headline metric ceiling (PRD §15/§19: false-positive rate < 5%). */
  fpRateMax: number;
  precisionMin: number;
  recallMin: number;
  /** Guard: require at least this many repos to have been scored (catches an empty run). */
  minReposScored?: number;
  /** Optional per-category thresholds keyed by contract Category string. */
  perCategory?: Record<string, CategoryThreshold>;
}

/** Fail-safe defaults matching the Phase-1 Definition of Done. */
export const DEFAULT_BASELINE: Baseline = {
  fpRateMax: 0.05,
  precisionMin: 0.9,
  recallMin: 0.9,
};

/** A single threshold breach. */
export interface Violation {
  scope: string;
  metric: "fpRate" | "precision" | "recall" | "reposScored";
  actual: number;
  threshold: number;
  direction: "min" | "max";
}

export interface RegressionResult {
  passed: boolean;
  violations: Violation[];
  baseline: Baseline;
}

/** Small epsilon so floating-point equality (e.g. exactly 0.05) does not spuriously fail. */
const EPS = 1e-9;

function isRate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function parseCategoryThreshold(scope: string, raw: unknown): CategoryThreshold {
  if (typeof raw !== "object" || raw === null) {
    throw new ConfigValidationError(`baseline.perCategory.${scope} must be an object`);
  }
  const r = raw as Record<string, unknown>;
  const out: CategoryThreshold = {};
  for (const key of ["precisionMin", "recallMin", "fpRateMax"] as const) {
    if (r[key] === undefined) continue;
    if (!isRate(r[key])) {
      throw new ConfigValidationError(
        `baseline.perCategory.${scope}.${key} must be a rate in [0,1]`,
      );
    }
    out[key] = r[key] as number;
  }
  return out;
}

/** Validate an untrusted object into a {@link Baseline}. Throws ConfigValidationError. */
export function parseBaseline(raw: unknown): Baseline {
  if (typeof raw !== "object" || raw === null) {
    throw new ConfigValidationError("baseline must be a JSON object");
  }
  const r = raw as Record<string, unknown>;
  for (const key of ["fpRateMax", "precisionMin", "recallMin"] as const) {
    if (!isRate(r[key])) {
      throw new ConfigValidationError(`baseline.${key} must be a rate in [0,1]`);
    }
  }
  const baseline: Baseline = {
    fpRateMax: r.fpRateMax as number,
    precisionMin: r.precisionMin as number,
    recallMin: r.recallMin as number,
  };
  if (r.minReposScored !== undefined) {
    if (
      typeof r.minReposScored !== "number" ||
      !Number.isInteger(r.minReposScored) ||
      r.minReposScored < 0
    ) {
      throw new ConfigValidationError("baseline.minReposScored must be a non-negative integer");
    }
    baseline.minReposScored = r.minReposScored;
  }
  if (r.perCategory !== undefined) {
    if (typeof r.perCategory !== "object" || r.perCategory === null) {
      throw new ConfigValidationError("baseline.perCategory must be an object");
    }
    const perCategory: Record<string, CategoryThreshold> = {};
    for (const [cat, val] of Object.entries(r.perCategory as Record<string, unknown>)) {
      perCategory[cat] = parseCategoryThreshold(cat, val);
    }
    baseline.perCategory = perCategory;
  }
  return baseline;
}

/** Read + validate a committed baseline JSON file. */
export async function loadBaselineFile(path: string): Promise<Baseline> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read baseline file: ${path}`, {
      cause: String(cause),
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ConfigValidationError(`baseline file is not valid JSON: ${path}`, {
      cause: String(cause),
    });
  }
  return parseBaseline(json);
}

/**
 * Evaluate a corpus score against the baseline. Returns every violation (not
 * just the first) so operators see the full regression picture at once.
 */
export function evaluateBaseline(score: CorpusScore, baseline: Baseline): RegressionResult {
  const violations: Violation[] = [];

  if (score.fpRate > baseline.fpRateMax + EPS) {
    violations.push({
      scope: "overall",
      metric: "fpRate",
      actual: score.fpRate,
      threshold: baseline.fpRateMax,
      direction: "max",
    });
  }
  if (score.precision < baseline.precisionMin - EPS) {
    violations.push({
      scope: "overall",
      metric: "precision",
      actual: score.precision,
      threshold: baseline.precisionMin,
      direction: "min",
    });
  }
  if (score.recall < baseline.recallMin - EPS) {
    violations.push({
      scope: "overall",
      metric: "recall",
      actual: score.recall,
      threshold: baseline.recallMin,
      direction: "min",
    });
  }
  if (baseline.minReposScored !== undefined && score.reposScored < baseline.minReposScored) {
    violations.push({
      scope: "corpus",
      metric: "reposScored",
      actual: score.reposScored,
      threshold: baseline.minReposScored,
      direction: "min",
    });
  }

  if (baseline.perCategory) {
    const byCategory = new Map(score.perCategory.map((c) => [c.category as string, c]));
    for (const [category, thr] of Object.entries(baseline.perCategory)) {
      const cat = byCategory.get(category);
      // A category with a threshold but no data is treated as perfect (nothing to
      // find, nothing surfaced) — the overall guards still apply.
      if (!cat) continue;
      if (thr.fpRateMax !== undefined && cat.fpRate > thr.fpRateMax + EPS) {
        violations.push({
          scope: category,
          metric: "fpRate",
          actual: cat.fpRate,
          threshold: thr.fpRateMax,
          direction: "max",
        });
      }
      if (thr.precisionMin !== undefined && cat.precision < thr.precisionMin - EPS) {
        violations.push({
          scope: category,
          metric: "precision",
          actual: cat.precision,
          threshold: thr.precisionMin,
          direction: "min",
        });
      }
      if (thr.recallMin !== undefined && cat.recall < thr.recallMin - EPS) {
        violations.push({
          scope: category,
          metric: "recall",
          actual: cat.recall,
          threshold: thr.recallMin,
          direction: "min",
        });
      }
    }
  }

  return { passed: violations.length === 0, violations, baseline };
}
