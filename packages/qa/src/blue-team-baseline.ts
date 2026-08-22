import { readFile } from "node:fs/promises";
import { ConfigValidationError } from "@montr/contracts";
import type { BlueTeamCorpusScore } from "./blue-team-corpus.js";

/**
 * B12 — committed regression baseline for the blue-team detection corpus
 * gate. Mirrors `packages/qa/src/baseline.ts`'s `Baseline`/`evaluateBaseline`
 * shape and conventions exactly, scaled to the blue-team corpus's own
 * metrics (detection precision/recall over labelled scenarios, not
 * finding-level precision/recall/FP-rate over the golden corpus). The scorer
 * (`pnpm --filter @montr/qa qa:blue-team-corpus`) exits non-zero when a run
 * falls below these thresholds. Tighten (never loosen) as the labelled
 * corpus grows or detection-rule generation improves.
 */
export interface BlueTeamBaseline {
  detectionPrecisionMin: number;
  detectionRecallMin: number;
  /** Guard: require at least this many labelled scenarios to have been scored (catches an empty/truncated run). */
  minScenariosScored?: number;
}

/** Fail-safe defaults — a floor low enough to never block on an empty/near-empty corpus. */
export const DEFAULT_BLUE_TEAM_BASELINE: BlueTeamBaseline = {
  detectionPrecisionMin: 0.5,
  detectionRecallMin: 0.5,
};

/** A single threshold breach. */
export interface BlueTeamViolation {
  metric: "detectionPrecision" | "detectionRecall" | "scenariosScored";
  actual: number;
  threshold: number;
  direction: "min";
}

export interface BlueTeamRegressionResult {
  passed: boolean;
  violations: BlueTeamViolation[];
  baseline: BlueTeamBaseline;
}

/** Small epsilon so floating-point equality does not spuriously fail (mirrors baseline.ts). */
const EPS = 1e-9;

function isRate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

/** Validate an untrusted object into a {@link BlueTeamBaseline}. Throws ConfigValidationError. */
export function parseBlueTeamBaseline(raw: unknown): BlueTeamBaseline {
  if (typeof raw !== "object" || raw === null) {
    throw new ConfigValidationError("blue-team baseline must be a JSON object");
  }
  const r = raw as Record<string, unknown>;
  for (const key of ["detectionPrecisionMin", "detectionRecallMin"] as const) {
    if (!isRate(r[key])) {
      throw new ConfigValidationError(`blueTeamBaseline.${key} must be a rate in [0,1]`);
    }
  }
  const baseline: BlueTeamBaseline = {
    detectionPrecisionMin: r.detectionPrecisionMin as number,
    detectionRecallMin: r.detectionRecallMin as number,
  };
  if (r.minScenariosScored !== undefined) {
    if (
      typeof r.minScenariosScored !== "number" ||
      !Number.isInteger(r.minScenariosScored) ||
      r.minScenariosScored < 0
    ) {
      throw new ConfigValidationError(
        "blueTeamBaseline.minScenariosScored must be a non-negative integer",
      );
    }
    baseline.minScenariosScored = r.minScenariosScored;
  }
  return baseline;
}

/** Read + validate a committed blue-team baseline JSON file. */
export async function loadBlueTeamBaselineFile(path: string): Promise<BlueTeamBaseline> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read blue-team baseline file: ${path}`, {
      cause: String(cause),
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ConfigValidationError(`blue-team baseline file is not valid JSON: ${path}`, {
      cause: String(cause),
    });
  }
  return parseBlueTeamBaseline(json);
}

/**
 * Evaluate a blue-team corpus score against the baseline. Returns every
 * violation (not just the first) so operators see the full regression
 * picture at once — mirrors `evaluateBaseline` (baseline.ts) exactly.
 */
export function evaluateBlueTeamBaseline(
  score: BlueTeamCorpusScore,
  baseline: BlueTeamBaseline,
): BlueTeamRegressionResult {
  const violations: BlueTeamViolation[] = [];

  if (score.detectionPrecision < baseline.detectionPrecisionMin - EPS) {
    violations.push({
      metric: "detectionPrecision",
      actual: score.detectionPrecision,
      threshold: baseline.detectionPrecisionMin,
      direction: "min",
    });
  }
  if (score.detectionRecall < baseline.detectionRecallMin - EPS) {
    violations.push({
      metric: "detectionRecall",
      actual: score.detectionRecall,
      threshold: baseline.detectionRecallMin,
      direction: "min",
    });
  }
  if (
    baseline.minScenariosScored !== undefined &&
    score.totalScenarios < baseline.minScenariosScored
  ) {
    violations.push({
      metric: "scenariosScored",
      actual: score.totalScenarios,
      threshold: baseline.minScenariosScored,
      direction: "min",
    });
  }

  return { passed: violations.length === 0, violations, baseline };
}
