import { readFile } from "node:fs/promises";
import { ConfigValidationError } from "@montr/contracts";
import type { DetectionCoverageScore } from "./detection-coverage-scorer.js";

/**
 * Committed regression baseline for the detection-coverage gate (suggested
 * enhancement, docs/plan/26-09-12-tasks-red-blue-agentic-posture.md — "fail a
 * build when a newly confirmed finding lands on a route with no telemetry").
 * Mirrors `packages/qa/src/baseline.ts`'s `Baseline`/`evaluateBaseline` and
 * `blue-team-baseline.ts`'s `BlueTeamBaseline`/`evaluateBlueTeamBaseline`
 * shape exactly, scaled to this gate's own metric: what fraction of confirmed
 * findings land on a route A7's tri-state `DetectionCoverage.detected` verdict
 * calls a GENUINE gap (`false` — see `detection-coverage-scorer.ts`'s module
 * header for why `"unknown"` is deliberately excluded from this threshold).
 * The scorer (`pnpm --filter @montr/qa qa:detection-coverage`) exits non-zero
 * when a real run's `gapRate` exceeds this ceiling. Tighten (never loosen) as
 * telemetry/detection-rule coverage improves.
 */
export interface DetectionCoverageBaseline {
  /** Ceiling: detectedFalse / totalConfirmedFindings must not exceed this. */
  gapRateMax: number;
  /** Guard: require at least this many confirmed findings to have been scored (catches an empty/degraded run). */
  minConfirmedFindings?: number;
}

/** Fail-safe default — a ceiling wide enough to never block before a real measurement exists. */
export const DEFAULT_DETECTION_COVERAGE_BASELINE: DetectionCoverageBaseline = {
  gapRateMax: 1,
};

/** A single threshold breach. */
export interface DetectionCoverageViolation {
  metric: "gapRate" | "confirmedFindingsScored";
  actual: number;
  threshold: number;
  direction: "min" | "max";
}

export interface DetectionCoverageRegressionResult {
  passed: boolean;
  violations: DetectionCoverageViolation[];
  baseline: DetectionCoverageBaseline;
}

/** Small epsilon so floating-point equality does not spuriously fail (mirrors baseline.ts). */
const EPS = 1e-9;

function isRate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

/** Validate an untrusted object into a {@link DetectionCoverageBaseline}. Throws ConfigValidationError. */
export function parseDetectionCoverageBaseline(raw: unknown): DetectionCoverageBaseline {
  if (typeof raw !== "object" || raw === null) {
    throw new ConfigValidationError("detection-coverage baseline must be a JSON object");
  }
  const r = raw as Record<string, unknown>;
  if (!isRate(r.gapRateMax)) {
    throw new ConfigValidationError("detectionCoverageBaseline.gapRateMax must be a rate in [0,1]");
  }
  const baseline: DetectionCoverageBaseline = { gapRateMax: r.gapRateMax as number };
  if (r.minConfirmedFindings !== undefined) {
    if (
      typeof r.minConfirmedFindings !== "number" ||
      !Number.isInteger(r.minConfirmedFindings) ||
      r.minConfirmedFindings < 0
    ) {
      throw new ConfigValidationError(
        "detectionCoverageBaseline.minConfirmedFindings must be a non-negative integer",
      );
    }
    baseline.minConfirmedFindings = r.minConfirmedFindings;
  }
  return baseline;
}

/** Read + validate a committed detection-coverage baseline JSON file. */
export async function loadDetectionCoverageBaselineFile(
  path: string,
): Promise<DetectionCoverageBaseline> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read detection-coverage baseline file: ${path}`, {
      cause: String(cause),
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ConfigValidationError(`detection-coverage baseline file is not valid JSON: ${path}`, {
      cause: String(cause),
    });
  }
  return parseDetectionCoverageBaseline(json);
}

/**
 * Evaluate a detection-coverage score against the baseline. Returns every
 * violation (not just the first) — mirrors `evaluateBaseline`/
 * `evaluateBlueTeamBaseline` exactly.
 */
export function evaluateDetectionCoverageBaseline(
  score: DetectionCoverageScore,
  baseline: DetectionCoverageBaseline,
): DetectionCoverageRegressionResult {
  const violations: DetectionCoverageViolation[] = [];

  if (score.gapRate > baseline.gapRateMax + EPS) {
    violations.push({
      metric: "gapRate",
      actual: score.gapRate,
      threshold: baseline.gapRateMax,
      direction: "max",
    });
  }
  if (
    baseline.minConfirmedFindings !== undefined &&
    score.totalConfirmedFindings < baseline.minConfirmedFindings
  ) {
    violations.push({
      metric: "confirmedFindingsScored",
      actual: score.totalConfirmedFindings,
      threshold: baseline.minConfirmedFindings,
      direction: "min",
    });
  }

  return { passed: violations.length === 0, violations, baseline };
}
