import { readFile } from "node:fs/promises";
import { CategorySchema, ConfigValidationError } from "@montr/contracts";
import type { DetectionCoverageEntry } from "./detection-coverage-scorer.js";

/**
 * Parse a detection-coverage-scan-results file into
 * {@link DetectionCoverageEntry}[] — mirrors `findings-io.ts#parseScanFindings`
 * / `blue-team-findings-io.ts#parseBlueTeamScanFindings`'s shape exactly. This
 * is how a REAL run's output (written by `scripts/detection-coverage-scan.mjs`)
 * is fed to the gate.
 *
 * Accepted shape:
 *   { "results": [{ "repo": "...", "findingId": "...", "category": "...", "detected": true|false|"unknown", "reasoning": "..." }, ...] }
 */
export function parseDetectionCoverageFindings(raw: unknown): DetectionCoverageEntry[] {
  const container = raw as { results?: unknown } | unknown[];
  const entries = Array.isArray(container) ? container : container?.results;
  if (!Array.isArray(entries)) {
    throw new ConfigValidationError(
      "detection-coverage findings file must be an array or an object with a `results` array",
    );
  }

  return entries.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new ConfigValidationError(`results[${i}] must be an object`);
    }
    const rec = entry as Record<string, unknown>;
    if (typeof rec.repo !== "string" || rec.repo.length === 0) {
      throw new ConfigValidationError(`results[${i}].repo must be a non-empty string`);
    }
    if (typeof rec.findingId !== "string" || rec.findingId.length === 0) {
      throw new ConfigValidationError(`results[${i}].findingId must be a non-empty string`);
    }
    const category = CategorySchema.safeParse(rec.category);
    if (!category.success) {
      throw new ConfigValidationError(`results[${i}].category is not a valid Category`);
    }
    if (rec.detected !== true && rec.detected !== false && rec.detected !== "unknown") {
      throw new ConfigValidationError(`results[${i}].detected must be true, false, or "unknown"`);
    }
    return {
      repo: rec.repo,
      findingId: rec.findingId,
      category: category.data,
      detected: rec.detected,
      reasoning: typeof rec.reasoning === "string" ? rec.reasoning : "",
    };
  });
}

/** Read + validate a detection-coverage scan-results JSON file. Throws ConfigValidationError. */
export async function loadDetectionCoverageFindingsFile(
  path: string,
): Promise<DetectionCoverageEntry[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read detection-coverage findings file: ${path}`, {
      cause: String(cause),
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ConfigValidationError(`detection-coverage findings file is not valid JSON: ${path}`, {
      cause: String(cause),
    });
  }
  return parseDetectionCoverageFindings(json);
}
