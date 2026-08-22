import { readFile } from "node:fs/promises";
import { ConfigValidationError } from "@montr/contracts";
import { BLUE_TEAM_GROUND_TRUTH, type BlueTeamScenarioResult } from "./blue-team-corpus.js";

/**
 * Parse a blue-team-scan-results file into {@link BlueTeamScenarioResult}[] —
 * mirrors `findings-io.ts#parseScanFindings`'s shape/conventions exactly, for
 * the blue-team detection corpus. This is how a REAL run's output (written
 * by `scripts/blue-team-corpus-scan.mjs`) is fed to the gate.
 *
 * Accepted shape:
 *   { "results": [{ "templateKey": "...", "actualFired": bool, "evidence": "...", "sigmaRulesEvaluated": n }, ...] }
 *
 * Each entry's `expectedFired`/`findingCategory`/`scenarioName` are taken from
 * the COMMITTED ground truth ({@link BLUE_TEAM_GROUND_TRUTH}), never from the
 * findings file itself — a findings file can only ever report what actually
 * happened, not redefine what should have happened.
 */
export function parseBlueTeamScanFindings(raw: unknown): BlueTeamScenarioResult[] {
  const container = raw as { results?: unknown } | unknown[];
  const entries = Array.isArray(container) ? container : container?.results;
  if (!Array.isArray(entries)) {
    throw new ConfigValidationError(
      "blue-team findings file must be an array or an object with a `results` array",
    );
  }

  const groundTruthByKey = new Map(BLUE_TEAM_GROUND_TRUTH.map((c) => [c.templateKey, c]));

  return entries.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new ConfigValidationError(`results[${i}] must be an object`);
    }
    const rec = entry as Record<string, unknown>;
    if (typeof rec.templateKey !== "string" || rec.templateKey.length === 0) {
      throw new ConfigValidationError(`results[${i}].templateKey must be a non-empty string`);
    }
    if (typeof rec.actualFired !== "boolean") {
      throw new ConfigValidationError(`results[${i}].actualFired must be a boolean`);
    }
    const groundTruth = groundTruthByKey.get(rec.templateKey);
    if (!groundTruth) {
      throw new ConfigValidationError(
        `results[${i}].templateKey "${rec.templateKey}" is not in BLUE_TEAM_GROUND_TRUTH — the committed labelled corpus changed underneath this findings file`,
      );
    }
    return {
      templateKey: rec.templateKey,
      scenarioName: typeof rec.scenarioName === "string" ? rec.scenarioName : rec.templateKey,
      findingCategory: groundTruth.findingCategory,
      expectedFired: groundTruth.expectedFired,
      actualFired: rec.actualFired,
      evidence: typeof rec.evidence === "string" ? rec.evidence : "",
      sigmaRulesEvaluated:
        typeof rec.sigmaRulesEvaluated === "number" ? rec.sigmaRulesEvaluated : 0,
    };
  });
}

/** Read + validate a blue-team scan-results JSON file. Throws ConfigValidationError. */
export async function loadBlueTeamScanFindingsFile(
  path: string,
): Promise<BlueTeamScenarioResult[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read blue-team findings file: ${path}`, {
      cause: String(cause),
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ConfigValidationError(`blue-team findings file is not valid JSON: ${path}`, {
      cause: String(cause),
    });
  }
  return parseBlueTeamScanFindings(json);
}
