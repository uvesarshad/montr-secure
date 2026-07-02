import { readFile } from "node:fs/promises";
import { ConfigValidationError, ConfirmedFindingSchema } from "@montr/contracts";
import type { RepoScanResult } from "./types.js";

/**
 * Parse a scan-results file into {@link RepoScanResult}[] for the scorer. This is
 * how real Layer-3 output (per repo) is fed to the gate once the pipeline lands.
 *
 * Accepted shapes:
 *   [{ "repo": "<name>", "confirmed": ConfirmedFinding[] }, ...]
 *   { "results": [{ "repo": "<name>", "confirmed": ConfirmedFinding[] }, ...] }
 */
export function parseScanFindings(raw: unknown): RepoScanResult[] {
  const container = raw as { results?: unknown } | unknown[];
  const entries = Array.isArray(container) ? container : container?.results;
  if (!Array.isArray(entries)) {
    throw new ConfigValidationError(
      "findings file must be an array or an object with a `results` array",
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
    if (!Array.isArray(rec.confirmed)) {
      throw new ConfigValidationError(`results[${i}].confirmed must be an array`);
    }
    const confirmed = rec.confirmed.map((c, j) => {
      const parsed = ConfirmedFindingSchema.safeParse(c);
      if (!parsed.success) {
        throw new ConfigValidationError(
          `results[${i}].confirmed[${j}] is not a valid ConfirmedFinding: ${parsed.error.issues
            .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
            .join("; ")}`,
        );
      }
      return parsed.data;
    });
    return { repo: rec.repo, confirmed };
  });
}

/** Read + validate a scan-results JSON file. Throws ConfigValidationError. */
export async function loadScanFindingsFile(path: string): Promise<RepoScanResult[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`could not read findings file: ${path}`, {
      cause: String(cause),
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ConfigValidationError(`findings file is not valid JSON: ${path}`, {
      cause: String(cause),
    });
  }
  return parseScanFindings(json);
}
