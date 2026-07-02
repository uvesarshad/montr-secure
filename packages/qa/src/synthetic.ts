import { ConfirmedFindingSchema, type ConfirmedFinding } from "@montr/contracts";
import type { GroundTruthFinding, GroundTruthRepo } from "@montr/fixtures";

/**
 * Build a valid {@link ConfirmedFinding} from a ground-truth label. Used by the
 * "perfect scanner" self-check (so the gate is runnable + green before the real
 * pipeline is wired) and as a deterministic test helper. All values are derived
 * from the manifest — no Date.now()/random, no client code bodies.
 */

const SYNTHETIC_NOW = "2026-01-15T10:00:00.000Z";
const SYNTHETIC_CLIENT_ID = "client_corpus_synthetic";
const SYNTHETIC_SCAN_ID = "scan_corpus_synthetic";

export function groundTruthToConfirmed(
  gt: GroundTruthFinding,
  overrides: Partial<ConfirmedFinding> = {},
): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: `conf_${gt.id}`,
    scanId: SYNTHETIC_SCAN_ID,
    clientId: SYNTHETIC_CLIENT_ID,
    title: `Confirmed ${gt.category} at ${gt.file}:${gt.line}`,
    category: gt.category,
    cwe: gt.cwe,
    owasp: gt.owasp,
    severity: gt.severity,
    exposure: "public",
    location: { file: gt.file, line: gt.line },
    impact: gt.description,
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: gt.description,
      dataFlow: [],
      sanitizersBypassed: [],
    },
    createdAt: SYNTHETIC_NOW,
    ...overrides,
  });
}

/** A perfect scan of one repo: exactly the exploitable ground-truth findings. */
export function perfectConfirmedForRepo(repo: GroundTruthRepo): ConfirmedFinding[] {
  return repo.expectedFindings.filter((f) => f.exploitable).map((f) => groundTruthToConfirmed(f));
}
