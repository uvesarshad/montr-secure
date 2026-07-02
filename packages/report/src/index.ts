/**
 * @montr/report — Layer 5: report model (§12), exports (SARIF/PDF/HTML/JSON),
 * and the gated auto-fix PR flow.
 *
 * ⛔ Never headline raw counts — headline = confirmed + prioritized; appendix
 * holds breadth. PRs only for auto-eligible fixes (never direct commits);
 * human-required fixes are always recommendations. Implementation: WS-J.
 */
import {
  NotImplementedError,
  type ConfirmedFinding,
  type CostRollup,
  type ExportArtifact,
  type ExportFormat,
  type Fix,
  type Layer5Output,
  type Report,
  type Scan,
  type UnconfirmedFinding,
} from "@montr/contracts";

export interface BuildReportInput {
  scan: Scan;
  confirmed: ConfirmedFinding[];
  unconfirmed: UnconfirmedFinding[];
  fixes: Fix[];
  costRollup: CostRollup;
  /** When true, open PRs for auto-eligible fixes (gated). */
  autoApply: boolean;
}

export async function buildReport(_input: BuildReportInput): Promise<Layer5Output> {
  throw new NotImplementedError("buildReport — WS-J");
}

export async function exportReport(
  _report: Report,
  _format: ExportFormat,
): Promise<ExportArtifact> {
  throw new NotImplementedError("exportReport — WS-J / WS-M");
}
