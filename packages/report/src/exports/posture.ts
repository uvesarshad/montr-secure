/**
 * POSTURE DELTA vs the last scan (§12.1, build-plan §6, WS-M).
 *
 * The frozen {@link PostureDelta} (new / resolved / net) is computed in
 * `report-builder.ts` and surfaced in the executive summary. This module adds:
 *   1. {@link loadPreviousScanContext} — reads SCAN HISTORY from @montr/state-store
 *      (the prior completed scan's confirmed findings) so a caller can populate
 *      `BuildReportInput.previous` from persisted state.
 *   2. {@link computePostureDeltaDetail} — a richer new/fixed/REGRESSED breakdown
 *      (regressed = a finding present in both scans whose severity or exposure got
 *      worse) for the compliance/evidence exports. This never becomes a headline —
 *      the headline stays confirmed-only (golden rule).
 *
 * State-store access is a minimal structural interface so tests run OFFLINE
 * against a fake (no live DB).
 */
import type { ConfirmedFinding, PostureDelta, Scan, Severity } from "@montr/contracts";
import { PostureDeltaSchema } from "@montr/contracts";
import { computePostureDelta, findingFingerprint } from "../report-builder.js";
import type { PreviousScanContext } from "../types.js";

/** Severity ordering used to detect a regression (higher = worse). */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * The slice of the state store this module reads. Structurally satisfied by
 * @montr/state-store's `StateStore` ({ scans, confirmed }). Tests inject a fake.
 */
export interface ScanHistorySource {
  scans: { list(clientId: string, filter?: Record<string, unknown>): Promise<Scan[]> };
  confirmed: { listByScan(clientId: string, scanId: string): Promise<ConfirmedFinding[]> };
}

/**
 * Load the previous scan's context for a posture delta by reading scan history.
 * Picks the most-recent COMPLETED scan for the client other than `currentScanId`
 * (the store lists newest-first). Returns `undefined` when there is no prior scan
 * (first scan for a repo → no delta, which is the correct, honest result).
 */
export async function loadPreviousScanContext(
  store: ScanHistorySource,
  clientId: string,
  currentScanId: string,
  opts: { repo?: string } = {},
): Promise<PreviousScanContext | undefined> {
  const scans = await store.scans.list(clientId);
  const prior = scans.find(
    (s) =>
      s.id !== currentScanId &&
      (s.status === "completed" || s.status === "partial") &&
      (opts.repo === undefined || s.repo === opts.repo),
  );
  if (!prior) return undefined;
  const confirmed = await store.confirmed.listByScan(clientId, prior.id);
  return { scanId: prior.id, confirmed };
}

/** One classified finding in the posture delta (fingerprint + identity + severity). */
export interface PostureFindingRef {
  fingerprint: string;
  findingId: string;
  title: string;
  severity: Severity;
  /** For regressions: the prior severity it worsened from. */
  previousSeverity?: Severity;
}

/**
 * Rich posture breakdown for the evidence exports. `summary` is the SAME frozen
 * {@link PostureDelta} surfaced in the exec summary, so the two never disagree.
 * `regressed` findings are present in BOTH scans (so they are neither new nor
 * resolved) but got worse — a signal auditors care about.
 */
export interface PostureDeltaDetail {
  previousScanId?: string;
  isFirstScan: boolean;
  new: PostureFindingRef[];
  fixed: PostureFindingRef[];
  regressed: PostureFindingRef[];
  unchanged: PostureFindingRef[];
  summary: PostureDelta;
}

function refOf(f: ConfirmedFinding, previousSeverity?: Severity): PostureFindingRef {
  return {
    fingerprint: findingFingerprint(f),
    findingId: f.id,
    title: f.title,
    severity: f.severity,
    ...(previousSeverity ? { previousSeverity } : {}),
  };
}

/** A finding worsened if its severity increased or exposure widened (authed → public). */
function worsened(current: ConfirmedFinding, previous: ConfirmedFinding): boolean {
  if (SEVERITY_RANK[current.severity] > SEVERITY_RANK[previous.severity]) return true;
  return previous.exposure === "authed" && current.exposure === "public";
}

/**
 * Compute the detailed new/fixed/regressed/unchanged posture breakdown. Matches
 * findings across scans by {@link findingFingerprint} so line drift alone does not
 * read as "resolved + new".
 */
export function computePostureDeltaDetail(
  current: readonly ConfirmedFinding[],
  previous?: PreviousScanContext,
): PostureDeltaDetail {
  if (!previous) {
    return {
      isFirstScan: true,
      new: current.map((f) => refOf(f)),
      fixed: [],
      regressed: [],
      unchanged: [],
      summary: PostureDeltaSchema.parse({ newIssues: 0, resolvedIssues: 0, netDelta: 0 }),
    };
  }

  const curByFp = new Map<string, ConfirmedFinding>();
  for (const f of current)
    if (!curByFp.has(findingFingerprint(f))) curByFp.set(findingFingerprint(f), f);
  const prevByFp = new Map<string, ConfirmedFinding>();
  for (const f of previous.confirmed) {
    const fp = findingFingerprint(f);
    if (!prevByFp.has(fp)) prevByFp.set(fp, f);
  }

  const newFindings: PostureFindingRef[] = [];
  const regressed: PostureFindingRef[] = [];
  const unchanged: PostureFindingRef[] = [];
  for (const [fp, f] of curByFp) {
    const prior = prevByFp.get(fp);
    if (!prior) {
      newFindings.push(refOf(f));
    } else if (worsened(f, prior)) {
      regressed.push(refOf(f, prior.severity));
    } else {
      unchanged.push(refOf(f));
    }
  }

  const fixed: PostureFindingRef[] = [];
  for (const [fp, f] of prevByFp) {
    if (!curByFp.has(fp)) fixed.push(refOf(f));
  }

  return {
    ...(previous.scanId ? { previousScanId: previous.scanId } : {}),
    isFirstScan: false,
    new: newFindings,
    fixed,
    regressed,
    unchanged,
    // Reuse the frozen computation so summary numbers always match the exec summary.
    summary: computePostureDelta(current, previous),
  };
}
