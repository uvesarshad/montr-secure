/**
 * Deduplication. The same root cause reported by multiple tools (e.g. Semgrep +
 * a custom rule both flagging one raw query) must collapse into ONE issue with
 * `mergedCandidateIds[]` (PRD §7 Layer 2). Injection findings are keyed on the
 * mapped SINK location — so two tools pointing at different lines of the same
 * flow still merge — while config/secret/dependency findings key on their
 * natural identity (file, or package).
 */
import type { CandidateFinding } from "@montr/contracts";
import { AppMapIndex, extractPackageName, groundCandidate, type Grounding } from "./grounding.js";
import { SEVERITY_WEIGHT } from "./taxonomy.js";

export interface RootCauseGroup {
  key: string;
  category: CandidateFinding["category"];
  candidates: CandidateFinding[];
  /** Highest-severity candidate (report location + representative grounding). */
  representative: CandidateFinding;
  grounding: Grounding;
}

function dedupKey(cand: CandidateFinding, g: Grounding): string {
  const cat = cand.category;
  if (g.klass === "injection" && g.matchedSink) {
    const l = g.matchedSink.location;
    return `${cat}@sink:${l.file}:${l.line}`;
  }
  if (g.klass === "config" || g.klass === "secret") {
    // One misconfiguration / secret per file is a single root cause.
    return `${cat}@file:${cand.location.file}`;
  }
  if (g.klass === "dependency") {
    return `${cat}@pkg:${extractPackageName(cand) ?? cand.location.file}`;
  }
  return `${cat}@loc:${cand.location.file}:${cand.location.line}`;
}

function pickRepresentative(cands: CandidateFinding[]): CandidateFinding {
  let best: CandidateFinding | undefined;
  for (const c of cands) {
    if (!best) {
      best = c;
      continue;
    }
    const cw = SEVERITY_WEIGHT[c.rawSeverity];
    const bw = SEVERITY_WEIGHT[best.rawSeverity];
    if (cw > bw || (cw === bw && c.location.line < best.location.line)) best = c;
  }
  if (!best) throw new Error("pickRepresentative: empty group");
  return best;
}

/** Group candidates into deduplicated root causes, grounded against the App Map. */
export function groupCandidates(
  candidates: CandidateFinding[],
  index: AppMapIndex,
): RootCauseGroup[] {
  const groundings = new Map<string, Grounding>();
  const buckets = new Map<string, CandidateFinding[]>();
  const order: string[] = [];

  for (const cand of candidates) {
    const g = groundCandidate(cand, index);
    groundings.set(cand.id, g);
    const key = dedupKey(cand, g);
    const bucket = buckets.get(key);
    if (bucket) {
      bucket.push(cand);
    } else {
      buckets.set(key, [cand]);
      order.push(key);
    }
  }

  return order.map((key) => {
    const members = buckets.get(key) ?? [];
    const representative = pickRepresentative(members);
    // Ground the group on its representative (the sink/highest-severity member).
    const grounding = groundings.get(representative.id) ?? groundCandidate(representative, index);
    return {
      key,
      category: representative.category,
      candidates: members,
      representative,
      grounding,
    };
  });
}
