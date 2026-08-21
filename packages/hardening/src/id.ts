import { createHash } from "node:crypto";
import type { RecommendationDraft } from "./types.js";

/**
 * Stable id from a draft's identity (category + title + evidence) — same
 * "hash of the identity tuple" spirit as `@montr/discovery`'s
 * `candidateId`/`fnv1a` (`packages/discovery/src/util/ids.ts`), reimplemented
 * locally rather than imported so this package's only dependency on
 * `@montr/discovery` stays scoped to genuine file/dependency detection
 * helpers (see this package's index.ts module doc on why it does not import
 * `@montr/fix` at all).
 */
export function hardeningId(
  draft: Pick<RecommendationDraft, "category" | "title" | "evidence">,
): string {
  const key = [draft.category, draft.title, ...draft.evidence].join("|");
  const hash = createHash("sha1").update(key).digest("hex").slice(0, 16);
  return `hard_${draft.category}_${hash}`;
}
