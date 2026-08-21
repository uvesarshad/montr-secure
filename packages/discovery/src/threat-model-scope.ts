/**
 * E6 — consume Layer 0's threat-model `ScopeHints` to PRIORITIZE Layer 1
 * candidates. ⛔ SAFETY: this module is additive-only. It never removes a
 * candidate, never skips a detector, and never changes `candidates.length` —
 * it only (1) annotates matching candidates with `metadata.threatModelPriority`
 * and (2) stable-sorts priority-annotated candidates first, so a downstream
 * consumer that looks at "the top N" naturally sees the app's actual highest-
 * risk surface first. See `packages/contracts/src/threat-model.ts`'s
 * `ScopeHintsSchema` doc comment for why this is a prioritization signal, not
 * a filter — recall can never regress because a hint was wrong.
 *
 * `zeroSurfaceCategories` (e.g. no XXE surface because no deserialize sink
 * exists anywhere in the App Map) is deliberately NOT consumed here to skip
 * anything — every candidate the deterministic detectors already produced for
 * that category still ships unchanged. It remains purely advisory metadata a
 * future report/UI layer could use to de-emphasize a section.
 */
import type { AppMap, CandidateFinding } from "@montr/contracts";

/** Route handler files named by `scopeHints.priorityRoutePaths`, resolved via the App Map. */
function priorityFiles(appMap: AppMap, priorityRoutePaths: readonly string[]): Set<string> {
  if (priorityRoutePaths.length === 0) return new Set();
  const wanted = new Set(priorityRoutePaths);
  const files = new Set<string>();
  for (const route of appMap.routes) {
    if (wanted.has(route.path) && route.handler?.file) files.add(route.handler.file);
  }
  return files;
}

function hasThreatModelPriority(c: CandidateFinding): boolean {
  return Boolean(
    (c.metadata as { threatModelPriority?: unknown } | undefined)?.threatModelPriority,
  );
}

/**
 * Annotate candidates whose category or file matches the threat model's
 * `scopeHints`, then stable-sort priority-annotated candidates first. Returns
 * the SAME set of candidates (by id), same length, just reordered/annotated —
 * every existing candidate id from the input is present in the output.
 */
export function applyThreatModelScopeHints(
  candidates: CandidateFinding[],
  appMap: AppMap,
): CandidateFinding[] {
  const threatModel = appMap.threatModel;
  if (!threatModel || candidates.length === 0) return candidates;

  const priorityCategories = new Set(
    threatModel.scopeHints.priorityCategories.map((h) => h.category),
  );
  const files = priorityFiles(appMap, threatModel.scopeHints.priorityRoutePaths);
  if (priorityCategories.size === 0 && files.size === 0) return candidates;

  const annotated = candidates.map((c) => {
    const categoryMatch = priorityCategories.has(c.category);
    const routeMatch = files.has(c.location.file);
    if (!categoryMatch && !routeMatch) return c;
    return {
      ...c,
      metadata: {
        ...(c.metadata ?? {}),
        threatModelPriority: {
          ...(categoryMatch ? { categoryMatch: true } : {}),
          ...(routeMatch ? { routeMatch: true } : {}),
        },
      },
    };
  });

  // Stable sort (Array.prototype.sort is spec-guaranteed stable): priority
  // candidates float to the front, ties keep their original relative order.
  return [...annotated].sort((a, b) => {
    const ap = hasThreatModelPriority(a);
    const bp = hasThreatModelPriority(b);
    if (ap === bp) return 0;
    return ap ? -1 : 1;
  });
}
