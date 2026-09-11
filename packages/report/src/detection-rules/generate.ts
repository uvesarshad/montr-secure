/**
 * B3/B4 — top-level entry point. `generateDetectionRules` is pure (no I/O):
 * it builds one `DetectionRule` per format (sigma/otel/siem_query) for a
 * single confirmed finding, all three carrying the SAME B4 log-signature
 * narrative (identical underlying detection logic, three renderings — see
 * context.ts's header). `persistDetectionRules` is the thin I/O wrapper that
 * actually calls `StateStore.detectionRules.create` for each generated rule
 * (the B1 repository, packages/state-store/src/blue-team.ts).
 *
 * WIRED: `report-builder.ts`'s `buildBlueTeamReport` calls this unconditionally
 * (once per confirmed finding, via `.flatMap`) to populate the assembled
 * Layer 5 report's detection-engineering section — see that file's B3/B4
 * comment block.
 *
 * `mitreTechniques` defaults to B2's real mapping
 * (`mitreTechniqueIdsForCategory`, packages/contracts/src/mitre.ts — landed
 * concurrently in this same wave) rather than `[]`; still overridable via
 * `GenerateDetectionRulesDeps.mitreTechniques` for a caller with a more
 * specific per-finding mapping.
 */
import type {
  AppMap,
  ConfirmedFinding,
  DetectionRule,
  DetectionRuleFormat,
} from "@montr/contracts";
import { mitreTechniqueIdsForCategory } from "@montr/contracts";
import type { StateStore } from "@montr/state-store";
import { buildRuleContext } from "./context.js";
import { buildSigmaRule } from "./sigma.js";
import { buildOtelQuery } from "./otel.js";
import { buildSiemQuery } from "./siem.js";
import { buildLogSignature } from "./narrative.js";
import { deterministicUuid } from "./id.js";

export interface GenerateDetectionRulesDeps {
  /**
   * MITRE ATT&CK technique ids for this finding. B2 landed
   * (packages/contracts/src/mitre.ts) partway through this same wave, so the
   * default is now `mitreTechniqueIdsForCategory(finding.category)` — B2's
   * real, exhaustive category -> ATT&CK/ATLAS mapping — rather than `[]`.
   * Still overridable (e.g. a caller with a more specific per-finding
   * mapping than the category-level default).
   */
  mitreTechniques?: string[];
  /**
   * The App Map, used only to resolve a route for STATIC-proof findings
   * (route.ts). Live-proof findings need no App Map — the route comes
   * straight from the transcript.
   */
  appMap?: AppMap;
  /** Clock override (tests). */
  now?: () => string;
  /**
   * Id factory override (tests). Default: deterministic, seeded from
   * `${finding.id}:${format}` — re-generating for the same finding produces
   * the same ids (not literal DB idempotency — `create` always inserts a new
   * row — but makes output reproducible for tests/diffing).
   */
  idFactory?: (finding: ConfirmedFinding, format: DetectionRuleFormat) => string;
}

const FORMATS: readonly DetectionRuleFormat[] = ["sigma", "otel", "siem_query"];

function defaultId(finding: ConfirmedFinding, format: DetectionRuleFormat): string {
  return `detr_${format}_${deterministicUuid(`${finding.id}:${format}`).replace(/-/g, "").slice(0, 20)}`;
}

/** Pure — no I/O. Builds one `DetectionRule` per format for one finding. */
export function generateDetectionRules(
  finding: ConfirmedFinding,
  deps: GenerateDetectionRulesDeps = {},
): DetectionRule[] {
  const ctx = buildRuleContext(finding, deps.appMap);
  const mitreTechniques = deps.mitreTechniques ?? mitreTechniqueIdsForCategory(finding.category);
  const logSignature = buildLogSignature(finding, ctx);
  const now = deps.now ?? (() => new Date().toISOString());
  const idFactory = deps.idFactory ?? defaultId;
  const createdAt = now();

  const contentByFormat: Record<DetectionRuleFormat, string> = {
    sigma: buildSigmaRule(finding, ctx, mitreTechniques),
    otel: buildOtelQuery(ctx),
    siem_query: buildSiemQuery(ctx),
  };

  return FORMATS.map((format) => ({
    id: idFactory(finding, format),
    clientId: finding.clientId,
    scanId: finding.scanId,
    findingId: finding.id,
    format,
    content: contentByFormat[format],
    mitreTechniques,
    provenance: finding.proofType,
    logSignature,
    createdAt,
  }));
}

/**
 * I/O wrapper: generates + persists every format's `DetectionRule` via
 * `StateStore.detectionRules.create` (B1's repository), row-scoped by
 * `finding.clientId`.
 */
export async function persistDetectionRules(
  store: StateStore,
  finding: ConfirmedFinding,
  deps: GenerateDetectionRulesDeps = {},
): Promise<DetectionRule[]> {
  const rules = generateDetectionRules(finding, deps);
  const created: DetectionRule[] = [];
  for (const rule of rules) {
    created.push(await store.detectionRules.create(finding.clientId, rule));
  }
  return created;
}
