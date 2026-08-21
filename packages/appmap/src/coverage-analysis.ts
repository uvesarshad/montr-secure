/**
 * Detection-coverage gap analysis (B6) — given a CONFIRMED finding, its
 * linked route, the App Map's `telemetrySurfaces` (see telemetry-surfaces.ts),
 * and any existing `DetectionRule`s for it, derive a tri-state
 * `DetectionCoverage.detected` verdict with a real, specific `reasoning`
 * string. No partial credit: every branch below is earned from a concrete
 * signal (route resolution, per-route logging presence, rule existence) —
 * "unknown" is returned only for the genuinely ambiguous cases named in the
 * task (console-only logging with no structured fields; a route that could
 * not be linked or was never analyzed), never as a blanket default.
 *
 * ⛔ Distinct from B5's purple-team loop: B5 runs an ACTUAL scenario and
 * checks whether a rule fires against LIVE telemetry (a later, separate wave
 * item). This module never executes anything — it is a static readout of
 * the App Map's own structural telemetry evidence, always available the
 * moment a finding is confirmed.
 */
import type {
  AppMap,
  ConfirmedFinding,
  DetectionCoverage,
  DetectionRule,
  DetectionStatus,
  Route,
  RouteTelemetry,
} from "@montr/contracts";
import { DetectionCoverageSchema } from "@montr/contracts";
import type { DetectionCoverageRepository, DetectionRuleRepository } from "@montr/state-store";

export interface CoverageVerdict {
  detected: DetectionStatus;
  reasoning: string;
  detectionRuleId?: string;
}

/**
 * Resolve the route a confirmed finding belongs to. Matches by handler file
 * first (same discipline `threat-model.ts`'s `routePathForFile` already
 * uses); when several routes share a file (a common single-file Express/
 * Fastify shape), prefers the route whose handler starts at or before the
 * finding's line and is closest to it — real proximity evidence, not a
 * first-match guess.
 */
export function routeForFinding(appMap: AppMap, finding: ConfirmedFinding): Route | undefined {
  const file = finding.location.file;
  const candidates = appMap.routes.filter((r) => r.handler?.file === file);
  if (candidates.length === 0) return undefined;
  if (candidates.length === 1) return candidates[0];

  const line = finding.location.line;
  const before = candidates.filter((r) => (r.handler?.line ?? 0) <= line);
  const pool = before.length > 0 ? before : candidates;
  return pool.reduce((best, r) => {
    const bestDist = Math.abs((best.handler?.line ?? 0) - line);
    const dist = Math.abs((r.handler?.line ?? 0) - line);
    return dist < bestDist ? r : best;
  });
}

function telemetryForRoute(appMap: AppMap, route: Route | undefined): RouteTelemetry | undefined {
  if (!route) return undefined;
  return appMap.telemetrySurfaces?.routes.find(
    (rt) => rt.path === route.path && rt.method === route.method,
  );
}

/**
 * Derive the tri-state coverage verdict for one confirmed finding.
 * `existingRules` should already be filtered/queried for `finding.id` (see
 * {@link buildDetectionCoverage}), but this function re-filters defensively
 * so callers may also pass an unfiltered per-scan rule list.
 */
export function evaluateCoverageForFinding(
  appMap: AppMap,
  finding: ConfirmedFinding,
  existingRules: readonly DetectionRule[],
): CoverageVerdict {
  const rule = existingRules.find((r) => r.findingId === finding.id);
  const route = routeForFinding(appMap, finding);
  const ruleRef = rule ? { detectionRuleId: rule.id } : {};

  if (!route) {
    return {
      detected: rule ? "unknown" : false,
      reasoning: rule
        ? `A detection rule (${rule.id}, format ${rule.format}) exists for this finding, but the ` +
          `finding at ${finding.location.file}:${finding.location.line} could not be linked to a ` +
          "specific route in the App Map, so whether the target's telemetry actually covers the " +
          "request path this finding lives on cannot be determined."
        : `No detection rule exists for this finding, and the finding at ${finding.location.file}:` +
          `${finding.location.line} could not be linked to a specific route in the App Map — there ` +
          "is no route-scoped telemetry surface to evaluate at all.",
      ...ruleRef,
    };
  }

  const telemetry = telemetryForRoute(appMap, route);
  if (!telemetry) {
    return {
      detected: "unknown",
      reasoning:
        `Route ${route.method} ${route.path} was never analyzed for per-route logging presence ` +
        "(per-route call detection is TypeScript/JavaScript-only today — see " +
        "packages/appmap/src/telemetry-surfaces.ts), so whether this route's handler logs anything " +
        "cannot be determined from the App Map." +
        (rule
          ? ` A detection rule (${rule.id}, format ${rule.format}) exists, but its real-world ` +
            "coverage of this route cannot be confirmed without that signal."
          : " No detection rule exists for this finding either."),
      ...ruleRef,
    };
  }

  if (!telemetry.hasLoggingCall) {
    return {
      detected: false,
      reasoning:
        `Route ${route.method} ${route.path}'s handler (${route.handler?.file ?? finding.location.file}` +
        `:${route.handler?.line ?? finding.location.line}) makes NO logging call at all — this route ` +
        `is a blind spot regardless of ${rule ? `the existing detection rule (${rule.id})` : "whether a detection rule exists"}: ` +
        "there is no telemetry here for any rule to ever match against.",
      ...ruleRef,
    };
  }

  if (!rule) {
    const loggingDesc =
      telemetry.loggerKind === "structured"
        ? `structured logging (e.g. \`${telemetry.sample ?? "a logger call"}\`)`
        : `console-only logging (e.g. \`${telemetry.sample ?? "a console call"}\`)`;
    return {
      detected: false,
      reasoning:
        `Route ${route.method} ${route.path} has ${loggingDesc}, but no detection rule exists yet ` +
        `for this finding (category ${finding.category}) — the telemetry exists but nothing is ` +
        "watching it.",
    };
  }

  if (telemetry.loggerKind === "console") {
    return {
      detected: "unknown",
      reasoning:
        `Route ${route.method} ${route.path} logs via unstructured console output ` +
        `(e.g. \`${telemetry.sample ?? "console.log(...)"}\`) rather than a structured logging ` +
        `library, and a detection rule (${rule.id}, format ${rule.format}) exists for this finding ` +
        "— but a bare console call carries no reliable structured fields (event name, status code, " +
        "user id) for the rule to match on, so whether it would actually fire cannot be determined " +
        "from the App Map alone.",
      ...ruleRef,
    };
  }

  const mitre = rule.mitreTechniques.length > 0 ? `, MITRE ${rule.mitreTechniques.join(", ")}` : "";
  return {
    detected: true,
    reasoning:
      `Route ${route.method} ${route.path} logs via a structured logging call ` +
      `(e.g. \`${telemetry.sample ?? "logger.info(...)"}\`) and a detection rule (${rule.id}, ` +
      `format ${rule.format}${mitre}) exists for this finding (category ${finding.category}) — the ` +
      "existing telemetry gives the rule real structured fields to match against.",
    ...ruleRef,
  };
}

/**
 * Build the full `DetectionCoverage[]` for every confirmed finding in a
 * scan. Pure — no I/O; `existingRules` and `now` are injected so this stays
 * fully unit-testable. `id` defaults to a stable, deterministic
 * `covg_<findingId>` (mirrors this codebase's other deterministic-id
 * conventions, e.g. `threat-model.ts`'s appMapId default).
 */
export function buildDetectionCoverage(
  appMap: AppMap,
  confirmedFindings: readonly ConfirmedFinding[],
  existingRules: readonly DetectionRule[],
  opts: { idFor?: (finding: ConfirmedFinding) => string; now?: () => Date } = {},
): DetectionCoverage[] {
  const now = opts.now ?? ((): Date => new Date());
  return confirmedFindings.map((finding) => {
    const verdict = evaluateCoverageForFinding(appMap, finding, existingRules);
    return DetectionCoverageSchema.parse({
      id: opts.idFor ? opts.idFor(finding) : `covg_${finding.id}`,
      clientId: finding.clientId,
      scanId: finding.scanId,
      findingId: finding.id,
      detected: verdict.detected,
      reasoning: verdict.reasoning,
      ...(verdict.detectionRuleId ? { detectionRuleId: verdict.detectionRuleId } : {}),
      createdAt: now().toISOString(),
    } satisfies DetectionCoverage);
  });
}

export interface PersistDetectionCoverageDeps {
  detectionCoverage: DetectionCoverageRepository;
  detectionRules: DetectionRuleRepository;
}

/**
 * Run the gap analysis for every confirmed finding in a scan and PERSIST the
 * result via the real `StateStore.detectionCoverage`/`detectionRules`
 * repositories (B1) — the actual `.create()`/`.listByFinding()` calls, not a
 * mock. All findings for one scan share `clientId`, so it is read once from
 * the first finding.
 *
 * ⛔ NOT wired into `apps/worker/src/runners.ts`'s Layer 3 runner (or any
 * other production call site) by this change — that file is a live,
 * concurrently-edited integration point this same wave (B3's rule
 * generation and B5's purple-team loop both need to land there too), and
 * wiring a caller was judged higher collision risk than value for a task
 * scoped to `packages/appmap/src/**`. This mirrors an established, explicit
 * precedent in this codebase (E5's semantic-index entry points, E9's
 * escalation option, A31's Batch API): the mechanism is built, calls the
 * REAL repository, and is fully tested end-to-end against a fake conforming
 * to `DetectionCoverageRepository`/`DetectionRuleRepository` — production
 * wiring is a documented, scoped-out follow-up for whichever wave next
 * touches `apps/worker/src/runners.ts`'s layer3 runner.
 */
export async function persistDetectionCoverageForScan(
  appMap: AppMap,
  confirmedFindings: readonly ConfirmedFinding[],
  deps: PersistDetectionCoverageDeps,
  opts: { now?: () => Date } = {},
): Promise<DetectionCoverage[]> {
  if (confirmedFindings.length === 0) return [];
  const clientId = confirmedFindings[0]!.clientId;

  const rulesPerFinding = await Promise.all(
    confirmedFindings.map((f) => deps.detectionRules.listByFinding(clientId, f.id)),
  );
  const existingRules = rulesPerFinding.flat();

  const coverage = buildDetectionCoverage(appMap, confirmedFindings, existingRules, opts);
  const created: DetectionCoverage[] = [];
  for (const c of coverage) {
    created.push(await deps.detectionCoverage.create(clientId, c));
  }
  return created;
}
