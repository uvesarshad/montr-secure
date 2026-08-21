/**
 * Phase-4 (Wave 5) — scheduled scans (PRD §16). Cron-scheduled scans per repo,
 * per-client isolated.
 *
 * ⛔ SAFETY (§11, golden rules — never weakened here): a schedule carries a hard
 *    `budgetCeiling` (USD) applied to every run (budget hard-halt, §8.4), and a
 *    scheduled run STILL honors the human gate (estimate acknowledgement + the
 *    approver fix-gate) — automation never bypasses the gate. `enabled` OFF by
 *    default; the cron expression is VALIDATED before a schedule can be enabled,
 *    and every mutation is audited (schedule.created / .updated / .deleted).
 *
 * RBAC: reads are available to any authenticated role (per-client scoped);
 * create/update/delete require operator or approver (viewers are read-only).
 *
 * The actual firing of a schedule happens in apps/worker (BullMQ repeatable jobs);
 * this route owns CRUD, cron validation, `nextRunAt` computation, enable/disable
 * and the audit trail. The cron evaluator below is intentionally dependency-free
 * (pure) so it runs at the HTTP boundary AND in offline unit tests, and evaluates
 * in **UTC** (matches the containerized worker + keeps `nextRunAt` deterministic).
 *
 * Delta-only reporting (E12): a scheduled run always executes the SAME full
 * report pipeline a manual scan does (this route does not — and should not —
 * change what a scan itself computes; ⛔ the deterministic engines and the
 * report contract are out of this change's scope). What was missing was any
 * way to see WHAT'S NEW since the previous scheduled run for the same
 * repo — every run just produced a standalone full report with nothing
 * comparing it to the last one, so a continuously-scheduled repo diluted a
 * genuinely new finding into a full undifferentiated list every time it re-ran.
 * `GET /schedules/:id/delta` below closes that gap: it finds the two most
 * recent COMPLETED (or partial — a budget hard-halt still emits a report)
 * scheduler-triggered scans for this schedule's repo (`Scan.operator ===
 * SCHEDULER_OPERATOR`, the same marker `apps/worker/src/scheduling/scan-
 * scheduler.ts`'s `scheduledScanInput` already stamps on every scheduled
 * scan — no new Scan field needed) and diffs their CONFIRMED findings by
 * (category, file, line) — see {@link computeFindingsDelta}. This is
 * deliberately NOT wired into the report contract itself (`@montr/report`,
 * `packages/contracts/src/report.ts`'s `Report` shape) to stay within this
 * task's scoped files; it is a read-only, additive VIEW over data the report
 * pipeline already persists.
 *
 * KNOWN LIMITATION: because there is no `Scan.scheduleId` field (the
 * `ScanSchedule` contract carries no back-reference to the scans it created,
 * and adding one is a contract-and-migration change out of this task's
 * scope), the match is scoped to `(clientId, repo, operator===scheduler)`
 * rather than the exact schedule id. Two schedules for the same repo in the
 * same client would be indistinguishable here — an accepted, documented
 * simplification, not a silent bug.
 */
import type { FastifyInstance } from "fastify";
import {
  ScanScheduleSchema,
  type ConfirmedFinding,
  type Scan,
  type ScanSchedule,
} from "@montr/contracts";
import { badRequest, notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { CreateScanScheduleBodySchema, EntityIdParamsSchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

/**
 * The operator id every scheduler-triggered scan is created with (MUST match
 * `apps/worker/src/scheduling/scan-scheduler.ts`'s `SCHEDULER_OPERATOR` /
 * `scheduledScanInput` — apps/api cannot import apps/worker, so this is a
 * duplicated literal, not a shared import; both sides are covered by tests).
 */
const SCHEDULER_OPERATOR = "scan-scheduler";

/** Statuses that mean "a report was actually produced" (partial = budget hard-halt, still real). */
const REPORTED_STATUSES = new Set(["completed", "partial"]);

/** Stable identity for matching a confirmed finding across two scans of the same repo. */
function findingKey(f: ConfirmedFinding): string {
  return `${f.category}::${f.location.file}::${f.location.line}`;
}

export interface ScheduleFindingsDelta {
  /** Confirmed in the current scan but not (by identity) in the previous one. */
  newFindings: ConfirmedFinding[];
  /** Count present in the previous scan but no longer in the current one. */
  resolvedCount: number;
  currentConfirmedCount: number;
  previousConfirmedCount: number;
}

/**
 * Pure delta computation (E12): confirmed findings present in `current` but
 * not matched (by category + file + line) in `previous` are "new since last
 * scan"; findings in `previous` with no match in `current` count as
 * resolved. Dependency-free and unit-testable, mirroring this file's cron
 * evaluator's own "pure core, thin HTTP wrapper" shape.
 */
export function computeFindingsDelta(
  previous: ConfirmedFinding[],
  current: ConfirmedFinding[],
): ScheduleFindingsDelta {
  const previousKeys = new Set(previous.map(findingKey));
  const currentKeys = new Set(current.map(findingKey));
  const newFindings = current.filter((f) => !previousKeys.has(findingKey(f)));
  const resolvedCount = previous.filter((f) => !currentKeys.has(findingKey(f))).length;
  return {
    newFindings,
    resolvedCount,
    currentConfirmedCount: current.length,
    previousConfirmedCount: previous.length,
  };
}

/** Scheduler-triggered, reported scans for `repo`, newest first. */
function scheduledReportedScansForRepo(scans: Scan[], repo: string): Scan[] {
  return scans
    .filter(
      (s) =>
        s.repo === repo && s.operator === SCHEDULER_OPERATOR && REPORTED_STATUSES.has(s.status),
    )
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/* --------------------------------------------------------------------------- *
 * Dependency-free cron evaluator (standard 5- or 6-field, UTC).
 *
 * Fields: [second?] minute hour day-of-month month day-of-week. Each field
 * supports `*`, `n`, `a-b`, `* /step`, `a-b/step`, `n/step`, and comma lists.
 * Month (1-12) and day-of-week (0-6, both 0 and 7 = Sunday) also accept the
 * usual 3-letter names (JAN…DEC, SUN…SAT). Quartz extensions (`L`,`W`,`#`,`?`)
 * are intentionally rejected — fail-safe toward less surprise (golden rule #4).
 * --------------------------------------------------------------------------- */

interface CronFields {
  hasSeconds: boolean;
  second: Set<number>;
  minute: Set<number>;
  hour: Set<number>;
  dom: Set<number>;
  month: Set<number>;
  dow: Set<number>;
  domRestricted: boolean;
  dowRestricted: boolean;
}

const MONTH_NAMES: Record<string, number> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};
const DOW_NAMES: Record<string, number> = {
  sun: 0,
  mon: 1,
  tue: 2,
  wed: 3,
  thu: 4,
  fri: 5,
  sat: 6,
};

function resolveNames(token: string, names?: Record<string, number>): string {
  if (!names) return token;
  const key = token.toLowerCase();
  return key in names ? String(names[key]) : token;
}

/** Parse one cron field into the concrete set of matching integers in [min,max]. */
function parseField(
  field: string,
  min: number,
  max: number,
  names?: Record<string, number>,
): Set<number> {
  const out = new Set<number>();
  const parts = field.split(",");
  for (const rawPart of parts) {
    const part = rawPart.trim();
    if (part === "") throw new Error(`empty term in "${field}"`);

    const [rangeToken, stepToken, ...rest] = part.split("/");
    if (rest.length > 0) throw new Error(`invalid step in "${part}"`);
    if (rangeToken === undefined) throw new Error(`empty term in "${field}"`);
    let step = 1;
    if (stepToken !== undefined) {
      step = Number(stepToken);
      if (!Number.isInteger(step) || step <= 0) throw new Error(`invalid step "${stepToken}"`);
    }

    let lo: number;
    let hi: number;
    if (rangeToken === "*") {
      lo = min;
      hi = max;
    } else if (rangeToken.includes("-")) {
      const [a, b, ...more] = rangeToken.split("-");
      if (more.length > 0 || a === undefined || b === undefined) {
        throw new Error(`invalid range "${rangeToken}"`);
      }
      lo = Number(resolveNames(a, names));
      hi = Number(resolveNames(b, names));
    } else {
      lo = Number(resolveNames(rangeToken, names));
      // "n/step" means n, n+step, … up to max; a bare "n" means exactly n.
      hi = stepToken !== undefined ? max : lo;
    }

    if (!Number.isInteger(lo) || !Number.isInteger(hi)) {
      throw new Error(`non-integer term "${part}"`);
    }
    if (lo < min || hi > max || lo > hi) {
      throw new Error(`term "${part}" out of range [${min}-${max}]`);
    }
    for (let v = lo; v <= hi; v += step) out.add(v);
  }
  if (out.size === 0) throw new Error(`field "${field}" matches nothing`);
  return out;
}

/** Parse a full cron expression, or throw with a human-readable reason. */
export function parseCron(expr: string): CronFields {
  const tokens = expr.trim().split(/\s+/).filter(Boolean);
  if (tokens.length !== 5 && tokens.length !== 6) {
    throw new Error(`expected 5 or 6 fields, got ${tokens.length}`);
  }
  const hasSeconds = tokens.length === 6;
  const [secTok, minTok, hourTok, domTok, monthTok, dowTok] = hasSeconds
    ? tokens
    : (["0", ...tokens] as string[]);

  // dow: accept 0-7, fold 7 -> 0 (Sunday).
  const dowRaw = parseField(dowTok as string, 0, 7, DOW_NAMES);
  const dow = new Set<number>();
  for (const v of dowRaw) dow.add(v === 7 ? 0 : v);

  return {
    hasSeconds,
    second: parseField(secTok as string, 0, 59),
    minute: parseField(minTok as string, 0, 59),
    hour: parseField(hourTok as string, 0, 23),
    dom: parseField(domTok as string, 1, 31),
    month: parseField(monthTok as string, 1, 12, MONTH_NAMES),
    dow,
    domRestricted: (domTok as string).trim() !== "*",
    dowRestricted: (dowTok as string).trim() !== "*",
  };
}

/** True iff `expr` is a syntactically valid 5/6-field cron expression. */
export function cronIsValid(expr: string): boolean {
  try {
    parseCron(expr);
    return true;
  } catch {
    return false;
  }
}

function dayMatches(d: Date, f: CronFields): boolean {
  const domOk = f.dom.has(d.getUTCDate());
  const dowOk = f.dow.has(d.getUTCDay());
  // Vixie-cron rule: when BOTH day fields are restricted a day matches if EITHER
  // does; when only one is restricted, that one governs.
  if (f.domRestricted && f.dowRestricted) return domOk || dowOk;
  if (f.domRestricted) return domOk;
  if (f.dowRestricted) return dowOk;
  return true;
}

const FIVE_YEARS_MS = 5 * 366 * 24 * 60 * 60 * 1000;

/**
 * The next UTC instant strictly after `from` that satisfies `expr`, or null if
 * none occurs within a 5-year horizon (e.g. an impossible date like Feb 30).
 * Field-based advancement keeps this cheap even for sparse schedules.
 */
export function nextCronRun(expr: string, from: Date): Date | null {
  const f = parseCron(expr);
  const t = new Date(from.getTime());
  // Start at the next whole unit boundary strictly after `from`.
  if (f.hasSeconds) {
    t.setUTCMilliseconds(0);
    t.setUTCSeconds(t.getUTCSeconds() + 1);
  } else {
    t.setUTCSeconds(0, 0);
    t.setUTCMinutes(t.getUTCMinutes() + 1);
  }

  const limit = from.getTime() + FIVE_YEARS_MS;
  while (t.getTime() <= limit) {
    if (!f.month.has(t.getUTCMonth() + 1)) {
      // Jump to the 1st of the next month at 00:00:00.
      t.setUTCMonth(t.getUTCMonth() + 1, 1);
      t.setUTCHours(0, 0, 0, 0);
      continue;
    }
    if (!dayMatches(t, f)) {
      t.setUTCDate(t.getUTCDate() + 1);
      t.setUTCHours(0, 0, 0, 0);
      continue;
    }
    if (!f.hour.has(t.getUTCHours())) {
      t.setUTCHours(t.getUTCHours() + 1, 0, 0, 0);
      continue;
    }
    if (!f.minute.has(t.getUTCMinutes())) {
      t.setUTCMinutes(t.getUTCMinutes() + 1, 0, 0);
      continue;
    }
    if (f.hasSeconds && !f.second.has(t.getUTCSeconds())) {
      t.setUTCSeconds(t.getUTCSeconds() + 1, 0);
      continue;
    }
    return t;
  }
  return null;
}

/* --------------------------------------------------------------------------- *
 * Routes
 * --------------------------------------------------------------------------- */

const SCHEDULE_TARGET_TYPE = "scan_schedule";

/**
 * Validate the cron + compute `nextRunAt`. Throws a 400 when the expression is
 * malformed, or when an ENABLED schedule's cron never fires within the horizon
 * (a schedule you can't actually run is refused — fail-safe).
 */
function computeNextRunAt(cron: string, enabled: boolean, now: Date): string | undefined {
  if (!cronIsValid(cron)) {
    throw badRequest("Invalid cron expression", { cron });
  }
  if (!enabled) return undefined; // a disabled schedule has no next run.
  const next = nextCronRun(cron, now);
  if (!next) {
    throw badRequest("Cron expression never fires within a 5-year horizon", { cron });
  }
  return next.toISOString();
}

export function registerScheduleRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  app.get(
    "/schedules",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["schedules"],
        summary: "List scan schedules",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const schedules = await store.scanSchedules.list(user.clientId);
      return { schedules };
    },
  );

  app.get(
    "/schedules/:id",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["schedules"],
        summary: "Get a scan schedule",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const schedule = await store.scanSchedules.get(user.clientId, id);
      if (!schedule) throw notFound("Scan schedule not found");
      return { schedule };
    },
  );

  // E12 — delta-only reporting: what's new since the previous scheduled run
  // for this schedule's repo. Read-only; any authenticated role, same as the
  // other schedule GETs. See the module doc comment for the matching + scope
  // rationale (operator===scan-scheduler, no Scan.scheduleId field yet).
  app.get(
    "/schedules/:id/delta",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["schedules"],
        summary: "New/resolved confirmed findings since this schedule's previous run",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const schedule = await store.scanSchedules.get(user.clientId, id);
      if (!schedule) throw notFound("Scan schedule not found");

      const allScans = await store.scans.list(user.clientId);
      const [current, previous] = scheduledReportedScansForRepo(allScans, schedule.repo);

      if (!current) {
        return {
          scheduleId: schedule.id,
          repo: schedule.repo,
          currentScanId: null,
          previousScanId: null,
          newFindings: [],
          resolvedCount: 0,
          currentConfirmedCount: 0,
          previousConfirmedCount: 0,
          note: "No completed scheduled run yet for this schedule's repo.",
        };
      }

      const currentConfirmed = await store.confirmed.listByScan(user.clientId, current.id);
      if (!previous) {
        return {
          scheduleId: schedule.id,
          repo: schedule.repo,
          currentScanId: current.id,
          previousScanId: null,
          newFindings: currentConfirmed,
          resolvedCount: 0,
          currentConfirmedCount: currentConfirmed.length,
          previousConfirmedCount: 0,
          note: "Only one completed scheduled run so far — no prior baseline to diff against.",
        };
      }

      const previousConfirmed = await store.confirmed.listByScan(user.clientId, previous.id);
      const delta = computeFindingsDelta(previousConfirmed, currentConfirmed);
      return {
        scheduleId: schedule.id,
        repo: schedule.repo,
        currentScanId: current.id,
        previousScanId: previous.id,
        ...delta,
      };
    },
  );

  // ⛔ Validate cron BEFORE enable; create disabled-by-default; audit schedule.created.
  app.post(
    "/schedules",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["schedules"],
        summary: "Create a scan schedule (budget ceiling + human gate enforced)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(CreateScanScheduleBodySchema, req);

      const now = deps.clock.now();
      const nextRunAt = computeNextRunAt(body.cron, body.enabled, now);

      const schedule: ScanSchedule = ScanScheduleSchema.parse({
        id: deps.idgen("sched"),
        clientId: user.clientId,
        repo: body.repo,
        mode: body.mode,
        cron: body.cron,
        budgetCeiling: body.budgetCeiling,
        enabled: body.enabled,
        ...(nextRunAt ? { nextRunAt } : {}),
        createdBy: user.id,
        createdAt: now.toISOString(),
      });
      const created = await store.scanSchedules.create(user.clientId, schedule);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "schedule.created",
        targetType: SCHEDULE_TARGET_TYPE,
        targetId: created.id,
        summary: `Scan schedule created for ${created.repo} (${created.cron}, ${
          created.enabled ? "enabled" : "disabled"
        }); budget ceiling $${created.budgetCeiling}/run.`,
        metadata: {
          repo: created.repo,
          mode: created.mode,
          cron: created.cron,
          budgetCeiling: created.budgetCeiling,
          enabled: created.enabled,
        },
      });

      reply.status(201);
      return { schedule: created };
    },
  );

  // ⛔ Full replace. Re-validates cron before enable; audits schedule.updated
  //    (enable/disable is an update whose `enabled` flag flips).
  app.put(
    "/schedules/:id",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["schedules"],
        summary: "Update a scan schedule (enable/disable, re-validates cron)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);
      const body = parseBody(CreateScanScheduleBodySchema, req);

      const existing = await store.scanSchedules.get(user.clientId, id);
      if (!existing) throw notFound("Scan schedule not found");

      const now = deps.clock.now();
      const nextRunAt = computeNextRunAt(body.cron, body.enabled, now);

      // Preserve identity/provenance; replace the mutable fields.
      const updated: ScanSchedule = ScanScheduleSchema.parse({
        id: existing.id,
        clientId: existing.clientId,
        repo: body.repo,
        mode: body.mode,
        cron: body.cron,
        budgetCeiling: body.budgetCeiling,
        enabled: body.enabled,
        ...(nextRunAt ? { nextRunAt } : {}),
        createdBy: existing.createdBy,
        createdAt: existing.createdAt,
      });
      const saved = await store.scanSchedules.update(user.clientId, updated);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "schedule.updated",
        targetType: SCHEDULE_TARGET_TYPE,
        targetId: saved.id,
        summary: `Scan schedule updated for ${saved.repo} (${saved.cron}, ${
          saved.enabled ? "enabled" : "disabled"
        }); budget ceiling $${saved.budgetCeiling}/run.`,
        metadata: {
          repo: saved.repo,
          mode: saved.mode,
          cron: saved.cron,
          budgetCeiling: saved.budgetCeiling,
          enabled: saved.enabled,
          enabledChanged: existing.enabled !== saved.enabled,
        },
      });

      return { schedule: saved };
    },
  );

  app.delete(
    "/schedules/:id",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["schedules"],
        summary: "Delete a scan schedule",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(EntityIdParamsSchema, req);

      const existing = await store.scanSchedules.get(user.clientId, id);
      if (!existing) throw notFound("Scan schedule not found");

      await store.scanSchedules.delete(user.clientId, id);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "schedule.deleted",
        targetType: SCHEDULE_TARGET_TYPE,
        targetId: existing.id,
        summary: `Scan schedule deleted for ${existing.repo} (${existing.cron}).`,
        metadata: { repo: existing.repo, cron: existing.cron },
      });

      return { id: existing.id, deleted: true };
    },
  );
}
