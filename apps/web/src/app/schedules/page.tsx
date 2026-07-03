"use client";

import * as React from "react";
import type { ScanMode, ScanSchedule } from "@montr/contracts";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card.js";
import { Button } from "../../components/ui/button.js";
import { Badge } from "../../components/ui/badge.js";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "../../components/ui/table.js";
import { EmptyState } from "../../components/ui/empty-state.js";
import { LoadingCards, ErrorState } from "../../components/states.js";
import {
  CalendarIcon,
  ClockIcon,
  DollarIcon,
  ShieldAlertIcon,
  CheckIcon,
  XIcon,
  AlertTriangleIcon,
} from "../../components/icons.js";
import { canManageSchedules } from "../../lib/rbac.js";
import {
  useSchedules,
  useCreateSchedule,
  useUpdateSchedule,
  useDeleteSchedule,
  ScheduleApiError,
  type ScheduleDraft,
} from "./hooks.js";

/**
 * Phase-4 (Wave 5) — scheduled scans (PRD §16). Cron-scheduled scans per repo,
 * per-client isolated.
 *
 * ⛔ SAFETY (§11, golden rules — surfaced here, ENFORCED server-side): every
 *    schedule carries a HARD per-run `budgetCeiling` (budget hard-halt, §8.4), the
 *    cron is validated before a schedule can be enabled, and a scheduled run STILL
 *    honors the human gate (estimate acknowledgement + approver fix-gate). Auto-fix
 *    stays PR-only + approver-gated. `enabled` is OFF by default. Managing
 *    schedules is operator/approver only; viewers are read-only.
 */

const MODES: ScanMode[] = ["full", "diff"];

/** Format an ISO instant as compact UTC (the scheduler evaluates cron in UTC). */
function fmtUtc(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export default function ScanSchedulesPage() {
  const user = useCurrentUser();
  const canManage = canManageSchedules(user.role);
  const { data: schedules, isLoading, isError, error } = useSchedules();

  return (
    <div>
      <PageHeader
        title="Scan Schedules"
        description="Cron-schedule recurring scans per repo. Each run enforces a hard per-run budget ceiling and still requires the human gate (cost-estimate acknowledgement + approver fix-gate) — automation never bypasses it."
      />

      {!canManage ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">
          <ShieldAlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <span>Managing schedules is operator/approver only. You have read-only access.</span>
        </div>
      ) : null}

      {canManage ? <ScheduleForm /> : null}

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CalendarIcon className="h-4 w-4" /> Scan schedules
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingCards count={2} />
          ) : isError ? (
            <ErrorState error={error} />
          ) : !schedules || schedules.length === 0 ? (
            <EmptyState
              icon={<CalendarIcon className="h-6 w-6" />}
              title="No scheduled scans yet"
              description="Define a cron cadence and a per-run budget ceiling. Scheduled runs still surface a cost estimate and honor the approver gate — they never auto-approve."
            />
          ) : (
            <SchedulesTable schedules={schedules} canManage={canManage} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

const FIELD_INPUT =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const FIELD_LABEL = "text-xs font-medium uppercase tracking-wide text-muted-foreground";

function ScheduleForm() {
  const create = useCreateSchedule();
  const [repo, setRepo] = React.useState("");
  const [cron, setCron] = React.useState("0 3 * * 1");
  const [mode, setMode] = React.useState<ScanMode>("full");
  const [budget, setBudget] = React.useState("10");
  const [enabled, setEnabled] = React.useState(false);

  const budgetNum = Number(budget);
  const budgetValid = Number.isFinite(budgetNum) && budgetNum > 0;
  const valid = repo.trim().length > 0 && cron.trim().length > 0 && budgetValid;

  const draft: ScheduleDraft = {
    repo: repo.trim(),
    mode,
    cron: cron.trim(),
    budgetCeiling: budgetNum,
    enabled,
  };

  const err = create.error instanceof ScheduleApiError ? create.error : undefined;
  const created = create.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Schedule a recurring scan</CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (valid) create.mutate(draft);
          }}
        >
          <div className="flex flex-wrap gap-3">
            <label className="flex-1 space-y-1" style={{ minWidth: "12rem" }}>
              <span className={FIELD_LABEL}>Repository</span>
              <input
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                placeholder="acme/app"
                className={FIELD_INPUT}
              />
            </label>
            <label className="space-y-1" style={{ minWidth: "10rem" }}>
              <span className={FIELD_LABEL}>Cron (UTC)</span>
              <input
                value={cron}
                onChange={(e) => setCron(e.target.value)}
                placeholder="0 3 * * 1"
                className={`${FIELD_INPUT} font-mono`}
              />
            </label>
            <label className="space-y-1">
              <span className={FIELD_LABEL}>Mode</span>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as ScanMode)}
                className="block rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {MODES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1">
              <span className={FIELD_LABEL}>Budget / run (USD)</span>
              <input
                type="number"
                min="0"
                step="0.5"
                value={budget}
                onChange={(e) => setBudget(e.target.value)}
                className="block w-32 rounded-md border border-input bg-background px-3 py-2 text-sm"
              />
            </label>
          </div>

          <p className="text-xs text-muted-foreground">
            Cron is 5- or 6-field, evaluated in UTC and validated before the schedule can be
            enabled.{" "}
            <span className="text-foreground/80">
              The budget ceiling is a hard per-run halt; each run still parks at the cost-estimate
              gate and keeps the approver fix-gate.
            </span>
          </p>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              <span>Enable now (cron must validate; runs still honor the human gate)</span>
            </label>
            <Button type="submit" size="sm" disabled={!valid || create.isPending}>
              {create.isPending ? "Saving…" : "Create schedule"}
            </Button>
          </div>

          {err ? (
            <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
              <p className="font-medium">{err.message}</p>
              {typeof err.details?.cron === "string" ? (
                <p className="mt-1 font-mono text-red-200/80">{err.details.cron}</p>
              ) : null}
            </div>
          ) : null}
          {created ? (
            <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">
              <p className="font-medium">
                Scheduled “{created.repo}” ({created.cron}).{" "}
                {created.enabled
                  ? `Next run ${fmtUtc(created.nextRunAt)}.`
                  : "Stored disabled — enable it to start the cadence."}
              </p>
            </div>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
}

function SchedulesTable({
  schedules,
  canManage,
}: {
  schedules: ScanSchedule[];
  canManage: boolean;
}) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Repository</TableHead>
            <TableHead>Cadence</TableHead>
            <TableHead>Mode</TableHead>
            <TableHead>Budget / run</TableHead>
            <TableHead>Next run</TableHead>
            <TableHead>Status</TableHead>
            {canManage ? <TableHead className="text-right">Actions</TableHead> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {schedules.map((schedule) => (
            <ScheduleRow key={schedule.id} schedule={schedule} canManage={canManage} />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function ScheduleRow({ schedule, canManage }: { schedule: ScanSchedule; canManage: boolean }) {
  const update = useUpdateSchedule();
  const del = useDeleteSchedule();

  const toggle = () =>
    update.mutate({
      id: schedule.id,
      draft: {
        repo: schedule.repo,
        mode: schedule.mode,
        cron: schedule.cron,
        budgetCeiling: schedule.budgetCeiling,
        enabled: !schedule.enabled,
      },
    });

  const toggleFailed = update.error instanceof ScheduleApiError && update.error.status === 400;

  return (
    <TableRow>
      <TableCell className="font-medium">{schedule.repo}</TableCell>
      <TableCell className="font-mono text-xs text-muted-foreground">{schedule.cron}</TableCell>
      <TableCell className="text-muted-foreground">{schedule.mode}</TableCell>
      <TableCell className="text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <DollarIcon className="h-3 w-3" />
          {schedule.budgetCeiling.toFixed(2)}
        </span>
      </TableCell>
      <TableCell className="text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <ClockIcon className="h-3 w-3" />
          {fmtUtc(schedule.nextRunAt)}
        </span>
      </TableCell>
      <TableCell>
        {schedule.enabled ? (
          <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-200">
            <CheckIcon className="h-3 w-3" /> Enabled
          </Badge>
        ) : (
          <Badge className="border-border text-muted-foreground">
            <XIcon className="h-3 w-3" /> Disabled
          </Badge>
        )}
      </TableCell>
      {canManage ? (
        <TableCell className="text-right">
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="outline" onClick={toggle} disabled={update.isPending}>
              {schedule.enabled ? "Disable" : "Enable"}
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => del.mutate(schedule.id)}
              disabled={del.isPending}
            >
              Delete
            </Button>
          </div>
          {toggleFailed ? (
            <p className="mt-1 flex items-center justify-end gap-1 text-xs text-amber-300">
              <AlertTriangleIcon className="h-3 w-3" /> Cannot enable: cron failed validation.
            </p>
          ) : null}
        </TableCell>
      ) : null}
    </TableRow>
  );
}
