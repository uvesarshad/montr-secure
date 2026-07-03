"use client";

import * as React from "react";
import type { RedTeamCategory, RedTeamScenario, RedTeamStep } from "@montr/contracts";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card.js";
import { Button } from "../../components/ui/button.js";
import { Badge } from "../../components/ui/badge.js";
import { EmptyState } from "../../components/ui/empty-state.js";
import { LoadingCards, ErrorState } from "../../components/states.js";
import {
  TargetIcon,
  ShieldAlertIcon,
  AlertTriangleIcon,
  CheckIcon,
  XIcon,
  RadarIcon,
} from "../../components/icons.js";
import { canRunRedTeam } from "../../lib/rbac.js";
import {
  useScenarios,
  useCreateScenario,
  useUpdateScenario,
  useDeleteScenario,
  useRunScenario,
  ScenarioApiError,
  type ScenarioDraft,
  type ScenarioRun,
} from "./hooks.js";

/**
 * Phase-4 (Wave 5) — red-team scenario library (PRD §16). Reusable, versioned
 * DAST/exploit scenarios, per-client isolated (steps encrypted at rest).
 *
 * ⛔ SAFETY (§11): scenarios are allowlist-gated (`targetAllowlistRef`), disabled
 *    by default, and RUNNING one is approver-authorized live DAST — routed via the
 *    egress guard with the kill switch + blast-radius caps in force. Production is
 *    blocked by policy. Every guardrail is re-enforced server-side.
 */

const CATEGORIES: RedTeamCategory[] = [
  "access_control",
  "injection",
  "authentication",
  "ssrf",
  "xss",
  "business_logic",
  "recon",
  "other",
];
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/** Parse a steps textarea (one step per line: `[METHOD] /path description`). */
function parseSteps(text: string): RedTeamStep[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line, i) => {
      const tokens = line.split(/\s+/);
      let method: string | undefined;
      let path: string;
      let rest: string[];
      if (tokens[0] && METHODS.has(tokens[0].toUpperCase())) {
        method = tokens[0].toUpperCase();
        path = tokens[1] ?? "/";
        rest = tokens.slice(2);
      } else {
        path = tokens[0] ?? "/";
        rest = tokens.slice(1);
      }
      const action = rest.join(" ") || `${method ?? "GET"} ${path}`;
      return {
        order: i,
        action,
        ...(method ? { method: method as NonNullable<RedTeamStep["method"]> } : {}),
        path,
      };
    });
}

function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host;
  } catch {
    return url;
  }
}

export default function RedTeamScenariosPage() {
  const user = useCurrentUser();
  const canRun = canRunRedTeam(user.role);
  const canAuthor = user.role !== "viewer";
  const { data: scenarios, isLoading, isError, error } = useScenarios();

  return (
    <div>
      <PageHeader
        title="Red-Team Scenarios"
        description="Reusable, versioned exploit scenarios bound to allowlisted staging targets. Approver-authorized; production is blocked and a kill switch halts probing instantly (§11)."
      />

      <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-100">
        <AlertTriangleIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
        <span>
          A scenario only parameterizes the gated live-DAST engine — it adds no new egress path.
          Every run re-enforces the allowlist, blocks production, honors the kill switch and
          rate/blast-radius caps, and routes through the egress guard. Runs are approver-only and
          audited.
        </span>
      </div>

      {!canRun ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">
          <ShieldAlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <span>
            Running a red-team scenario is approver-only, exactly like live-DAST authorization (§10,
            §11).
          </span>
        </div>
      ) : null}

      {canAuthor ? <ScenarioForm /> : null}

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TargetIcon className="h-4 w-4" /> Scenario library
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingCards count={2} />
          ) : isError ? (
            <ErrorState error={error} />
          ) : !scenarios || scenarios.length === 0 ? (
            <EmptyState
              icon={<TargetIcon className="h-6 w-6" />}
              title="No red-team scenarios yet"
              description="Author an allowlist-gated scenario; enable it, then run it against an authorized staging target under the same guardrails as live DAST."
            />
          ) : (
            <div className="space-y-3">
              {scenarios.map((scn) => (
                <ScenarioRow key={scn.id} scenario={scn} canRun={canRun} canAuthor={canAuthor} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ScenarioForm() {
  const create = useCreateScenario();
  const [name, setName] = React.useState("");
  const [category, setCategory] = React.useState<RedTeamCategory>("injection");
  const [target, setTarget] = React.useState("");
  const [stepsText, setStepsText] = React.useState("");

  const steps = parseSteps(stepsText);
  const draft: ScenarioDraft = {
    name: name.trim(),
    category,
    targetAllowlistRef: target.trim(),
    steps,
  };
  const valid = draft.name.length > 0 && draft.targetAllowlistRef.length > 0;
  const err = create.error instanceof ScenarioApiError ? create.error : undefined;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Author a scenario (created disabled)</CardTitle>
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
            <label className="flex-1 space-y-1">
              <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Name
              </span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Login SQLi probe"
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
            </label>
            <label className="space-y-1">
              <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Category
              </span>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as RedTeamCategory)}
                className="block rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {CATEGORIES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="block space-y-1">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Allowlisted staging target
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://staging.example.internal"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            <span className="text-xs text-muted-foreground">
              Must be on the DAST allowlist; production is blocked by policy. Steps use paths
              relative to this target.
            </span>
          </label>

          <label className="block space-y-1">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Steps — one per line: <code className="font-mono">[METHOD] /path description</code>
            </span>
            <textarea
              value={stepsText}
              onChange={(e) => setStepsText(e.target.value)}
              rows={4}
              placeholder={
                "GET /api/users?q=baseline benign baseline\nGET /api/users?q=' OR '1'='1 boolean SQLi payload"
              }
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
          </label>

          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">{steps.length} step(s) parsed.</span>
            <Button type="submit" size="sm" disabled={!valid || create.isPending}>
              {create.isPending ? "Saving…" : "Add scenario"}
            </Button>
          </div>

          {err ? (
            <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
              <p className="font-medium">{err.message}</p>
              {err.details?.errors?.length ? (
                <ul className="mt-1 list-disc space-y-0.5 pl-4">
                  {err.details.errors.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          {create.isSuccess ? (
            <p className="text-xs text-emerald-300">
              Saved as a disabled scenario. Enable it, then an approver can run it.
            </p>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
}

function ScenarioRow({
  scenario,
  canRun,
  canAuthor,
}: {
  scenario: RedTeamScenario;
  canRun: boolean;
  canAuthor: boolean;
}) {
  const update = useUpdateScenario();
  const del = useDeleteScenario();
  const run = useRunScenario();

  const draftOf = (enabled: boolean): ScenarioDraft => ({
    name: scenario.name,
    category: scenario.category,
    targetAllowlistRef: scenario.targetAllowlistRef,
    steps: scenario.steps,
    enabled,
  });

  const runErr = run.error instanceof ScenarioApiError ? run.error : undefined;

  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="space-y-1">
          <p className="font-medium">{scenario.name}</p>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge className="border-border text-muted-foreground">{scenario.category}</Badge>
            <span>v{scenario.version}</span>
            <span>
              target <code className="font-mono">{hostOf(scenario.targetAllowlistRef)}</code>
            </span>
            <span>{scenario.steps.length} step(s)</span>
            {scenario.enabled ? (
              <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-200">
                <CheckIcon className="h-3 w-3" /> Enabled
              </Badge>
            ) : (
              <Badge className="border-border text-muted-foreground">
                <XIcon className="h-3 w-3" /> Disabled
              </Badge>
            )}
          </div>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          {canAuthor ? (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  update.mutate({ id: scenario.id, draft: draftOf(!scenario.enabled) })
                }
                disabled={update.isPending}
              >
                {scenario.enabled ? "Disable" : "Enable"}
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={() => del.mutate(scenario.id)}
                disabled={del.isPending}
              >
                Delete
              </Button>
            </>
          ) : null}
          {canRun ? (
            <Button
              size="sm"
              onClick={() => run.mutate(scenario.id)}
              disabled={!scenario.enabled || run.isPending}
              title={
                scenario.enabled
                  ? "Run against the allowlisted target"
                  : "Enable the scenario first"
              }
            >
              <RadarIcon className="h-3.5 w-3.5" /> {run.isPending ? "Authorizing…" : "Run"}
            </Button>
          ) : null}
        </div>
      </div>

      {runErr ? (
        <div className="mt-2 flex items-start gap-2 rounded-md border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-200">
          <ShieldAlertIcon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Refused ({runErr.code ?? runErr.status}): {runErr.message}
          </span>
        </div>
      ) : null}
      {run.data ? <RunOutcome run={run.data} /> : null}
    </div>
  );
}

function RunOutcome({ run }: { run: ScenarioRun }) {
  return (
    <div className="mt-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2 text-xs text-emerald-100">
      <p className="font-medium">
        Authorized against <code className="font-mono">{hostOf(run.target)}</code>.{" "}
        {run.probed
          ? `${run.requestsSent} probe(s) sent.`
          : "Gate-checked; probing executes in the worker (the console never probes)."}
        {run.blocked ? " A step was blocked by the blast-radius caps." : ""}
      </p>
      <ul className="mt-1 space-y-0.5">
        {run.steps.map((s) => (
          <li key={s.order} className={s.blocked ? "text-amber-200" : undefined}>
            <code className="font-mono">
              {s.method} {s.path}
            </code>{" "}
            —{" "}
            {s.blocked
              ? `blocked: ${s.reason ?? "guardrail"}`
              : s.probed
                ? `status ${s.status}`
                : "gate-passed"}
          </li>
        ))}
      </ul>
    </div>
  );
}
