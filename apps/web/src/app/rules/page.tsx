"use client";

import * as React from "react";
import type { CustomRule, Language, RuleEngine } from "@montr/contracts";
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
  RuleIcon,
  ShieldAlertIcon,
  CheckIcon,
  XIcon,
  AlertTriangleIcon,
} from "../../components/icons.js";
import { canAuthorRules } from "../../lib/rbac.js";
import {
  useCustomRules,
  useCreateRule,
  useUpdateRule,
  useDeleteRule,
  RuleApiError,
  type RuleDraft,
} from "./hooks.js";

/**
 * Phase-4 (Wave 5) — custom rule authoring (PRD §16). Client Semgrep / secret
 * detectors, validated + versioned, per-client isolated.
 *
 * ⛔ Golden rule: custom rules are VALIDATED before use. Authoring is
 *    operator/approver only; viewers are read-only (RBAC + server-enforced).
 */

const ENGINES: RuleEngine[] = ["semgrep", "secret"];
const LANGUAGES: Language[] = ["typescript", "javascript", "python", "java"];

const SEMGREP_EXAMPLE = `rules:
  - id: no-eval
    languages: [typescript]
    severity: ERROR
    message: Avoid eval()
    pattern: eval(...)`;

export default function CustomRulesPage() {
  const user = useCurrentUser();
  const canAuthor = canAuthorRules(user.role);
  const { data: rules, isLoading, isError, error } = useCustomRules();

  return (
    <div>
      <PageHeader
        title="Custom Rules"
        description="Author client-specific Semgrep and secret-detection rules. Every rule is validated before it can be enabled, versioned on edit, and loaded alongside the curated rulesets."
      />

      {!canAuthor ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">
          <ShieldAlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <span>Rule authoring is operator/approver only. You have read-only access.</span>
        </div>
      ) : null}

      {canAuthor ? <RuleForm /> : null}

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RuleIcon className="h-4 w-4" /> Custom rules
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingCards count={2} />
          ) : isError ? (
            <ErrorState error={error} />
          ) : !rules || rules.length === 0 ? (
            <EmptyState
              icon={<RuleIcon className="h-6 w-6" />}
              title="No custom rules yet"
              description="Add a Semgrep rule or secret detector; it is validated, versioned, and stored per client before it feeds discovery."
            />
          ) : (
            <RulesTable rules={rules} canAuthor={canAuthor} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function RuleForm() {
  const create = useCreateRule();
  const [name, setName] = React.useState("");
  const [engine, setEngine] = React.useState<RuleEngine>("secret");
  const [language, setLanguage] = React.useState<Language>("typescript");
  const [body, setBody] = React.useState("");
  const [enabled, setEnabled] = React.useState(false);

  const draft: RuleDraft = { name: name.trim(), engine, language, body, enabled };
  const valid = draft.name.length > 0 && body.trim().length > 0;

  const err = create.error instanceof RuleApiError ? create.error : undefined;
  const result = create.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Author a rule</CardTitle>
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
                placeholder="No eval() in handlers"
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
            </label>
            <label className="space-y-1">
              <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Engine
              </span>
              <select
                value={engine}
                onChange={(e) => setEngine(e.target.value as RuleEngine)}
                className="block rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {ENGINES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Language
              </span>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value as Language)}
                className="block rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {LANGUAGES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="block space-y-1">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Rule source {engine === "semgrep" ? "(Semgrep YAML)" : "(regex or JSON detector)"}
            </span>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={engine === "semgrep" ? 7 : 3}
              placeholder={engine === "semgrep" ? SEMGREP_EXAMPLE : "sk_live_[0-9a-zA-Z]{16,}"}
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
          </label>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              <span>Enable now (requires the rule to pass validation)</span>
            </label>
            <Button type="submit" size="sm" disabled={!valid || create.isPending}>
              {create.isPending ? "Validating…" : "Add rule"}
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
          {result ? (
            <div
              className={
                result.validation.valid
                  ? "rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200"
                  : "rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-100"
              }
            >
              <p className="font-medium">
                Saved “{result.rule.name}” (v{result.rule.version}).{" "}
                {result.validation.valid
                  ? "Validation passed."
                  : "Stored as a disabled draft — validation failed."}
              </p>
              {result.validation.errors.length ? (
                <ul className="mt-1 list-disc space-y-0.5 pl-4">
                  {result.validation.errors.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              ) : null}
              {result.validation.warnings.length ? (
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-amber-200/80">
                  {result.validation.warnings.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
}

function RulesTable({ rules, canAuthor }: { rules: CustomRule[]; canAuthor: boolean }) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Engine</TableHead>
            <TableHead>Language</TableHead>
            <TableHead>Version</TableHead>
            <TableHead>Status</TableHead>
            {canAuthor ? <TableHead className="text-right">Actions</TableHead> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((rule) => (
            <RuleRow key={rule.id} rule={rule} canAuthor={canAuthor} />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function RuleRow({ rule, canAuthor }: { rule: CustomRule; canAuthor: boolean }) {
  const update = useUpdateRule();
  const del = useDeleteRule();

  const toggle = () =>
    update.mutate({
      id: rule.id,
      draft: {
        name: rule.name,
        engine: rule.engine,
        language: rule.language,
        body: rule.body,
        enabled: !rule.enabled,
      },
    });

  return (
    <TableRow>
      <TableCell className="font-medium">{rule.name}</TableCell>
      <TableCell>
        <Badge className="border-border text-muted-foreground">{rule.engine}</Badge>
      </TableCell>
      <TableCell className="text-muted-foreground">{rule.language}</TableCell>
      <TableCell className="text-muted-foreground">v{rule.version}</TableCell>
      <TableCell>
        {rule.enabled ? (
          <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-200">
            <CheckIcon className="h-3 w-3" /> Enabled
          </Badge>
        ) : (
          <Badge className="border-border text-muted-foreground">
            <XIcon className="h-3 w-3" /> Disabled
          </Badge>
        )}
      </TableCell>
      {canAuthor ? (
        <TableCell className="text-right">
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="outline" onClick={toggle} disabled={update.isPending}>
              {rule.enabled ? "Disable" : "Enable"}
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => del.mutate(rule.id)}
              disabled={del.isPending}
            >
              Delete
            </Button>
          </div>
          {update.error instanceof RuleApiError && update.error.status === 400 ? (
            <p className="mt-1 flex items-center justify-end gap-1 text-xs text-amber-300">
              <AlertTriangleIcon className="h-3 w-3" /> Cannot enable: rule failed validation.
            </p>
          ) : null}
        </TableCell>
      ) : null}
    </TableRow>
  );
}
