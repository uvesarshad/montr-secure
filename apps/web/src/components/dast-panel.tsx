"use client";

import * as React from "react";
import type { Scan } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Button } from "./ui/button.js";
import { StatusChip } from "./chips.js";
import { KillSwitchButton } from "./kill-switch-button.js";
import { RadarIcon, ShieldAlertIcon, AlertTriangleIcon, CheckIcon } from "./icons.js";
import { useAuthorizeDast } from "../lib/api/hooks.js";
import { useCurrentUser } from "./role-context.js";
import { canAuthorizeDast } from "../lib/rbac.js";

/**
 * Live DAST (3b) authorization panel (§7 L3, §11). ⛔ Approver-only. Live probing
 * may only hit a client-authorized, allowlisted STAGING target — production is
 * blocked by policy — and a kill switch halts all probing instantly. Non-approvers
 * see a read-only view (RBAC-aware; the mock API also rejects them server-side).
 */
export function DastPanel({ scan }: { scan: Scan }) {
  const user = useCurrentUser();
  const authorized = Boolean(scan.scope.stagingUrl);
  const canAuthorize = canAuthorizeDast(user.role);

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <RadarIcon className="h-4 w-4" /> Live DAST authorization
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Off by default. Static proof ships on every scan; live confirmation is premium and
            heavily gated (§11).
          </p>
        </div>
        <StatusChip tone={authorized ? "success" : "neutral"}>
          {authorized ? "Authorized" : "Not authorized"}
        </StatusChip>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
          <AlertTriangleIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <span className="text-amber-100">
            Production is blocked by policy. Only an explicitly allowlisted staging target may be
            probed, under rate limits and blast-radius caps, with a kill switch always available.
          </span>
        </div>

        {authorized ? (
          <div className="flex items-start gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm">
            <CheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
            <div>
              <p className="font-medium text-emerald-100">Staging target authorized</p>
              <code className="font-mono text-xs text-emerald-200/90">{scan.scope.stagingUrl}</code>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            No staging target authorized. Static confirmation still runs by default.
          </p>
        )}

        {canAuthorize ? (
          <AuthorizeForm scanId={scan.id} current={scan.scope.stagingUrl} />
        ) : (
          <div className="flex items-start gap-2 rounded-md border border-border bg-secondary/40 p-3 text-xs text-muted-foreground">
            <ShieldAlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              Approver role required to authorize live DAST (§10, §11). Your current role is
              read-only for this action.
            </span>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
          <span className="text-xs text-muted-foreground">
            Halt all active probing for this scan immediately.
          </span>
          <KillSwitchButton scanId={scan.id} />
        </div>
      </CardContent>
    </Card>
  );
}

function AuthorizeForm({ scanId, current }: { scanId: string; current?: string }) {
  const [url, setUrl] = React.useState(current ?? "");
  const mutation = useAuthorizeDast(scanId);

  const trimmed = url.trim();
  const looksProd = /(^|\/\/)(www\.)?[^/]*\bprod(uction)?\b/i.test(trimmed);
  const isHttp = /^https?:\/\//i.test(trimmed);
  const valid = isHttp && !looksProd;

  return (
    <form
      className="space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) mutation.mutate(trimmed);
      }}
    >
      <label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Authorized staging target
      </label>
      <div className="flex flex-wrap gap-2">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://staging.example.internal"
          className="min-w-0 flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        <Button type="submit" size="sm" disabled={!valid || mutation.isPending}>
          {mutation.isPending ? "Authorizing…" : "Authorize DAST"}
        </Button>
      </div>
      {trimmed.length > 0 && !isHttp ? (
        <p className="text-xs text-amber-300">Enter a full http(s):// URL.</p>
      ) : null}
      {looksProd ? (
        <p className="text-xs text-red-300">
          This looks like a production host — production targets are blocked by policy.
        </p>
      ) : null}
      {mutation.isError ? (
        <p className="text-xs text-red-300">Authorization failed. Approver role is required.</p>
      ) : null}
      {mutation.isSuccess ? (
        <p className="text-xs text-emerald-300">Authorized. Recorded in the audit log.</p>
      ) : null}
    </form>
  );
}
