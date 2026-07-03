import * as React from "react";
import type { AppMap, AuthState } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Badge } from "./ui/badge.js";
import { StatusChip } from "./chips.js";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import type { Tone } from "../lib/format.js";

const AUTH_LABEL: Record<AuthState, string> = {
  public: "Public",
  authenticated: "Authenticated",
  role_gated: "Role-gated",
  unknown: "Unknown",
};

const AUTH_TONE: Record<AuthState, Tone> = {
  public: "danger",
  authenticated: "info",
  role_gated: "success",
  unknown: "neutral",
};

/**
 * App Map summary (§7 L0, §9). The structural model of the target that Layer 2
 * correlates findings against: languages/frameworks, registered routes with auth
 * state, data stores/ORM models, and the taint source → sink surface.
 */
export function AppMapSummary({ appMap }: { appMap: AppMap }) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>App Map</CardTitle>
          {appMap.stale ? (
            <StatusChip tone="warning">Stale — rebuild on next scan</StatusChip>
          ) : (
            <StatusChip tone="success">Fresh</StatusChip>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Metric label="Routes" value={appMap.routes.length} />
            <Metric label="Taint sinks" value={appMap.taintSinks.length} />
            <Metric label="ORM models" value={appMap.ormModels.length} />
            <Metric label="Data stores" value={appMap.dataStores.length} />
          </div>

          <div className="flex flex-wrap gap-1.5">
            {appMap.languages.map((l) => (
              <Badge key={l} className="border-border bg-secondary text-[11px]">
                {l}
              </Badge>
            ))}
            {appMap.frameworks.map((f) => (
              <Badge key={f} className="border-sky-500/30 bg-sky-500/10 text-[11px] text-sky-300">
                {f}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Registered routes</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Route</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Auth state</TableHead>
                <TableHead>Handler</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {appMap.routes.map((route, i) => (
                <TableRow key={route.id ?? `${route.method}-${route.path}-${i}`}>
                  <TableCell className="font-mono text-xs">{route.path}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {route.method}
                  </TableCell>
                  <TableCell>
                    <StatusChip tone={AUTH_TONE[route.authState]}>
                      {AUTH_LABEL[route.authState]}
                    </StatusChip>
                    {route.authGate ? (
                      <span className="ml-1 font-mono text-[11px] text-muted-foreground">
                        {route.authGate}
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-muted-foreground">
                    {route.handler ? `${route.handler.file}:${route.handler.line}` : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Taint surface</CardTitle>
          <p className="text-sm text-muted-foreground">
            Untrusted input ({appMap.taintSources.length} source
            {appMap.taintSources.length === 1 ? "" : "s"}) that can reach {appMap.taintSinks.length}{" "}
            dangerous sink
            {appMap.taintSinks.length === 1 ? "" : "s"}.
          </p>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <SurfaceList
            title="Sources"
            items={appMap.taintSources.map((s) => ({
              kind: s.kind,
              location: `${s.location.file}:${s.location.line}`,
              description: s.description,
            }))}
          />
          <SurfaceList
            title="Sinks"
            items={appMap.taintSinks.map((s) => ({
              kind: s.kind,
              location: `${s.location.file}:${s.location.line}`,
              description: s.description,
            }))}
          />
        </CardContent>
      </Card>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SurfaceList({
  title,
  items,
}: {
  title: string;
  items: { kind: string; location: string; description?: string }[];
}) {
  return (
    <div>
      <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {title}
      </p>
      <ul className="space-y-2">
        {items.map((item, i) => (
          <li key={i} className="rounded-md border border-border bg-background/50 p-2.5 text-xs">
            <div className="flex items-center justify-between gap-2">
              <Badge className="border-border bg-secondary font-mono text-[11px]">
                {item.kind}
              </Badge>
              <code className="font-mono text-[11px] text-muted-foreground">{item.location}</code>
            </div>
            {item.description ? (
              <p className="mt-1 text-muted-foreground">{item.description}</p>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
