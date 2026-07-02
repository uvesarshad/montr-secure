import * as React from "react";
import type { ProofArtifact, AuthState, HttpExchange, SourceLocation } from "@montr/contracts";
import { StatusChip } from "./chips.js";
import type { Tone } from "../lib/format.js";
import { ShieldAlertIcon, AlertTriangleIcon } from "./icons.js";

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

function loc(l: SourceLocation): string {
  return `${l.file}:${l.line}`;
}

/** Renders the exploit proof — a static reachability argument or a live transcript.
 * This is the evidence a human reproduces (§12.2); both proof types are supported. */
export function ProofViewer({ proof }: { proof: ProofArtifact }) {
  if (proof.kind === "static") {
    return (
      <div className="space-y-4">
        <div className="rounded-md border border-border bg-background/60 p-3">
          <p className="text-sm leading-relaxed">{proof.argument}</p>
        </div>

        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Data-flow proof (source → sink, auth state at each hop)
          </p>
          <ol className="space-y-0">
            {proof.dataFlow.map((hop, i) => (
              <li key={i} className="relative pl-6">
                <span className="absolute left-1.5 top-1.5 h-2 w-2 rounded-full bg-primary" />
                {i < proof.dataFlow.length - 1 ? (
                  <span className="absolute left-[0.6rem] top-3 h-full w-px bg-border" />
                ) : null}
                <div className="flex flex-wrap items-center gap-2 pb-4">
                  <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">
                    {loc(hop.location)}
                  </code>
                  <StatusChip tone={AUTH_TONE[hop.authState]}>
                    {AUTH_LABEL[hop.authState]}
                  </StatusChip>
                  {hop.transform ? (
                    <span className="text-xs text-muted-foreground">{hop.transform}</span>
                  ) : null}
                  {hop.note ? (
                    <span className="text-xs text-muted-foreground">— {hop.note}</span>
                  ) : null}
                </div>
              </li>
            ))}
          </ol>
        </div>

        {proof.sanitizersBypassed.length > 0 ? (
          <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
            <AlertTriangleIcon className="mt-0.5 h-4 w-4 text-amber-300" />
            <div>
              <p className="font-medium text-amber-200">Sanitizers bypassed</p>
              <p className="text-muted-foreground">{proof.sanitizersBypassed.join(", ")}</p>
            </div>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            No sanitizer or validator interrupts the tainted path.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
        <ShieldAlertIcon className="mt-0.5 h-4 w-4 text-amber-300" />
        <div>
          <p className="font-medium text-amber-200">Live DAST transcript</p>
          <p className="text-muted-foreground">
            Captured against the allowlisted staging target{" "}
            <code className="font-mono text-xs">{proof.target}</code>. Production is blocked by
            policy.
          </p>
        </div>
      </div>
      <ol className="space-y-3">
        {proof.transcript.map((exchange, i) => (
          <ExchangeView key={i} exchange={exchange} index={i + 1} />
        ))}
      </ol>
    </div>
  );
}

function ExchangeView({ exchange, index }: { exchange: HttpExchange; index: number }) {
  const { request, response } = exchange;
  return (
    <li className="overflow-hidden rounded-md border border-border">
      <div className="flex items-center justify-between border-b border-border bg-secondary/50 px-3 py-1.5">
        <span className="text-xs font-medium text-muted-foreground">Exchange {index}</span>
        <span className="font-mono text-xs">
          {request.method} · {response.status}
        </span>
      </div>
      <div className="grid gap-0 md:grid-cols-2">
        <div className="border-b border-border p-3 md:border-b-0 md:border-r">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            Request
          </p>
          <pre className="whitespace-pre-wrap break-all font-mono text-xs">
            {request.method} {request.url}
            {request.headers ? `\n${formatHeaders(request.headers)}` : ""}
            {request.bodySnippet ? `\n\n${request.bodySnippet}` : ""}
          </pre>
        </div>
        <div className="p-3">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            Response
          </p>
          <pre className="whitespace-pre-wrap break-all font-mono text-xs">
            HTTP {response.status}
            {response.headers ? `\n${formatHeaders(response.headers)}` : ""}
            {response.bodySnippet ? `\n\n${response.bodySnippet}` : ""}
          </pre>
        </div>
      </div>
      {exchange.note ? (
        <p className="border-t border-border bg-background/60 px-3 py-2 text-xs text-muted-foreground">
          {exchange.note}
        </p>
      ) : null}
    </li>
  );
}

function formatHeaders(headers: Record<string, string>): string {
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}
