"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { RedTeamCategory, RedTeamScenario, RedTeamStep } from "@montr/contracts";
import { API_BASE } from "../../lib/api/config.js";
import { csrfHeaders, mockActorHeaders } from "../../lib/api/auth-headers.js";
import { useActor } from "../../components/role-context.js";

/**
 * Data hooks for the red-team scenario library page. Self-contained (co-located
 * with the page) so the feature does not edit the shared api client/mocks. ⛔ The
 * server enforces every guardrail on `/scenarios/:id/run` (approver-only,
 * allowlist-gated, production blocked, kill switch, egress guard).
 */

const base = `${API_BASE}/api/v1/scenarios`;
const SCN_KEY = ["red-team-scenarios"] as const;

export interface ScenarioDraft {
  name: string;
  category: RedTeamCategory;
  targetAllowlistRef: string;
  steps: RedTeamStep[];
  enabled?: boolean;
}

/** Structural mirror of @montr/confirm's ScenarioRunResult (kept local — web has no confirm dep). */
export interface ScenarioRun {
  scenarioId: string;
  target: string;
  authorized: boolean;
  probed: boolean;
  blocked: boolean;
  requestsSent: number;
  mutatingSent: number;
  steps: {
    order: number;
    action: string;
    method: string;
    path: string;
    url: string;
    probed: boolean;
    status?: number;
    blocked?: boolean;
    reason?: string;
  }[];
}

/**
 * A1 (2026-09-12) — real worker-side execution status. `run` above is still
 * only ever a gate-only PREVIEW (never probes from the API process); this is
 * the honest signal for whether apps/worker will actually probe the target.
 */
export interface ScenarioLiveExecution {
  enqueued: boolean;
  jobId?: string;
}

export interface ScenarioRunResponse {
  run: ScenarioRun;
  liveExecution: ScenarioLiveExecution;
}

export class ScenarioApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly details?: { errors?: string[]; warnings?: string[] };
  constructor(
    status: number,
    message: string,
    code?: string,
    details?: ScenarioApiError["details"],
  ) {
    super(message);
    this.name = "ScenarioApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      // These endpoints are real-API-only (no MSW handler) — always send the
      // session cookie regardless of mock mode.
      credentials: "include",
      headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ScenarioApiError(0, `Network error contacting ${url}`, "NETWORK");
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = (
      body as { error?: { code?: string; message?: string; details?: ScenarioApiError["details"] } }
    )?.error;
    throw new ScenarioApiError(res.status, env?.message ?? res.statusText, env?.code, env?.details);
  }
  return body as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export function useScenarios() {
  return useQuery({
    queryKey: SCN_KEY,
    queryFn: () => req<{ scenarios: RedTeamScenario[] }>(base).then((r) => r.scenarios),
  });
}

export function useCreateScenario() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (draft: ScenarioDraft) =>
      req<{ scenario: RedTeamScenario }>(base, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...mockActorHeaders(actor),
          ...csrfHeaders(),
        },
        body: JSON.stringify(draft),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCN_KEY }),
  });
}

export function useUpdateScenario() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; draft: ScenarioDraft }) =>
      req<{ scenario: RedTeamScenario }>(`${base}/${vars.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          ...mockActorHeaders(actor),
          ...csrfHeaders(),
        },
        body: JSON.stringify(vars.draft),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCN_KEY }),
  });
}

export function useDeleteScenario() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      req<{ ok: boolean; id: string }>(`${base}/${id}`, {
        method: "DELETE",
        headers: { ...mockActorHeaders(actor), ...csrfHeaders() },
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCN_KEY }),
  });
}

/**
 * ⛔ Approver-only, allowlist-gated live-DAST run. Server enforces every
 * guardrail, INCLUDING (A1, 2026-09-12) written-authorization: a scenario
 * missing a complete, current-version `POST /scenarios/:id/authorize` grant
 * is refused with a 403 (`ScenarioApiError`) rather than a silent no-op —
 * `run.mutate` throws that error into `run.error`.
 */
export function useRunScenario() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      req<ScenarioRunResponse>(`${base}/${id}/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...mockActorHeaders(actor),
          ...csrfHeaders(),
        },
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["audit", "all"] }),
  });
}

/**
 * ⛔ A1 — approver-only. Records a REQUIRED free-text authorization reference
 * (a ticket number, a signed agreement reference, etc.) binding written
 * authorization to run this scenario for real to its EXACT current version —
 * any subsequent edit invalidates it and requires a fresh call.
 */
export function useAuthorizeScenario() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; authorizationReference: string }) =>
      req<{ scenario: RedTeamScenario }>(`${base}/${vars.id}/authorize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...mockActorHeaders(actor),
          ...csrfHeaders(),
        },
        body: JSON.stringify({ authorizationReference: vars.authorizationReference }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: SCN_KEY });
      void qc.invalidateQueries({ queryKey: ["audit", "all"] });
    },
  });
}
