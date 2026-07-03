"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { RedTeamCategory, RedTeamScenario, RedTeamStep } from "@montr/contracts";
import { API_BASE, ACTOR_ID_HEADER, ACTOR_ROLE_HEADER } from "../../lib/api/config.js";
import { useActor } from "../../components/role-context.js";
import type { Actor } from "../../lib/api/types.js";

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

function actorHeaders(actor: Actor): Record<string, string> {
  return { [ACTOR_ID_HEADER]: actor.id, [ACTOR_ROLE_HEADER]: actor.role };
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
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
        headers: { "Content-Type": "application/json", ...actorHeaders(actor) },
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
        headers: { "Content-Type": "application/json", ...actorHeaders(actor) },
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
        headers: actorHeaders(actor),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCN_KEY }),
  });
}

/** ⛔ Approver-only, allowlist-gated live-DAST run. Server enforces every guardrail. */
export function useRunScenario() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      req<{ run: ScenarioRun }>(`${base}/${id}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...actorHeaders(actor) },
      }).then((r) => r.run),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["audit", "all"] }),
  });
}
