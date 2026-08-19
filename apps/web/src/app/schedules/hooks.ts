"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ScanMode, ScanSchedule } from "@montr/contracts";
import { API_BASE } from "../../lib/api/config.js";
import { csrfHeaders, mockActorHeaders } from "../../lib/api/auth-headers.js";
import { useActor } from "../../components/role-context.js";

/**
 * Data hooks for the scheduled-scans page. Self-contained (co-located with the
 * page) so the feature does not edit the shared api client/mocks. Talks to the
 * real Phase-4 endpoints (`/schedules`).
 *
 * ⛔ SAFETY is enforced SERVER-SIDE (never here): the cron is validated before a
 *    schedule can be enabled, the per-run `budgetCeiling` is a hard USD ceiling,
 *    and a scheduled run STILL honors the human gate (estimate ack + approver
 *    fix-gate). RBAC (operator/approver create; viewers read-only) is server-side
 *    too. Every mutation is audited (schedule.created / .updated / .deleted).
 */

const base = `${API_BASE}/api/v1/schedules`;
const SCHED_KEY = ["scan-schedules"] as const;

/** Create/update body — mirrors CreateScanScheduleBodySchema (apps/api). */
export interface ScheduleDraft {
  repo: string;
  mode: ScanMode;
  cron: string;
  budgetCeiling: number;
  enabled: boolean;
}

/** Typed transport error carrying the server's envelope (e.g. a bad-cron 400). */
export class ScheduleApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly details?: Record<string, unknown>;
  constructor(status: number, message: string, code?: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ScheduleApiError";
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
    throw new ScheduleApiError(0, `Network error contacting ${url}`, "NETWORK");
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = (
      body as { error?: { code?: string; message?: string; details?: Record<string, unknown> } }
    )?.error;
    throw new ScheduleApiError(res.status, env?.message ?? res.statusText, env?.code, env?.details);
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

export function useSchedules() {
  return useQuery({
    queryKey: SCHED_KEY,
    queryFn: () => req<{ schedules: ScanSchedule[] }>(base).then((r) => r.schedules),
  });
}

export function useCreateSchedule() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (draft: ScheduleDraft) =>
      req<{ schedule: ScanSchedule }>(base, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...mockActorHeaders(actor),
          ...csrfHeaders(),
        },
        body: JSON.stringify(draft),
      }).then((r) => r.schedule),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCHED_KEY }),
  });
}

export function useUpdateSchedule() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; draft: ScheduleDraft }) =>
      req<{ schedule: ScanSchedule }>(`${base}/${vars.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          ...mockActorHeaders(actor),
          ...csrfHeaders(),
        },
        body: JSON.stringify(vars.draft),
      }).then((r) => r.schedule),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCHED_KEY }),
  });
}

export function useDeleteSchedule() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      req<{ id: string; deleted: boolean }>(`${base}/${id}`, {
        method: "DELETE",
        headers: { ...mockActorHeaders(actor), ...csrfHeaders() },
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: SCHED_KEY }),
  });
}
