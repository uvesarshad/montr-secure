"use client";

import { useQuery } from "@tanstack/react-query";
import type { BlueTeamOrgSummary } from "@montr/contracts";
import { API_BASE } from "../../lib/api/config.js";

/**
 * A5 (red/blue agentic-posture audit) — data hook for the org-wide blue-team
 * aggregate page. Self-contained (co-located with the page), same pattern as
 * app/dashboards/hooks.ts and app/{rules,scenarios,schedules}/hooks.ts — this
 * is a real-API-only endpoint (no MSW handler) so the session cookie is
 * always sent regardless of mock mode. Read-only: no CSRF/mutation headers
 * needed (apps/api/src/routes/analytics.ts exposes a GET route only).
 */

const base = `${API_BASE}/api/v1/analytics`;
const BLUE_TEAM_KEY = ["org-blue-team"] as const;

export class BlueTeamApiError extends Error {
  readonly status: number;
  readonly code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "BlueTeamApiError";
    this.status = status;
    this.code = code;
  }
}

async function req<T>(url: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new BlueTeamApiError(0, `Network error contacting ${url}`, "NETWORK");
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = (body as { error?: { code?: string; message?: string } })?.error;
    throw new BlueTeamApiError(res.status, env?.message ?? res.statusText, env?.code);
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

/** Org-wide blue-team aggregate: ATT&CK coverage over time, the deduped
 * detection-rule inventory, and the real (A7) detection-coverage trend. */
export function useBlueTeamOrgSummary() {
  return useQuery({
    queryKey: BLUE_TEAM_KEY,
    queryFn: () => req<{ summary: BlueTeamOrgSummary }>(`${base}/blue-team`).then((r) => r.summary),
  });
}
