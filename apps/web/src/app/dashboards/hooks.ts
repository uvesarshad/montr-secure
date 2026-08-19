"use client";

import { useQuery } from "@tanstack/react-query";
import type { OrgPostureSummary, PostureTrend } from "@montr/contracts";
import { API_BASE } from "../../lib/api/config.js";

/**
 * Data hooks for the org-wide posture dashboard. Self-contained (co-located
 * with the page), same pattern as app/{rules,scenarios,schedules}/hooks.ts —
 * these are real-API-only endpoints (no MSW handler) so the session cookie is
 * always sent regardless of mock mode. Read-only: no CSRF/mutation headers
 * needed (apps/api/src/routes/analytics.ts exposes GET routes only).
 */

const base = `${API_BASE}/api/v1/analytics`;
const POSTURE_KEY = ["org-posture"] as const;
const trendKey = (repo: string) => ["posture-trend", repo] as const;

export class AnalyticsApiError extends Error {
  readonly status: number;
  readonly code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "AnalyticsApiError";
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
    throw new AnalyticsApiError(0, `Network error contacting ${url}`, "NETWORK");
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = (body as { error?: { code?: string; message?: string } })?.error;
    throw new AnalyticsApiError(res.status, env?.message ?? res.statusText, env?.code);
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

/** Org-wide posture aggregate (confirmed-by-severity per repo + totals). */
export function useOrgPosture() {
  return useQuery({
    queryKey: POSTURE_KEY,
    queryFn: () => req<{ summary: OrgPostureSummary }>(`${base}/posture`).then((r) => r.summary),
  });
}

/** A single repo's posture time-series (confirmed findings over time). */
export function useRepoTrend(repo: string | undefined) {
  return useQuery({
    queryKey: trendKey(repo ?? ""),
    queryFn: () =>
      req<{ trend: PostureTrend }>(`${base}/trends?repo=${encodeURIComponent(repo ?? "")}`).then(
        (r) => r.trend,
      ),
    enabled: !!repo,
  });
}
