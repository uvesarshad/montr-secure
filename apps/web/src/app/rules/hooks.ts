"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { CustomRule, CustomRuleValidation, Language, RuleEngine } from "@montr/contracts";
import { API_BASE, ACTOR_ID_HEADER, ACTOR_ROLE_HEADER } from "../../lib/api/config.js";
import { useActor } from "../../components/role-context.js";
import type { Actor } from "../../lib/api/types.js";

/**
 * Data hooks for the custom-rule authoring page. Self-contained (co-located with
 * the page) so the feature does not edit the shared api client/mocks. Talks to the
 * real Phase-4 endpoints (`/rules`); RBAC + validation are enforced server-side.
 */

const base = `${API_BASE}/api/v1/rules`;
const RULES_KEY = ["custom-rules"] as const;

export interface RuleDraft {
  name: string;
  engine: RuleEngine;
  language: Language;
  body: string;
  enabled: boolean;
}
export interface RuleMutationResult {
  rule: CustomRule;
  validation: CustomRuleValidation;
}

/** Typed transport error carrying the server's validation details when present. */
export class RuleApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly details?: { errors?: string[]; warnings?: string[] };
  constructor(status: number, message: string, code?: string, details?: RuleApiError["details"]) {
    super(message);
    this.name = "RuleApiError";
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
    throw new RuleApiError(0, `Network error contacting ${url}`, "NETWORK");
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = (
      body as { error?: { code?: string; message?: string; details?: RuleApiError["details"] } }
    )?.error;
    throw new RuleApiError(res.status, env?.message ?? res.statusText, env?.code, env?.details);
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

export function useCustomRules() {
  return useQuery({
    queryKey: RULES_KEY,
    queryFn: () => req<{ rules: CustomRule[] }>(base).then((r) => r.rules),
  });
}

export function useCreateRule() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (draft: RuleDraft) =>
      req<RuleMutationResult>(base, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...actorHeaders(actor) },
        body: JSON.stringify(draft),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: RULES_KEY }),
  });
}

export function useUpdateRule() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; draft: RuleDraft }) =>
      req<RuleMutationResult>(`${base}/${vars.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...actorHeaders(actor) },
        body: JSON.stringify(vars.draft),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: RULES_KEY }),
  });
}

export function useDeleteRule() {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      req<{ ok: boolean; id: string }>(`${base}/${id}`, {
        method: "DELETE",
        headers: actorHeaders(actor),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: RULES_KEY }),
  });
}
