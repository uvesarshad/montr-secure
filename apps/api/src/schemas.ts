/**
 * Request schemas for every route. These reuse @montr/contracts schemas
 * (ScanMode, ScanScope, BudgetPolicy, Role, Category, ExportFormat, ...) so the
 * HTTP boundary and the domain model never drift.
 */
import { z } from "zod";
import {
  BudgetPolicySchema,
  CustomRuleSchema,
  ExportFormatSchema,
  RedTeamScenarioSchema,
  RoleSchema,
  ScanModeSchema,
  ScanScheduleSchema,
  ScanScopeSchema,
} from "@montr/contracts";
import { DastScopeContractSchema } from "@montr/config";
import { EmailSchema, PasswordSchema } from "./auth/users.js";

/* ------------------------------- auth ------------------------------- */

export const RegisterBodySchema = z.object({
  email: EmailSchema,
  password: PasswordSchema,
  /**
   * Requested role. Honored ONLY for the first (bootstrap) user of a client;
   * subsequent self-registrations are forced to `viewer` (least privilege,
   * golden rule #4). Role elevation is an approver-gated, audited action.
   */
  role: RoleSchema.optional(),
});
export type RegisterBody = z.infer<typeof RegisterBodySchema>;

export const LoginBodySchema = z.object({
  email: EmailSchema,
  password: z.string().min(1).max(200),
});
export type LoginBody = z.infer<typeof LoginBodySchema>;

export const ChangeRoleBodySchema = z.object({
  userId: z.string().min(1),
  role: RoleSchema,
});
export type ChangeRoleBody = z.infer<typeof ChangeRoleBodySchema>;

/* ------------------------------- scans ------------------------------ */

export const CreateScanBodySchema = z.object({
  repo: z.string().min(1),
  branch: z.string().min(1).default("main"),
  mode: ScanModeSchema.default("full"),
  /** Optional scan scope; `mode` is forced to match the top-level mode. */
  scope: ScanScopeSchema.partial().optional(),
  budgetPolicy: BudgetPolicySchema.optional(),
});
export type CreateScanBody = z.infer<typeof CreateScanBodySchema>;

export const ScanIdParamsSchema = z.object({ id: z.string().min(1) });
export type ScanIdParams = z.infer<typeof ScanIdParamsSchema>;

export const GateNoteBodySchema = z.object({ note: z.string().max(1000).optional() }).optional();

/* -------------------------------- DAST ------------------------------ */

export const CreateDastTargetBodySchema = z.object({
  url: z.string().url(),
  scopeContract: DastScopeContractSchema.partial().optional(),
});
export type CreateDastTargetBody = z.infer<typeof CreateDastTargetBodySchema>;

export const DastTargetIdParamsSchema = z.object({ id: z.string().min(1) });

/* ------------------------------ findings ---------------------------- */

export const FindingIdParamsSchema = z.object({ id: z.string().min(1) });

export const MarkFalsePositiveBodySchema = z.object({
  reason: z.string().min(1).max(2000),
});
export type MarkFalsePositiveBody = z.infer<typeof MarkFalsePositiveBodySchema>;

/* ------------------------------- audit ------------------------------ */

export const AuditExportQuerySchema = z.object({
  scanId: z.string().min(1).optional(),
  format: z.enum(["json", "csv"]).default("json"),
  limit: z.coerce.number().int().positive().max(10000).optional(),
  fromSequence: z.coerce.number().int().positive().optional(),
});
export type AuditExportQuery = z.infer<typeof AuditExportQuerySchema>;

/* --------------------------- report exports ------------------------- */

export const ReportExportQuerySchema = z.object({
  format: ExportFormatSchema.optional(),
});

/* ---------------------- Phase-4: scale & intelligence ---------------------- */
// Server-supplied fields (id/clientId/createdBy/createdAt) are omitted from the
// request bodies; the route fills them from the authenticated actor + clock.

/** POST /rules — author a custom detection rule (validated before enable). */
export const CreateCustomRuleBodySchema = CustomRuleSchema.omit({
  id: true,
  clientId: true,
  createdBy: true,
  createdAt: true,
});
export type CreateCustomRuleBody = z.infer<typeof CreateCustomRuleBodySchema>;

/** ⛔ POST /scenarios — a red-team scenario is disabled until approver-authorized. */
export const CreateRedTeamScenarioBodySchema = RedTeamScenarioSchema.omit({
  id: true,
  clientId: true,
  createdBy: true,
  createdAt: true,
});
export type CreateRedTeamScenarioBody = z.infer<typeof CreateRedTeamScenarioBodySchema>;

/** POST /schedules — a cron-scheduled scan (budget ceiling + human gate). */
export const CreateScanScheduleBodySchema = ScanScheduleSchema.omit({
  id: true,
  clientId: true,
  createdBy: true,
  createdAt: true,
  nextRunAt: true,
});
export type CreateScanScheduleBody = z.infer<typeof CreateScanScheduleBodySchema>;

/** Shared `:id` path param for rule/scenario/schedule routes. */
export const EntityIdParamsSchema = z.object({ id: z.string().min(1) });
export type EntityIdParams = z.infer<typeof EntityIdParamsSchema>;

/** GET /analytics/trends?repo= — a repo's posture time-series. */
export const TrendQuerySchema = z.object({ repo: z.string().min(1) });
export type TrendQuery = z.infer<typeof TrendQuerySchema>;
