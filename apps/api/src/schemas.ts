/**
 * Request schemas for every route. These reuse @montr/contracts schemas
 * (ScanMode, ScanScope, BudgetPolicy, Role, Category, ExportFormat, ...) so the
 * HTTP boundary and the domain model never drift.
 */
import { z } from "zod";
import {
  BudgetPolicySchema,
  ExportFormatSchema,
  RoleSchema,
  ScanModeSchema,
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
