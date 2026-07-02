import { z } from "zod";
import {
  IdSchema,
  IsoDateTimeSchema,
  CommitShaSchema,
  FilePathSchema,
  UrlSchema,
} from "./primitives.js";
import { ScanModeSchema, ScanStatusSchema, GateStateSchema } from "./enums.js";
import { CostEstimateSchema, CostActualSchema, BudgetPolicySchema } from "./cost.js";

/** What a scan covers. For diff mode: changed files + reachable call graph (§7 L0). */
export const ScanScopeSchema = z.object({
  mode: ScanModeSchema,
  includePaths: z.array(FilePathSchema).default([]),
  excludePaths: z.array(FilePathSchema).default([]),
  /** Populated in diff mode. */
  changedFiles: z.array(FilePathSchema).default([]),
  reachableFromChanges: z.boolean().default(false),
  routeCount: z.number().int().nonnegative().optional(),
  fileCount: z.number().int().nonnegative().optional(),
  /** Client-authorized staging URL for optional live DAST (never production). */
  stagingUrl: UrlSchema.optional(),
});
export type ScanScope = z.infer<typeof ScanScopeSchema>;

/**
 * PRD §9 — Scan. The gate is an explicit STATE on the scan (golden rule #5).
 * Idempotent + resumable: a failed Layer-3 must not re-run Layer 0–2 (§8.1).
 */
export const ScanSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  appMapId: IdSchema.optional(),
  repo: z.string().min(1),
  branch: z.string().min(1),
  commitSha: CommitShaSchema.optional(),
  mode: ScanModeSchema,
  scope: ScanScopeSchema,
  status: ScanStatusSchema.default("queued"),
  gateState: GateStateSchema.default("not_started"),
  /** Operator (role: operator) who created the scan. */
  operator: IdSchema,
  /** Approver (role: approver) who cleared the human gate / DAST authorization. */
  approver: IdSchema.optional(),
  budgetPolicy: BudgetPolicySchema.optional(),
  costEstimate: CostEstimateSchema.optional(),
  costActual: CostActualSchema.optional(),
  startedAt: IsoDateTimeSchema.optional(),
  finishedAt: IsoDateTimeSchema.optional(),
  createdAt: IsoDateTimeSchema,
});
export type Scan = z.infer<typeof ScanSchema>;
