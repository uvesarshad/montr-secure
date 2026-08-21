import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { LayerIdSchema, ScanModeSchema, RoleSchema, type LayerId } from "./enums.js";
import { ScanScopeSchema } from "./scan.js";
import { ErrorEnvelopeSchema } from "./errors.js";
import type {
  Layer0Output,
  Layer1Output,
  Layer2Output,
  Layer3Output,
  Layer4Output,
  Layer5Output,
} from "./layers.js";

/**
 * Queue & event contracts (§3.3). BullMQ job definitions per layer, retry +
 * idempotency, progress/lifecycle events, the kill-switch signal, and the
 * partial-failure + resume-token contracts. BullMQ itself is imported only in
 * @montr/orchestrator; these are the shared shapes.
 */

/** One durable queue per layer + a control queue for kill-switch/lifecycle. */
export const QUEUE_NAMES = {
  layer0: "montr.layer0",
  layer1: "montr.layer1",
  layer2: "montr.layer2",
  layer3: "montr.layer3",
  layer4: "montr.layer4",
  layer5: "montr.layer5",
  control: "montr.control",
} as const;
export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

/** Redis pub/sub channel the kill switch broadcasts on. */
export const KILL_SWITCH_CHANNEL = "montr.control.kill" as const;

/**
 * Per-tenant queue isolation (A27, opt-in — OFF by default everywhere it's
 * wired). The documented deployment model is single-tenant on-prem — one
 * worker process per client (see apps/worker/src/main.ts) — so the plain
 * `QUEUE_NAMES[layer]` name is correct today and repository-layer `clientId`
 * row-scoping already gives complete data isolation. This function is forward
 * cover for a future multi-tenant deployment (one worker fleet serving
 * several clientIds), where a single shared per-layer queue would let one
 * client's backlog starve another client's newly-queued job on the same
 * layer (noisy-neighbour, head-of-line blocking).
 *
 * `tenantIsolation: false` (default) returns exactly `QUEUE_NAMES[layer]`,
 * byte-for-byte identical to today's behavior. `tenantIsolation: true`
 * returns a per-client queue name (`montr.layer0.<clientId>` instead of
 * `montr.layer0`), so each client gets a dedicated queue per layer.
 */
export function resolveQueueName(
  layer: LayerId,
  clientId: string,
  tenantIsolation: boolean,
): string {
  if (!tenantIsolation) return QUEUE_NAMES[layer];
  return `${QUEUE_NAMES[layer]}.${sanitizeClientIdForQueueName(clientId)}`;
}

/**
 * BullMQ queue names become Redis keys, so keep them restricted to a
 * conservative charset. `clientId` is operator-provisioned (config.clientId /
 * the Client row id), never raw end-user input — but resolveQueueName still
 * fails closed on anything outside `[A-Za-z0-9_-]` rather than silently
 * mangling or colliding two different clients' queue names.
 */
export function sanitizeClientIdForQueueName(clientId: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(clientId)) {
    throw new Error(
      `resolveQueueName: clientId "${clientId}" contains characters outside [A-Za-z0-9_-], ` +
        "which is unsafe to use in a BullMQ/Redis queue name",
    );
  }
  return clientId;
}

/** Fields on every layer job. `idempotencyKey` dedupes retries/replays. */
export const BaseJobDataSchema = z.object({
  scanId: IdSchema,
  clientId: IdSchema,
  layer: LayerIdSchema,
  idempotencyKey: z.string().min(1),
  attempt: z.number().int().nonnegative().default(0),
  /** Present when resuming a partially-completed scan. */
  resumeTokenRef: IdSchema.optional(),
});
export type BaseJobData = z.infer<typeof BaseJobDataSchema>;

export const Layer0JobDataSchema = BaseJobDataSchema.extend({
  layer: z.literal("layer0"),
  repo: z.string().min(1),
  branch: z.string().min(1),
  mode: ScanModeSchema,
  scope: ScanScopeSchema,
});
export type Layer0JobData = z.infer<typeof Layer0JobDataSchema>;

export const Layer1JobDataSchema = BaseJobDataSchema.extend({
  layer: z.literal("layer1"),
  appMapId: IdSchema,
});
export type Layer1JobData = z.infer<typeof Layer1JobDataSchema>;

export const Layer2JobDataSchema = BaseJobDataSchema.extend({
  layer: z.literal("layer2"),
});
export type Layer2JobData = z.infer<typeof Layer2JobDataSchema>;

export const Layer3JobDataSchema = BaseJobDataSchema.extend({
  layer: z.literal("layer3"),
  /** Live DAST is OFF by default and requires approver authorization (DECIDE-1, §11). */
  allowLive: z.boolean().default(false),
  stagingUrl: z.string().optional(),
});
export type Layer3JobData = z.infer<typeof Layer3JobDataSchema>;

export const Layer4JobDataSchema = BaseJobDataSchema.extend({
  layer: z.literal("layer4"),
});
export type Layer4JobData = z.infer<typeof Layer4JobDataSchema>;

export const Layer5JobDataSchema = BaseJobDataSchema.extend({
  layer: z.literal("layer5"),
  /** When true, open PRs for auto-eligible fixes (never direct commits). */
  autoApply: z.boolean().default(false),
});
export type Layer5JobData = z.infer<typeof Layer5JobDataSchema>;

export const LayerJobDataSchema = z.discriminatedUnion("layer", [
  Layer0JobDataSchema,
  Layer1JobDataSchema,
  Layer2JobDataSchema,
  Layer3JobDataSchema,
  Layer4JobDataSchema,
  Layer5JobDataSchema,
]);
export type LayerJobData = z.infer<typeof LayerJobDataSchema>;

/** Compile-time map from layer to its job-data / result types. */
export interface LayerJobDataMap {
  layer0: Layer0JobData;
  layer1: Layer1JobData;
  layer2: Layer2JobData;
  layer3: Layer3JobData;
  layer4: Layer4JobData;
  layer5: Layer5JobData;
}
export interface LayerJobResultMap {
  layer0: Layer0Output;
  layer1: Layer1Output;
  layer2: Layer2Output;
  layer3: Layer3Output;
  layer4: Layer4Output;
  layer5: Layer5Output;
}

/** BullMQ-compatible retry/backoff policy. */
export interface RetryPolicy {
  readonly attempts: number;
  readonly backoff: { readonly type: "exponential" | "fixed"; readonly delay: number };
  readonly removeOnComplete?: boolean | number;
  readonly removeOnFail?: boolean | number;
}

/**
 * Per-layer retry policies. Layer 3 live DAST is deliberately conservative
 * (few retries, no thundering herd against a staging target).
 */
export const RETRY_POLICIES: Record<LayerId, RetryPolicy> = {
  layer0: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: 100 },
  layer1: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: 100 },
  layer2: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: 100 },
  layer3: { attempts: 2, backoff: { type: "fixed", delay: 5000 }, removeOnComplete: 100 },
  layer4: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: 100 },
  layer5: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: 100 },
};

/**
 * Deterministic idempotency key: `${scanId}:${layer}:${discriminator}`.
 * No Date.now()/random — replays produce the same key.
 */
export function buildIdempotencyKey(scanId: string, layer: LayerId, discriminator = "0"): string {
  return `${scanId}:${layer}:${discriminator}`;
}

/* ------------------------- progress / lifecycle events ------------------------- */

export const ProgressEventSchema = z.object({
  scanId: IdSchema,
  layer: LayerIdSchema,
  phase: z.string(),
  /** 0..100 percent complete within the layer. */
  pct: z.number().min(0).max(100),
  message: z.string().optional(),
  at: IsoDateTimeSchema,
});
export type ProgressEvent = z.infer<typeof ProgressEventSchema>;

/** Full pipeline event stream (progress + lifecycle + safety events). */
export const PipelineEventSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("scan_started"), scanId: IdSchema, at: IsoDateTimeSchema }),
  z.object({
    type: z.literal("layer_started"),
    scanId: IdSchema,
    layer: LayerIdSchema,
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("progress"),
    scanId: IdSchema,
    layer: LayerIdSchema,
    pct: z.number().min(0).max(100),
    phase: z.string(),
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("layer_completed"),
    scanId: IdSchema,
    layer: LayerIdSchema,
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("gate_required"),
    scanId: IdSchema,
    gate: z.enum(["estimate", "fix"]),
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("budget_warning"),
    scanId: IdSchema,
    spentUsd: z.number(),
    ceilingUsd: z.number().optional(),
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("budget_exceeded"),
    scanId: IdSchema,
    spentUsd: z.number(),
    ceilingUsd: z.number().optional(),
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("killed"),
    scanId: IdSchema,
    reason: z.string(),
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("failed"),
    scanId: IdSchema,
    layer: LayerIdSchema.optional(),
    error: ErrorEnvelopeSchema,
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("resumed"),
    scanId: IdSchema,
    fromLayer: LayerIdSchema,
    at: IsoDateTimeSchema,
  }),
  z.object({
    type: z.literal("scan_completed"),
    scanId: IdSchema,
    partial: z.boolean().default(false),
    at: IsoDateTimeSchema,
  }),
]);
export type PipelineEvent = z.infer<typeof PipelineEventSchema>;

/* --------------------------- kill switch / resume --------------------------- */

/** ⛔ Kill-switch signal — halts all active work immediately, especially DAST (§11). */
export const KillSwitchSignalSchema = z.object({
  scope: z.enum(["scan", "global"]),
  scanId: IdSchema.optional(),
  reason: z.string(),
  requestedBy: IdSchema,
  requestedByRole: RoleSchema.optional(),
  at: IsoDateTimeSchema,
});
export type KillSwitchSignal = z.infer<typeof KillSwitchSignalSchema>;

/**
 * Resume token — the checkpoint that makes the pipeline resumable. A failed
 * Layer-3 must NOT re-run Layer 0–2 (§8.1).
 */
export const ResumeTokenSchema = z.object({
  id: IdSchema.optional(),
  scanId: IdSchema,
  completedLayers: z.array(LayerIdSchema).default([]),
  lastCompletedLayer: LayerIdSchema.optional(),
  /** Reference to the persisted checkpoint (e.g. ScanState row id). */
  checkpointRef: z.string().optional(),
  updatedAt: IsoDateTimeSchema,
});
export type ResumeToken = z.infer<typeof ResumeTokenSchema>;

/** A layer that failed, and whether the scan can resume from it. */
export const PartialFailureSchema = z.object({
  scanId: IdSchema,
  failedLayer: LayerIdSchema,
  error: ErrorEnvelopeSchema,
  resumable: z.boolean(),
  at: IsoDateTimeSchema,
});
export type PartialFailure = z.infer<typeof PartialFailureSchema>;
